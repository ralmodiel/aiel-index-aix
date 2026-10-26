//! Log line parsing for `aix logs`: entry boundaries (multi-line stack traces), timestamp / level / logger / thread /
//! message / exception class / error id, message templating, stack-frame extraction, and the log-specific PII scrub
//! (emails, auth/cookie header values, IPs) that runs before the shared `text::redact`. Pure functions, no I/O: the
//! ingest lives in aix-core.

use std::sync::LazyLock;

use regex::Regex;

pub const TRACE: u8 = 0;
pub const DEBUG: u8 = 1;
pub const INFO: u8 = 2;
pub const WARN: u8 = 3;
pub const ERROR: u8 = 4;
pub const FATAL: u8 = 5;

pub fn level_name(l: u8) -> &'static str {
    ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"].get(l as usize).copied().unwrap_or("INFO")
}

/// `warn`, `WARNING`, `err`, `severe` ... -> level number.
pub fn level_from(s: &str) -> Option<u8> {
    Some(match s.trim().to_ascii_uppercase().as_str() {
        "TRACE" | "FINEST" | "FINER" | "VERBOSE" => TRACE,
        "DEBUG" | "FINE" | "DBG" => DEBUG,
        "INFO" | "INFORMATION" | "NOTICE" | "CONFIG" => INFO,
        "WARN" | "WARNING" => WARN,
        "ERROR" | "ERR" | "SEVERE" => ERROR,
        "FATAL" | "CRITICAL" | "CRIT" | "PANIC" | "EMERG" | "ALERT" => FATAL,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Auto,
    Json,
    Logfmt,
    Java,
    Plain,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        Some(match s {
            "auto" => Format::Auto,
            "json" => Format::Json,
            "logfmt" => Format::Logfmt,
            "java" => Format::Java,
            "plain" => Format::Plain,
            _ => return None,
        })
    }
}

/// One parsed entry (before redaction of the free text; the caller redacts `message`, `logger`, `thread`, `body`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    /// seconds since the epoch; local-time (naive) stamps are returned as if UTC with `tz_known = false`
    pub ts: Option<i64>,
    pub tz_known: bool,
    pub level: Option<u8>,
    pub logger: String,
    pub thread: String,
    pub message: String,
    pub error_id: String,
    pub exception: String,
    /// JSON logs: the stack trace field (not part of the one-line message)
    pub stack: String,
}

const LV: &str = r"TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|SEVERE|CRITICAL|FINE[RST]*";

static TS_ISO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\W{0,2}(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?\s*(Z|[+-]\d\d:?\d\d)?").unwrap()
});
static TS_SLASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\W{0,2}(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)").unwrap());
static START_TIME_ONLY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[?\d\d:\d\d:\d\d").unwrap());
static START_SYSLOG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d ").unwrap());
static START_LEVEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^\s{{0,2}}\[?(?:{LV})\]?(?:[:\s]|$)")).unwrap());
static START_LOGFMT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:time|ts|level|lvl|t)=\S").unwrap());
static CONT_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:\s+|at\s|Caused by:|Traceback \(|\.\.\. \d+ (?:more|common)|Suppressed:|File "|[\w.$]+(?:Exception|Error|Throwable)(?::|$)|\}|\)|Wrapped by:)"#).unwrap()
});
static LEVEL_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"(?:^|[\s\[|:,;])\(?({LV})\)?(?:[\]\s:|,;]|$)")).unwrap());
static LOGGER_AFTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:\d+\s+---\s+)?(?:\[([^\]]{1,80})\]\s*)?([A-Za-z_][\w.$/-]{1,120})\s*(?:-|:|\||\s)\s+(.*)$").unwrap());
static THREAD_BRACKET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[([^\]\s][^\]]{0,79})\]").unwrap());
static ERR_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:error[_ -]?id|errorid|incident[_ -]?id|trace[_ -]?id|correlation[_ -]?id|request[_ -]?id)\b[=:\s"']{1,3}([A-Za-z0-9_.-]{4,64})"#).unwrap());
static JAVA_EXC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b((?:[a-z_][\w]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable|Failure|Fault))\b").unwrap());
static PY_EXC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Warning))(?::|$)").unwrap());
static BARE_EXC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([A-Z][\w]*(?:Exception|Error))(?::|$)").unwrap());

/// `true` when `line` begins a new entry (else it continues the previous one: stack frame, `Caused by`, traceback body ...).
pub fn is_entry_start(line: &str, fmt: Format) -> bool {
    if line.trim().is_empty() {
        return false;
    }
    match fmt {
        Format::Json => return line.trim_start().starts_with('{'),
        Format::Logfmt => return true,
        _ => {}
    }
    if line.starts_with('{') && line.trim_end().ends_with('}') {
        return true;
    }
    if TS_ISO.is_match(line) || TS_SLASH.is_match(line) || START_SYSLOG.is_match(line) || START_TIME_ONLY.is_match(line) || START_LEVEL.is_match(line) || START_LOGFMT.is_match(line) {
        return true;
    }
    // a line without a recognisable start: continuation when it looks like one, else its own entry
    !CONT_HINT.is_match(line)
}

/// Remove ANSI escape sequences and other control characters (tab kept as a space).
pub fn strip_ansi(s: &str) -> String {
    static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]").unwrap());
    let t = ANSI.replace_all(s, "");
    t.chars().map(|c| if c == '\t' { ' ' } else { c }).filter(|c| !c.is_control()).collect()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Epoch seconds of a civil date-time in UTC (also used to read `--since 2025-03-01T10:00`).
pub fn civil_to_epoch(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
}

/// ISO-ish stamp at the start of `s` -> (epoch seconds, tz known, bytes consumed).
pub fn parse_ts(s: &str) -> Option<(i64, bool, usize)> {
    if let Some(c) = TS_ISO.captures(s) {
        let g = |i: usize| c.get(i).map(|m| m.as_str().parse::<i64>().unwrap_or(0)).unwrap_or(0);
        let mut t = civil_to_epoch(g(1), g(2), g(3), g(4), g(5), g(6));
        let mut known = false;
        if let Some(z) = c.get(8) {
            known = true;
            let z = z.as_str();
            if z != "Z" {
                let sign = if z.starts_with('-') { -1 } else { 1 };
                let d: String = z[1..].chars().filter(|c| c.is_ascii_digit()).collect();
                let off = d[..2].parse::<i64>().unwrap_or(0) * 3600 + d[2..].parse::<i64>().unwrap_or(0) * 60;
                t -= sign * off;
            }
        }
        return Some((t, known, c.get(0).unwrap().end()));
    }
    if let Some(c) = TS_SLASH.captures(s) {
        let g = |i: usize| c[i].parse::<i64>().unwrap_or(0);
        return Some((civil_to_epoch(g(1), g(2), g(3), g(4), g(5), g(6)), false, c.get(0).unwrap().end()));
    }
    None
}

fn epoch_any(v: &serde_json::Value) -> Option<(i64, bool)> {
    match v {
        serde_json::Value::String(s) => parse_ts(s.trim()).map(|(t, k, _)| (t, k)),
        serde_json::Value::Number(n) => {
            let f = n.as_f64()?;
            let secs = if f > 1e17 { f / 1e9 } else if f > 1e14 { f / 1e6 } else if f > 1e11 { f / 1e3 } else { f };
            Some((secs as i64, true))
        }
        _ => None,
    }
}

fn first_str<'a>(m: &'a serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<&'a serde_json::Value> {
    keys.iter().find_map(|k| m.get(*k).filter(|v| !v.is_null()))
}

fn vstr(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        o => o.to_string(),
    }
}

fn parse_json(line: &str) -> Option<(Parsed, String)> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let m = v.as_object()?;
    let mut p = Parsed::default();
    if let Some((t, k)) = first_str(m, &["@timestamp", "timestamp", "time", "ts", "asctime", "datetime", "@t"]).and_then(epoch_any) {
        p.ts = Some(t);
        p.tz_known = k;
    }
    p.level = first_str(m, &["level", "severity", "lvl", "log.level", "levelname", "@l"]).and_then(|v| match v {
        serde_json::Value::Number(n) => n.as_i64().map(|n| if n >= 50 { ERROR } else if n >= 40 { WARN } else if n >= 30 { INFO } else { DEBUG }),
        o => level_from(&vstr(o)),
    });
    p.logger = first_str(m, &["logger", "logger_name", "name", "loggerName", "caller", "module"]).map(vstr).unwrap_or_default();
    p.thread = first_str(m, &["thread", "thread_name", "threadName"]).map(vstr).unwrap_or_default();
    p.message = first_str(m, &["message", "msg", "@m", "event", "text"]).map(vstr).unwrap_or_default();
    p.error_id = first_str(m, &["error_id", "errorId", "errorID", "incident_id", "trace_id", "traceId", "request_id", "requestId"]).map(vstr).unwrap_or_default();
    let stack = first_str(m, &["stack_trace", "stacktrace", "exception", "error.stack", "stack", "exc_info", "err", "error"]).map(vstr).unwrap_or_default();
    if let Some(e) = first_str(m, &["exception_class", "error.type", "error_type", "exceptionClass", "exc_type"]) {
        p.exception = vstr(e);
    }
    if p.message.is_empty() {
        p.message = line.chars().take(300).collect();
    }
    Some((p, stack))
}

fn parse_logfmt(line: &str) -> Option<Parsed> {
    static KV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([A-Za-z_][\w.@-]*)=("(?:[^"\\]|\\.)*"|\S*)"#).unwrap());
    let mut p = Parsed::default();
    let mut n = 0;
    for c in KV.captures_iter(line) {
        n += 1;
        let k = c[1].to_ascii_lowercase();
        let v = c[2].trim_matches('"').replace("\\\"", "\"");
        match k.as_str() {
            "time" | "ts" | "timestamp" | "t" => {
                if let Some((t, kn, _)) = parse_ts(&v) {
                    p.ts = Some(t);
                    p.tz_known = kn;
                } else if let Ok(f) = v.parse::<f64>() {
                    p.ts = Some(if f > 1e11 { (f / 1e3) as i64 } else { f as i64 });
                    p.tz_known = true;
                }
            }
            "level" | "lvl" | "severity" => p.level = level_from(&v),
            "msg" | "message" => p.message = v,
            "logger" | "component" | "module" | "caller" => p.logger = v,
            "thread" => p.thread = v,
            "error_id" | "errorid" | "request_id" | "trace_id" => p.error_id = v,
            "err" | "error" if p.message.is_empty() => p.message = v,
            _ => {}
        }
    }
    (n >= 2 && (p.level.is_some() || !p.message.is_empty())).then_some(p)
}

fn parse_text(line: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut rest = line.trim_start();
    if let Some((t, k, n)) = parse_ts(rest) {
        p.ts = Some(t);
        p.tz_known = k;
        rest = rest[n..].trim_start();
    }
    let head_end = rest.char_indices().nth(90).map(|x| x.0).unwrap_or(rest.len());
    if let Some(c) = LEVEL_TOKEN.captures(&rest[..head_end]) {
        let m = c.get(1).unwrap();
        p.level = level_from(m.as_str());
        let before = rest[..m.start()].trim();
        let after = rest[m.end()..].trim_start_matches(|c: char| " ]):|-,;".contains(c));
        if let Some(t) = THREAD_BRACKET.captures(before) {
            p.thread = t[1].to_string();
        }
        // python "logger - LEVEL - msg" / "LEVEL:logger:msg"; logback "[thread] LEVEL logger - msg"
        let py_before = before.trim_matches(|c: char| " -|:".contains(c));
        if !py_before.is_empty() && !py_before.contains(' ') && !py_before.starts_with('[') && p.thread.is_empty() {
            p.logger = py_before.to_string();
            p.message = after.to_string();
        } else if let Some(l) = LOGGER_AFTER.captures(after) {
            if p.thread.is_empty() {
                if let Some(t) = l.get(1) {
                    p.thread = t.as_str().to_string();
                }
            }
            let name = l[2].to_string();
            let sep = after[name.len().min(after.len())..].trim_start();
            let named = name.contains('.') || name.contains('$') || sep.starts_with("- ") || sep.starts_with(": ");
            if named {
                p.logger = name;
                p.message = l[3].to_string();
            } else {
                p.message = after.to_string();
            }
        } else {
            p.message = after.to_string();
        }
        if p.thread.is_empty() {
            if let Some(t) = THREAD_BRACKET.captures(&p.message.clone()) {
                if t.get(0).unwrap().start() < 2 {
                    p.thread = t[1].to_string();
                    p.message = p.message[t.get(0).unwrap().end()..].trim_start().to_string();
                }
            }
        }
        // "ERROR:root:boom" -> after = "root:boom"
        if p.logger.is_empty() && p.message.is_empty() {
            p.message = after.to_string();
        }
    } else {
        p.message = rest.to_string();
    }
    if p.message.is_empty() {
        p.message = rest.to_string();
    }
    p
}

/// Parse one entry: `first` is its first physical line (ANSI stripped, not yet redacted), `cont` the continuation lines.
/// The returned message is the first line's message only; exception class and error id use the whole entry.
pub fn parse_entry(first: &str, cont: &[String], fmt: Format) -> Parsed {
    let mut extra_stack = String::new();
    let json = match fmt {
        Format::Json | Format::Auto if first.trim_start().starts_with('{') => parse_json(first),
        _ => None,
    };
    let mut p = if let Some((p, stack)) = json {
        extra_stack = stack;
        p
    } else if let Some(p) = match fmt {
        Format::Logfmt => parse_logfmt(first),
        Format::Auto if first.contains("level=") || first.contains("lvl=") || first.starts_with("time=") => parse_logfmt(first),
        _ => None,
    } {
        p
    } else {
        parse_text(first)
    };
    p.stack = extra_stack.clone();
    let mut body = String::from(&p.message);
    for l in cont.iter().take(400) {
        body.push('\n');
        body.push_str(l);
    }
    for l in extra_stack.lines().take(400) {
        body.push('\n');
        body.push_str(l);
    }
    if p.exception.is_empty() {
        p.exception = exception_class(&body);
    }
    if p.error_id.is_empty() {
        if let Some(c) = ERR_ID.captures(&body) {
            p.error_id = c[1].to_string();
        }
    }
    if p.level.is_none() && !p.exception.is_empty() {
        p.level = Some(ERROR);
    }
    p
}

/// The exception class an entry reports: Python (the last `XError: ...` line after a Traceback) or Java (first fully
/// qualified `...Exception` in the message or the stack, `Caused by` lines included).
pub fn exception_class(body: &str) -> String {
    if body.contains("Traceback (most recent call last)") {
        if let Some(c) = body.lines().rev().find_map(|l| PY_EXC.captures(l.trim_end()).map(|c| c[1].to_string())) {
            return c;
        }
    }
    for l in body.lines().take(60) {
        if let Some(c) = JAVA_EXC.captures(l) {
            return c[1].to_string();
        }
    }
    for l in body.lines().take(60) {
        if let Some(c) = BARE_EXC.captures(l) {
            return c[1].to_string();
        }
    }
    String::new()
}

// ---- log-specific PII scrub (before text::redact) ------------------------------------------------------------------

static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+").unwrap());
static BEARER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]{6,}").unwrap());
static AUTH_HDR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(authorization|proxy-authorization|x-api-key|x-auth-token|cookie|set-cookie)(["']?\s*[:=]\s*["']?)[^\r\n"']*"#).unwrap());
static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap());
static IPV6: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b").unwrap());

/// Log-specific PII: emails, bearer/basic values, auth and cookie header values, optionally IP addresses.
/// Everything else (tokens, passwords, JWTs, opaque keys) is left to the shared `text::redact`.
pub fn pii_scrub(line: &str, keep_ips: bool) -> String {
    let s = AUTH_HDR.replace_all(line, "$1$2[redacted]");
    let s = BEARER.replace_all(&s, "$1 [redacted]");
    let s = EMAIL.replace_all(&s, "<email>");
    if keep_ips {
        return s.into_owned();
    }
    let s = IPV4.replace_all(&s, "<ip>");
    IPV6.replace_all(&s, "<ip>").into_owned()
}

// ---- templating ---------------------------------------------------------------------------------------------------

static T_UUID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap());
static T_QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""[^"\n]{0,120}"|'[^'\n]{0,120}'"#).unwrap());
static T_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})\b").unwrap());
static T_NUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:\b|[-+])\d+(?:[.,:]\d+)*\b").unwrap());
static T_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Za-z]{1,6}[-_]?\d{3,}[\w-]*\b").unwrap());

/// Replace the variable parts of a (redacted) message with placeholders so repeats group: uuids, quoted strings, hex
/// ids, ids like `ORD-1234`, numbers.
pub fn template(msg: &str) -> String {
    let s = T_UUID.replace_all(msg, "<uuid>");
    let s = T_QUOTED.replace_all(&s, "<str>");
    let s = T_HEX.replace_all(&s, "<hex>");
    let s = T_ID.replace_all(&s, "<id>");
    let s = T_NUM.replace_all(&s, "<n>");
    let t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    t.chars().take(240).collect()
}

// ---- stack frames -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// `java`, `python` or `js`
    pub lang: &'static str,
    /// Java: `pkg.Class` (inner classes stripped); Python/JS: empty
    pub class: String,
    pub func: String,
    /// as printed in the log: `Foo.java`, `/app/x.py`, `src/a.ts`
    pub file: String,
    pub line: i64,
}

static F_JAVA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bat\s+(?:[\w.$]+/)?([\w$.]+)\.([\w$<>]+)\(([\w$.-]+\.(?:java|kt|scala|groovy)):(\d+)\)").unwrap());
static F_PY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"File "([^"]+)", line (\d+)(?:, in (\S+))?"#).unwrap());
static F_JS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bat\s+(?:(?:async\s+)?([^\s()]+)\s+\()?((?:[a-z]+://[^/\s)]*)?[^\s()?]+?\.(?:[cm]?[jt]sx?|vue|svelte))(?:\?[^:\s)]*)?:(\d+):\d+\)?").unwrap());

pub fn frames(body: &str, max: usize) -> Vec<Frame> {
    let mut v = vec![];
    for l in body.lines() {
        if v.len() >= max {
            break;
        }
        if let Some(c) = F_JAVA.captures(l) {
            let class = c[1].split('$').next().unwrap_or("").to_string();
            v.push(Frame { lang: "java", class, func: c[2].to_string(), file: c[3].to_string(), line: c[4].parse().unwrap_or(0) });
        } else if let Some(c) = F_PY.captures(l) {
            v.push(Frame { lang: "python", class: String::new(), func: c.get(3).map(|m| m.as_str().to_string()).unwrap_or_default(), file: c[1].to_string(), line: c[2].parse().unwrap_or(0) });
        } else if let Some(c) = F_JS.captures(l) {
            v.push(Frame { lang: "js", class: String::new(), func: c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(), file: c[2].to_string(), line: c[3].parse().unwrap_or(0) });
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_line_parses() {
        let p = parse_entry("2025-03-01 10:00:05,123 ERROR [http-nio-8080-exec-1] com.shop.OrderService - Failed to load order 4711 for user 'bob'", &["java.lang.NullPointerException: x".into(), "\tat com.shop.OrderService.load(OrderService.java:42)".into()], Format::Auto);
        assert_eq!(p.level, Some(ERROR));
        assert_eq!(p.logger, "com.shop.OrderService");
        assert_eq!(p.thread, "http-nio-8080-exec-1");
        assert!(p.message.starts_with("Failed to load order 4711"));
        assert_eq!(p.exception, "java.lang.NullPointerException");
        assert!(p.ts.is_some());
    }

    #[test]
    fn spring_and_python_styles() {
        let p = parse_entry("2025-03-01T10:00:05.123Z  WARN 123 --- [main] c.shop.Boot : slow start", &[], Format::Auto);
        assert_eq!((p.level, p.logger.as_str(), p.thread.as_str(), p.message.as_str()), (Some(WARN), "c.shop.Boot", "main", "slow start"));
        assert!(p.tz_known);
        let p = parse_entry("2025-03-01 10:00:05,123 - app.db - ERROR - connection lost", &[], Format::Auto);
        assert_eq!((p.level, p.logger.as_str(), p.message.as_str()), (Some(ERROR), "app.db", "connection lost"));
        let p = parse_entry("ERROR:root:boom", &["Traceback (most recent call last):".into(), "  File \"/srv/app/views.py\", line 12, in get".into(), "ValueError: bad".into()], Format::Auto);
        assert_eq!((p.level, p.exception.as_str()), (Some(ERROR), "ValueError"));
    }

    #[test]
    fn json_and_logfmt() {
        let p = parse_entry(r#"{"@timestamp":"2025-03-01T10:00:05Z","level":"error","logger_name":"a.B","message":"x 1","stack_trace":"java.io.IOException: boom\n\tat a.B.c(B.java:3)"}"#, &[], Format::Auto);
        assert_eq!((p.level, p.logger.as_str(), p.exception.as_str()), (Some(ERROR), "a.B", "java.io.IOException"));
        let p = parse_entry(r#"time=2025-03-01T10:00:05Z level=warn msg="disk slow" took=3s"#, &[], Format::Auto);
        assert_eq!((p.level, p.message.as_str()), (Some(WARN), "disk slow"));
    }

    #[test]
    fn entry_boundaries() {
        assert!(is_entry_start("2025-03-01 10:00:05 INFO x", Format::Auto));
        assert!(!is_entry_start("\tat a.B.c(B.java:3)", Format::Auto));
        assert!(!is_entry_start("Caused by: java.io.IOException: x", Format::Auto));
        assert!(!is_entry_start("Traceback (most recent call last):", Format::Auto));
        assert!(!is_entry_start("ValueError: bad", Format::Auto));
        assert!(is_entry_start("Starting server on port 8080", Format::Auto));
    }

    #[test]
    fn templates_group() {
        let a = template("Failed to load order 4711 for user 'bob' id 3f2a9c1d-1111-2222-3333-444455556666");
        let b = template("Failed to load order 9 for user 'alice' id 00000000-1111-2222-3333-444455556666");
        assert_eq!(a, b);
        assert_eq!(a, "Failed to load order <n> for user <str> id <uuid>");
    }

    #[test]
    fn frames_all_langs() {
        let f = frames("\tat com.shop.OrderService$Inner.load(OrderService.java:42)\n  File \"/srv/app/views.py\", line 12, in get\n    at render (webpack:///./src/pages/Orders.tsx?a1b2:10:5)", 10);
        assert_eq!(f.len(), 3);
        assert_eq!((f[0].class.as_str(), f[0].line), ("com.shop.OrderService", 42));
        assert_eq!((f[1].file.as_str(), f[1].func.as_str()), ("/srv/app/views.py", "get"));
        assert_eq!((f[2].file.as_str(), f[2].line), ("webpack:///./src/pages/Orders.tsx", 10));
    }

    #[test]
    fn pii_scrub_removes_pii() {
        let s = pii_scrub("user bob@example.test from 10.1.2.3 Authorization: Bearer abcdef123456 cookie: sid=zzz", false);
        for bad in ["bob@example.test", "10.1.2.3", "abcdef123456", "zzz"] {
            assert!(!s.contains(bad), "{s}");
        }
    }
}
