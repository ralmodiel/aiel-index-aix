//! Named fields at ingest for data sets (`aix put NAME --pattern ...`): regexes with named groups, templates
//! (`{ts:time} [{level}] {logger}: {msg}`), presets (`--format log|clf|syslog`), `--fields a,b --sep S` splitting,
//! `--kv` key=value pairs, `--multiline START` record joining and `--type f=int|num|time` typing; plus `--pattern auto`
//! / `--guess`, which proposes a template from the first lines and says how many it matches. Extraction runs on the
//! redacted text, so a secret never reaches a field. The rows land in the set store's `recs` table (one JSON object
//! per record, keyed by its first line) and every field query (`--where`, `--field`, `count by`, `sql`) reads them.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Text,
    Int,
    Num,
    Time,
}

impl Ty {
    pub fn parse(s: &str) -> Option<Ty> {
        Some(match s {
            "text" | "str" | "string" | "word" | "ip" | "quoted" => Ty::Text,
            "int" | "integer" => Ty::Int,
            "num" | "number" | "float" => Ty::Num,
            "time" | "ts" | "date" | "datetime" => Ty::Time,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Ty::Text => "text",
            Ty::Int => "int",
            Ty::Num => "num",
            Ty::Time => "time",
        }
    }
}

/// What the store keeps for an item (`items.shape`): the user's inputs, recompiled when lines are appended.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ShapeSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pats: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sep: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kv: bool,
    /// "log" (the logs parser: ts level thread logger msg exception), "clf", "syslog"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub types: BTreeMap<String, String>,
}

impl ShapeSpec {
    pub fn is_empty(&self) -> bool {
        self.pats.is_empty() && self.fields.is_empty() && !self.kv && self.preset.is_none()
    }
    /// One line for `sets` / the put summary.
    pub fn describe(&self) -> String {
        let mut v = vec![];
        if let Some(p) = &self.preset {
            v.push(format!("preset {p}"));
        }
        for p in &self.pats {
            v.push(format!("pattern '{p}'"));
        }
        if !self.fields.is_empty() {
            v.push(format!("fields {} sep '{}'", self.fields.join(","), self.sep.as_deref().unwrap_or(" ")));
        }
        if self.kv {
            v.push("key=value pairs".into());
        }
        if let Some(m) = &self.multiline {
            v.push(format!("multiline '{m}'"));
        }
        v.join("; ")
    }
}

pub struct Pat {
    pub re: Regex,
    /// capture group index -> field name (None: a non-field group)
    pub names: Vec<Option<String>>,
    /// fields whose value is a "..." string (quotes stripped)
    pub quoted: Vec<String>,
}

pub struct Shape {
    pub spec: ShapeSpec,
    pub pats: Vec<Pat>,
    pub multiline: Option<Regex>,
    /// records start where the logs parser sees an entry start (preset log)
    pub entry_start: bool,
    pub split: Option<(Vec<String>, Sep)>,
    pub types: BTreeMap<String, Ty>,
}

pub enum Sep {
    Lit(String),
    Re(Regex),
}

const RE_LIMIT: usize = 1 << 21;

fn build(re: &str, what: &str) -> Result<Regex> {
    regex::RegexBuilder::new(re).size_limit(RE_LIMIT).dfa_size_limit(RE_LIMIT * 2).build().map_err(|e| {
        let m = e.to_string();
        let last = m.lines().filter(|l| !l.trim().is_empty()).last().unwrap_or("invalid").trim().to_string();
        anyhow!("{what} {re:?}: {last}")
    })
}

pub const TS_RE: &str = r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d(?:[.,]\d{1,9})?)?(?:Z|[+-]\d\d:?\d\d)?|\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:[.,]\d{1,9})?|\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d(?: [+-]\d{4})?|[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d\d:\d\d:\d\d(?:[.,]\d{1,9})?";
const LV_RE: &str = r"TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|SEVERE|CRITICAL";

pub fn preset_regexes(name: &str) -> Option<(Vec<&'static str>, Vec<(&'static str, Ty)>)> {
    Some(match name {
        "clf" => (
            vec![r#"^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" (?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?"#],
            vec![("status", Ty::Int), ("size", Ty::Int), ("ts", Ty::Time)],
        ),
        "syslog" => (vec![r"^(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) (?P<host>\S+) (?P<app>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"], vec![("pid", Ty::Int), ("ts", Ty::Time)]),
        _ => return None,
    })
}

/// Is this pattern a template (`{name}` placeholders) rather than a regex?
pub fn is_template(p: &str) -> bool {
    !p.contains("(?P<") && !p.contains("(?<") && Regex::new(r"\{[A-Za-z_][\w]*(?::[^}]*)?\}|\{_\}").unwrap().is_match(p)
}

/// `{ts} [{level}] {logger}: {msg}` -> an anchored regex: `{name}` lazy, the last placeholder takes the rest, literal
/// text escaped (a run of spaces matches any run of spaces), `{name:int|num|time|ip|word|quoted}` typed,
/// `{name:/re/}` a custom sub-regex, `{_}` a skipped part. Returns (regex, field types, quoted fields).
pub fn template_to_regex(t: &str) -> Result<(String, Vec<(String, Ty)>, Vec<String>)> {
    static PH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{(_|[A-Za-z_]\w*)(?::(/(?:[^/\\]|\\.)*/|[a-z]+))?\}").unwrap());
    let phs: Vec<regex::Captures> = PH.captures_iter(t).collect();
    if phs.is_empty() {
        bail!("pattern {t:?}: no {{name}} placeholder (or write a regex with (?P<name>...) groups)");
    }
    // (?s): the last field of a multi-line record (--multiline, log entries) takes its continuation lines too
    let mut re = String::from("(?s)^");
    let mut types = vec![];
    let mut quoted = vec![];
    let mut last = 0;
    let lit = |s: &str| -> String {
        let mut o = String::new();
        let mut sp = false;
        for c in s.chars() {
            if c == ' ' {
                if !sp {
                    o.push_str(r"\s+");
                }
                sp = true;
            } else {
                sp = false;
                o.push_str(&regex::escape(&c.to_string()));
            }
        }
        o
    };
    let mut seen = std::collections::HashSet::new();
    for (k, c) in phs.iter().enumerate() {
        let m = c.get(0).unwrap();
        re.push_str(&lit(&t[last..m.start()]));
        last = m.end();
        let name = &c[1];
        let is_last = k + 1 == phs.len();
        let rest_lazy = if is_last { ".*" } else { ".*?" };
        let (body, ty, q) = match c.get(2).map(|x| x.as_str()) {
            None => (rest_lazy.to_string(), Ty::Text, false),
            Some(s) if s.starts_with('/') => (s[1..s.len() - 1].replace("\\/", "/"), Ty::Text, false),
            Some("int") => (r"[-+]?\d+".to_string(), Ty::Int, false),
            Some("num") => (r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?".to_string(), Ty::Num, false),
            Some("time") => (format!("(?:{TS_RE})"), Ty::Time, false),
            Some("ip") => (r"<ip>|\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+".to_string(), Ty::Text, false),
            Some("word") => (r"\S+".to_string(), Ty::Text, false),
            Some("quoted") => (r#""(?:[^"\\]|\\.)*""#.to_string(), Ty::Text, true),
            Some("text") | Some("rest") => (rest_lazy.to_string(), Ty::Text, false),
            Some(other) => bail!("pattern {t:?}: unknown placeholder type {{{name}:{other}}} (int, num, time, ip, word, quoted, text, or /regex/)"),
        };
        if name == "_" {
            re.push_str(&format!("(?:{body})"));
            continue;
        }
        if !seen.insert(name.to_string()) {
            bail!("pattern {t:?}: field {{{name}}} appears twice");
        }
        re.push_str(&format!("(?P<{name}>{body})"));
        if ty != Ty::Text {
            types.push((name.to_string(), ty));
        }
        if q {
            quoted.push(name.to_string());
        }
    }
    re.push_str(&lit(&t[last..]));
    re.push('$');
    Ok((re, types, quoted))
}

impl ShapeSpec {
    pub fn compile(&self) -> Result<Shape> {
        let mut pats = vec![];
        let mut types: BTreeMap<String, Ty> = BTreeMap::new();
        let mut entry_start = false;
        if let Some(p) = &self.preset {
            if p == "log" {
                entry_start = true;
                types.insert("ts".into(), Ty::Time);
            } else if let Some((res, ts)) = preset_regexes(p) {
                for r in res {
                    pats.push(Pat { re: build(r, "preset")?, names: vec![], quoted: vec![] });
                }
                for (f, t) in ts {
                    types.insert(f.into(), t);
                }
            } else {
                bail!("unknown preset {p}");
            }
        }
        for p in &self.pats {
            if is_template(p) {
                let (re, ts, q) = template_to_regex(p)?;
                pats.push(Pat { re: build(&re, "pattern")?, names: vec![], quoted: q });
                for (f, t) in ts {
                    types.insert(f, t);
                }
            } else {
                pats.push(Pat { re: build(p, "pattern")?, names: vec![], quoted: vec![] });
            }
        }
        for p in &mut pats {
            let mut unnamed = 0;
            p.names = p
                .re
                .capture_names()
                .enumerate()
                .map(|(i, n)| {
                    if i == 0 {
                        return None;
                    }
                    Some(match n {
                        Some(n) => n.to_string(),
                        None => {
                            unnamed += 1;
                            format!("f{unnamed}")
                        }
                    })
                })
                .collect();
        }
        let multiline = match &self.multiline {
            Some(m) => Some(build(m, "--multiline")?),
            None => None,
        };
        let split = if self.fields.is_empty() {
            None
        } else {
            let sep = match self.sep.as_deref() {
                None | Some(" ") => Sep::Re(Regex::new(r"\s+").unwrap()),
                Some(s) if s.len() >= 2 && s.starts_with('/') && s.ends_with('/') => Sep::Re(build(&s[1..s.len() - 1], "--sep")?),
                Some(s) => Sep::Lit(s.to_string()),
            };
            Some((self.fields.clone(), sep))
        };
        for (f, t) in &self.types {
            types.insert(f.clone(), Ty::parse(t).ok_or_else(|| anyhow!("--type {f}={t}: int, num, time or text"))?);
        }
        Ok(Shape { spec: self.clone(), pats, multiline, entry_start, split, types })
    }
}

static KV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:^|[\s,;{(\[])([A-Za-z_][\w.\-]{0,63})=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;)\]}]*)"#).unwrap());
static LEAD_TS: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^\W{{0,2}}(?:{TS_RE})")).unwrap());

/// Fields of one record (its text, continuation lines joined with `\n`): (fields, which pattern matched (1-based; 0 none),
/// fields whose value did not parse as their type).
pub fn extract(sh: &Shape, text: &str) -> (Map<String, Value>, usize, Vec<String>) {
    let mut m = Map::new();
    let mut which = 0usize;
    let first = text.split('\n').next().unwrap_or("");
    if sh.entry_start {
        let cont: Vec<String> = text.split('\n').skip(1).map(str::to_string).collect();
        let p = aix_extract::logparse::parse_entry(first, &cont, aix_extract::logparse::Format::Auto);
        if let Some(ts) = LEAD_TS.find(first) {
            m.insert("ts".into(), Value::String(ts.as_str().trim_start_matches(|c: char| !c.is_alphanumeric()).to_string()));
        }
        if let Some(l) = p.level {
            m.insert("level".into(), Value::String(aix_extract::logparse::level_name(l).into()));
        }
        for (k, v) in [("thread", &p.thread), ("logger", &p.logger), ("msg", &p.message), ("exception", &p.exception), ("error_id", &p.error_id)] {
            if !v.is_empty() {
                m.insert(k.into(), Value::String(v.clone()));
            }
        }
        if p.level.is_some() || m.contains_key("ts") {
            which = 1;
        }
    }
    // a pattern is tried on the whole record first (multi-line groups), then on its first line
    for (i, p) in sh.pats.iter().enumerate() {
        if which > 0 && !sh.entry_start {
            break;
        }
        let caps = p.re.captures(text).or_else(|| if text.contains('\n') { p.re.captures(first) } else { None });
        if let Some(c) = caps {
            for (gi, n) in p.names.iter().enumerate() {
                let (Some(n), Some(g)) = (n, c.get(gi)) else { continue };
                let mut v = g.as_str().to_string();
                if p.quoted.contains(n) && v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                    v = v[1..v.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\");
                }
                m.insert(n.clone(), Value::String(v));
            }
            which = i + 1 + usize::from(sh.entry_start);
            break;
        }
    }
    if let Some((names, sep)) = &sh.split {
        let parts: Vec<String> = match sep {
            Sep::Lit(s) => first.splitn(names.len(), s.as_str()).map(str::to_string).collect(),
            Sep::Re(r) => r.splitn(first.trim(), names.len()).map(str::to_string).collect(),
        };
        if parts.len() == names.len() || parts.len() > 1 {
            for (n, v) in names.iter().zip(parts) {
                m.entry(n.clone()).or_insert(Value::String(v));
            }
            if which == 0 {
                which = sh.pats.len() + 1;
            }
        }
    }
    if sh.spec.kv {
        let mut any = false;
        for c in KV.captures_iter(first) {
            let k = c[1].to_string();
            let mut v = c[2].to_string();
            if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) {
                v = v[1..v.len() - 1].replace("\\\"", "\"");
            }
            any = true;
            m.entry(k).or_insert(Value::String(v));
        }
        if which == 0 && any {
            which = sh.pats.len() + 2;
        }
    }
    let mut bad = vec![];
    for (f, t) in &sh.types {
        let Some(Value::String(s)) = m.get(f) else { continue };
        let s = s.clone();
        match t {
            Ty::Int => match s.trim().parse::<i64>() {
                Ok(n) => {
                    m.insert(f.clone(), Value::from(n));
                }
                Err(_) => bad.push(f.clone()),
            },
            Ty::Num => match s.trim().parse::<f64>().ok().and_then(serde_json::Number::from_f64) {
                Some(n) => {
                    m.insert(f.clone(), Value::Number(n));
                }
                None => bad.push(f.clone()),
            },
            Ty::Time => {
                if parse_time(&s).is_none() {
                    bad.push(f.clone())
                }
            }
            Ty::Text => {}
        }
    }
    (m, which, bad)
}

static T_ISO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d{1,9}))?)?)?\s*(Z|[+-]\d\d:?\d\d)?$").unwrap());
static T_SLASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{4})/(\d\d)/(\d\d)(?: (\d\d):(\d\d)(?::(\d\d)(?:[.,](\d{1,9}))?)?)?$").unwrap());
static T_CLF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d\d)/([A-Z][a-z]{2})/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-]\d{4}))?$").unwrap());
static T_SYS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)$").unwrap());
static T_HMS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?$").unwrap());
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn tz(s: Option<&str>) -> f64 {
    let Some(s) = s else { return 0.0 };
    if s == "Z" {
        return 0.0;
    }
    let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 4 {
        return 0.0;
    }
    let h: f64 = d[..2].parse().unwrap_or(0.0);
    let mi: f64 = d[2..].parse().unwrap_or(0.0);
    let sign = if s.starts_with('-') { -1.0 } else { 1.0 };
    sign * (h * 3600.0 + mi * 60.0)
}

fn frac(s: Option<regex::Match>) -> f64 {
    s.map(|m| format!("0.{}", m.as_str()).parse::<f64>().unwrap_or(0.0)).unwrap_or(0.0)
}

/// A timestamp -> seconds since the epoch (naive stamps as UTC; syslog stamps without a year as year 2000; a time of
/// day alone as seconds since midnight): ISO 8601 (minutes or seconds), `YYYY/MM/DD hh:mm:ss`, CLF, syslog, epoch
/// seconds (10 digits) or milliseconds (13 digits).
pub fn parse_time(s: &str) -> Option<f64> {
    let s = s.trim();
    let g = |c: &regex::Captures, i: usize| -> i64 { c.get(i).and_then(|m| m.as_str().parse().ok()).unwrap_or(0) };
    if let Some(c) = T_ISO.captures(s).or_else(|| T_SLASH.captures(s)) {
        let e = aix_extract::logparse::civil_to_epoch(g(&c, 1), g(&c, 2), g(&c, 3), g(&c, 4), g(&c, 5), g(&c, 6)) as f64;
        return Some(e + frac(c.get(7)) - tz(c.get(8).map(|m| m.as_str())));
    }
    if let Some(c) = T_CLF.captures(s) {
        let mo = MONTHS.iter().position(|m| *m == &c[2])? as i64 + 1;
        let e = aix_extract::logparse::civil_to_epoch(g(&c, 3), mo, g(&c, 1), g(&c, 4), g(&c, 5), g(&c, 6)) as f64;
        return Some(e - tz(c.get(7).map(|m| m.as_str())));
    }
    if let Some(c) = T_SYS.captures(s) {
        let mo = MONTHS.iter().position(|m| *m == &c[1])? as i64 + 1;
        return Some(aix_extract::logparse::civil_to_epoch(2000, mo, g(&c, 2), g(&c, 3), g(&c, 4), g(&c, 5)) as f64);
    }
    if let Some(c) = T_HMS.captures(s) {
        return Some((g(&c, 1) * 3600 + g(&c, 2) * 60 + g(&c, 3)) as f64 + frac(c.get(4)));
    }
    if s.len() == 10 && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    if s.len() == 13 && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<f64>().ok().map(|x| x / 1000.0);
    }
    None
}

// ---- guessing a template ----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Guess {
    /// None: the lines are JSON / CSV (their own fields), or nothing was recognised
    pub spec: Option<ShapeSpec>,
    pub fmt: Option<crate::sets::Fmt>,
    pub shown: String,
    pub rate: f64,
    pub matched: usize,
    pub sample: usize,
    pub what: String,
}

static G_THREAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[[^\]\s][^\]]{0,79}\]").unwrap());
static G_LEVEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^(?:\[(?:{LV_RE})\]|(?:{LV_RE}))(?:\s|$)")).unwrap());
static G_LOGGER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z_][\w.$]{1,120})(\s+-\s+|:\s+)").unwrap());
static G_PID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{1,7}\s").unwrap());

/// The template shape of one line: `{ts:time} {level} [{thread}] {logger} - {msg}`.
fn line_template(l: &str) -> Option<String> {
    let mut s = l;
    let mut t = String::new();
    let mut got = 0;
    if let Some(m) = LEAD_TS.find(s).filter(|m| m.start() == 0) {
        t.push_str("{ts:time}");
        s = &s[m.end()..];
        got += 1;
    }
    let mut level_done = false;
    let mut thread_done = false;
    let mut pid_done = false;
    for _ in 0..4 {
        let ws = s.len() - s.trim_start().len();
        if ws == 0 && !t.is_empty() {
            break;
        }
        let rest = s.trim_start();
        if !level_done {
            if let Some(m) = G_LEVEL.find(rest) {
                let tok = m.as_str().trim_end();
                if !t.is_empty() {
                    t.push(' ');
                }
                t.push_str(if tok.starts_with('[') { "[{level}]" } else { "{level}" });
                s = &rest[tok.len()..];
                level_done = true;
                got += 1;
                continue;
            }
        }
        if !thread_done {
            if let Some(m) = G_THREAD.find(rest) {
                if !t.is_empty() {
                    t.push(' ');
                }
                t.push_str("[{thread}]");
                s = &rest[m.end()..];
                thread_done = true;
                got += 1;
                continue;
            }
        }
        if !pid_done && got > 0 {
            if let Some(m) = G_PID.find(rest) {
                if !t.is_empty() {
                    t.push(' ');
                }
                t.push_str("{pid:int}");
                s = &rest[m.end() - 1..];
                pid_done = true;
                continue;
            }
        }
        break;
    }
    if got == 0 {
        return None;
    }
    let rest = s.trim_start();
    if let Some(c) = G_LOGGER.captures(rest) {
        let sep = if c[2].trim() == "-" { " - " } else { ": " };
        t.push_str(&format!(" {{logger}}{sep}{{msg}}"));
    } else {
        t.push_str(" {msg}");
    }
    Some(t)
}

/// Propose fields for the first lines of an input: JSON lines / CSV keep their own fields; CLF and syslog presets; a
/// log template; key=value pairs. `rate` = share of the sampled record lines the proposal matches.
pub fn guess(lines: &[String], name: &str) -> Guess {
    let sample: Vec<&str> = lines.iter().map(String::as_str).filter(|l| !l.trim().is_empty()).take(200).collect();
    let n = sample.len().max(1);
    let fmt = crate::sets::detect(&lines.iter().take(200).cloned().collect::<Vec<_>>(), name);
    let mut g = Guess { spec: None, fmt: None, shown: String::new(), rate: 0.0, matched: 0, sample: sample.len(), what: String::new() };
    if matches!(fmt, crate::sets::Fmt::Jsonl | crate::sets::Fmt::Json | crate::sets::Fmt::Csv | crate::sets::Fmt::Tsv) {
        g.fmt = Some(fmt);
        g.rate = 1.0;
        g.matched = sample.len();
        g.what = format!("{} (fields come from the data itself; no pattern needed)", fmt.name());
        g.shown = format!("--format {}", fmt.name());
        return g;
    }
    for p in ["clf", "syslog"] {
        let (res, _) = preset_regexes(p).unwrap();
        let re = Regex::new(res[0]).unwrap();
        let k = sample.iter().filter(|l| re.is_match(l)).count();
        if k * 10 >= n * 8 {
            g.spec = Some(ShapeSpec { preset: Some(p.into()), ..Default::default() });
            g.rate = k as f64 / n as f64;
            g.matched = k;
            g.what = format!("{p} lines");
            g.shown = format!("--format {p}");
            return g;
        }
    }
    // the commonest line shape among the lines that start an entry; the others continue one (stack frames)
    let starts: Vec<&str> = sample.iter().copied().filter(|l| aix_extract::logparse::is_entry_start(l, aix_extract::logparse::Format::Auto)).collect();
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    for l in &starts {
        if let Some(t) = line_template(l) {
            *shapes.entry(t).or_default() += 1;
        }
    }
    let kv_lines = sample.iter().filter(|l| KV.captures_iter(l).count() >= 2).count();
    let kv = kv_lines * 2 >= n;
    let best = shapes.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.len().cmp(&a.0.len())));
    let cont = sample.len() - starts.len();
    if let Some((tpl, _)) = best {
        let mut spec = ShapeSpec { pats: vec![tpl.clone()], kv, ..Default::default() };
        if cont > 0 && tpl.starts_with("{ts:time}") {
            // the start regex of the stamp form the lines use (short enough to read and edit)
            let f = starts.iter().find_map(|l| LEAD_TS.find(l).map(|m| m.as_str().to_string())).unwrap_or_default();
            let b = f.as_bytes();
            let ml = if b.len() >= 10 && b[4] == b'-' {
                r"^\d{4}-\d\d-\d\d"
            } else if b.len() >= 10 && b[4] == b'/' {
                r"^\d{4}/\d\d/\d\d"
            } else if b.len() >= 3 && b[2] == b':' {
                r"^\d\d:\d\d:\d\d"
            } else {
                ""
            };
            spec.multiline = Some(if ml.is_empty() { format!(r"^\W{{0,2}}(?:{TS_RE})") } else { ml.to_string() });
        }
        if let Ok(sh) = spec.compile() {
            let units = if spec.multiline.is_some() { starts.len() } else { sample.len() };
            let k = if spec.multiline.is_some() { starts.iter().filter(|l| sh.pats[0].re.is_match(l)).count() } else { sample.iter().filter(|l| sh.pats[0].re.is_match(l)).count() };
            g.rate = k as f64 / units.max(1) as f64;
            g.matched = k;
            g.sample = units;
            g.what = format!("log lines{}{}", if spec.multiline.is_some() { ", continuation lines joined to their entry" } else { "" }, if kv { ", plus key=value pairs" } else { "" });
            g.shown = format!("--pattern '{tpl}'{}{}", if kv { " --kv" } else { "" }, spec.multiline.as_ref().map(|m| format!(" --multiline '{m}'")).unwrap_or_default());
            g.spec = Some(spec);
            return g;
        }
    }
    if kv {
        g.spec = Some(ShapeSpec { kv: true, ..Default::default() });
        g.rate = kv_lines as f64 / n as f64;
        g.matched = kv_lines;
        g.what = "key=value lines".into();
        g.shown = "--kv".into();
        return g;
    }
    g.what = "no recognisable shape (plain text)".into();
    g
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates() {
        let (re, ty, _) = template_to_regex("{ts:time} [{level}] {logger}: {msg}").unwrap();
        let r = Regex::new(&re).unwrap();
        let c = r.captures("2026-10-24 10:00:01 [INFO] com.x.A: hello: world").unwrap();
        assert_eq!((&c["level"], &c["logger"], &c["msg"]), ("INFO", "com.x.A", "hello: world"));
        assert_eq!(ty, vec![("ts".to_string(), Ty::Time)]);
        let (re, _, _) = template_to_regex("{_} id={id:/[A-Z]+-\\d+/} took {ms:int}ms").unwrap();
        let c = Regex::new(&re).unwrap().captures("xx yy id=ORD-12 took 45ms").unwrap();
        assert_eq!((&c["id"], &c["ms"]), ("ORD-12", "45"));
        assert!(template_to_regex("{a} {a}").is_err() && template_to_regex("{a:bogus}").is_err());
        assert!(parse_time("2026-10-24T10:00").unwrap() < parse_time("2026-10-24 10:00:01").unwrap());
        assert_eq!(parse_time("10/Oct/2000:13:55:36 -0700"), Some(971211336.0));
        assert_eq!(line_template("2026-10-24 10:00:01.123 INFO [main] com.x.Svc - payment failed").unwrap(), "{ts:time} {level} [{thread}] {logger} - {msg}");
    }
}
