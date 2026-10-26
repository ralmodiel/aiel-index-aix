//! Same-arity overloads (Java, Kotlin, C#): `get(String)` and `get(Integer)` both take one argument, so the argument
//! count cannot pick one. The call's own text can: literal arguments and locals declared in the calling member have a
//! type. When exactly one overload accepts those types it keeps its confidence; when the types cannot tell them apart
//! every remaining overload is a `heuristic` edge (a labelled guess), never `exact`.

use super::*;

/// Parameter types of a signature (`Item get(String name, final int n)` -> ["String", "int"]).
pub(super) fn param_types(sig: &str) -> Vec<String> {
    let Some(open) = sig.find('(') else { return vec![] };
    let mut depth = 0i32;
    let (mut out, mut cur) = (vec![], String::new());
    for c in sig[open..].chars() {
        match c {
            '(' | '<' | '[' => {
                depth += 1;
                if depth > 1 && c != '<' {
                    cur.push(c);
                }
            }
            ')' | '>' | ']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                if c != '>' {
                    cur.push(c);
                }
            }
            ',' if depth == 1 => out.push(std::mem::take(&mut cur)),
            _ if depth > 1 && c != '[' && c != ']' => {} // generic arguments are dropped
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out.iter().map(|p| param_type(p)).collect()
}

fn param_type(p: &str) -> String {
    let p = p.trim();
    // Kotlin / Scala: `name: Type`
    if let Some((_, t)) = p.split_once(':') {
        return simple(t.trim().trim_end_matches('?'));
    }
    let toks: Vec<&str> = p.split_whitespace().filter(|t| !t.starts_with('@') && !matches!(*t, "final" | "ref" | "out" | "in" | "params" | "this")).collect();
    match toks.len() {
        0 => String::new(),
        1 => simple(toks[0]),
        n => simple(toks[n - 2]),
    }
}

fn simple(t: &str) -> String {
    let t = t.trim_end_matches("...").trim_end_matches("[]");
    t.rsplit('.').next().unwrap_or(t).to_string()
}

fn norm(t: &str) -> &str {
    match t {
        "Integer" | "Int" | "int" | "Int32" => "int",
        "Long" | "long" | "Int64" => "long",
        "Double" | "double" => "double",
        "Float" | "float" | "Single" => "float",
        "Boolean" | "boolean" | "bool" => "boolean",
        "Character" | "char" | "Char" => "char",
        "Short" | "short" => "short",
        "Byte" | "byte" => "byte",
        "String" | "string" => "String",
        t => t,
    }
}

/// Types whose values are never another type (final / primitive): a mismatch between two of them is certain.
fn closed(t: &str) -> bool {
    matches!(norm(t), "int" | "long" | "double" | "float" | "boolean" | "char" | "short" | "byte" | "String")
}

fn widens(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("byte", "short" | "int" | "long" | "float" | "double")
            | ("short", "int" | "long" | "float" | "double")
            | ("char", "int" | "long" | "float" | "double")
            | ("int", "long" | "float" | "double")
            | ("long", "float" | "double")
            | ("float", "double")
    )
}

/// May an argument of type `arg` ("" = unknown, "null") be passed as `param`?
fn accepts(param: &str, arg: &str) -> bool {
    if arg.is_empty() || param.is_empty() {
        return true;
    }
    let p = norm(param);
    if matches!(p, "Object" | "object" | "Any" | "dynamic" | "var" | "T" | "Number" | "Comparable" | "Serializable" | "CharSequence")
        || (p.len() == 1 && p.chars().all(|c| c.is_ascii_uppercase()))
    {
        // CharSequence takes only strings among the closed types; Number only numbers
        return match p {
            "CharSequence" => !closed(arg) || norm(arg) == "String",
            "Number" => !closed(arg) || !matches!(norm(arg), "String" | "boolean" | "char"),
            _ => true,
        };
    }
    if arg == "null" {
        return !matches!(param, "int" | "long" | "double" | "float" | "boolean" | "char" | "short" | "byte");
    }
    let a = norm(arg);
    if a == p {
        return true;
    }
    if closed(arg) && closed(param) {
        // boxing and primitive widening; an int literal never boxes to Long / Double
        return widens(a, p) && param.chars().next().is_some_and(|c| c.is_ascii_lowercase());
    }
    // a closed argument never becomes an unrelated class, and a class never becomes a primitive or a String
    !(closed(arg) || closed(param))
}

/// The text of the call's arguments on its line (`callee(` first occurrence after a `.` or at a word start).
fn call_args(line: &str, callee: &str) -> Option<Vec<String>> {
    let b = line.as_bytes();
    let mut from = 0;
    while let Some(k) = line[from..].find(callee) {
        let s = from + k;
        let e = s + callee.len();
        from = e;
        let before_ok = s == 0 || !(b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_');
        let mut j = e;
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        if !before_ok || j >= b.len() || b[j] != b'(' {
            continue;
        }
        let mut depth = 0i32;
        let (mut args, mut cur) = (vec![], String::new());
        let mut q: Option<char> = None;
        let mut esc = false;
        for c in line[j..].chars() {
            if let Some(qc) = q {
                cur.push(c);
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == qc {
                    q = None;
                }
                continue;
            }
            match c {
                '"' | '\'' => {
                    q = Some(c);
                    cur.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth > 1 {
                        cur.push(c);
                    }
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if !cur.trim().is_empty() {
                            args.push(cur.trim().to_string());
                        }
                        return Some(args);
                    }
                    cur.push(c);
                }
                ',' if depth == 1 => args.push(std::mem::take(&mut cur).trim().to_string()),
                c => cur.push(c),
            }
        }
        return None; // the arguments continue on the next line
    }
    None
}

/// Type of one argument expression: a literal's type, a local declared in `body` (the calling member's lines up to the
/// call), or "" when unknown.
fn arg_type(a: &str, body: &[&str]) -> String {
    let a = a.trim();
    if a.starts_with('"') || a.starts_with("@\"") || a.starts_with("$\"") {
        return "String".into();
    }
    if a.starts_with('\'') {
        return "char".into();
    }
    if a == "true" || a == "false" {
        return "boolean".into();
    }
    if a == "null" {
        return "null".into();
    }
    let num = a.trim_start_matches('-');
    if num.chars().next().is_some_and(|c| c.is_ascii_digit()) && num.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_') {
        let l = num.to_ascii_lowercase();
        return if l.starts_with("0x") {
            if l.ends_with('l') { "long" } else { "int" }
        } else if l.ends_with('l') {
            "long"
        } else if l.ends_with('f') {
            "float"
        } else if l.ends_with('d') || l.ends_with('m') || l.contains('.') || l.contains('e') {
            "double"
        } else {
            "int"
        }
        .into();
    }
    if !a.chars().all(|c| c.is_alphanumeric() || c == '_') || a.is_empty() {
        return String::new();
    }
    // `Type a` / `Type<X> a` / `a: Type` declared earlier in the member (parameters included); the last one wins
    let Ok(re) = regex::Regex::new(&format!(r"\b([A-Za-z_][\w.]*)(?:<[^<>()]*>)?(?:\[\])*\s+{a}\s*[=;,):]|\b{a}\s*:\s*([A-Za-z_][\w.]*)")) else {
        return String::new();
    };
    let mut ty = String::new();
    for l in body {
        for c in re.captures_iter(l) {
            let t = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()).unwrap_or("");
            if !matches!(t, "return" | "new" | "else" | "case" | "throw" | "val" | "var" | "let" | "final" | "await") {
                ty = simple(t);
            }
        }
    }
    if ty == "var" { String::new() } else { ty }
}

impl Graph {
    fn src_lines(&self, file: &str) -> Option<Arc<Vec<String>>> {
        if let Some(t) = self.src_.lock().ok()?.get(file) {
            return t.clone();
        }
        let t = std::fs::read_to_string(self.repo.join(file)).ok().map(|s| Arc::new(s.lines().map(str::to_string).collect::<Vec<_>>()));
        self.src_.lock().ok()?.insert(file.to_string(), t.clone());
        t
    }

    /// Among targets, the overload groups (same file, container, name) with more than one member: keep the overloads
    /// whose parameter types accept the call's argument types; an undecided group becomes `heuristic`.
    pub(super) fn pick_overloads(&self, file: &str, callee: &str, rc: &Rc, v: &mut Vec<(usize, &'static str)>) {
        let mut groups: HashMap<(&str, &str, &str), Vec<usize>> = HashMap::new();
        for (k, (i, _)) in v.iter().enumerate() {
            let m = &self.ms[*i];
            if !m.params.is_empty() || m.arity == Some((0, 0)) {
                groups.entry((m.file.as_str(), m.container.as_str(), m.name.as_str())).or_default().push(k);
            }
        }
        if !groups.values().any(|g| g.len() > 1) {
            return;
        }
        let args: Option<Vec<String>> = self.src_lines(file).and_then(|ls| {
            let at = (rc.line - 1).max(0) as usize;
            let line = ls.get(at)?;
            let raw = call_args(line, callee)?;
            let from = if rc.caller_line > 0 { (rc.caller_line - 1) as usize } else { at.saturating_sub(40) };
            let body: Vec<&str> = ls[from.min(at)..=at.min(ls.len() - 1)].iter().map(|s| s.as_str()).collect();
            Some(raw.iter().map(|a| arg_type(a, &body)).collect())
        });
        let mut drop: HashSet<usize> = HashSet::new();
        let mut guess: HashSet<usize> = HashSet::new();
        for g in groups.values().filter(|g| g.len() > 1) {
            let ok: Vec<usize> = match &args {
                Some(a) => g
                    .iter()
                    .copied()
                    .filter(|&k| {
                        let ps = &self.ms[v[k].0].params;
                        a.iter().enumerate().all(|(j, t)| ps.get(j).or(ps.last()).is_none_or(|p| accepts(p, t)))
                    })
                    .collect(),
                None => g.clone(),
            };
            if ok.len() == 1 {
                drop.extend(g.iter().copied().filter(|k| *k != ok[0]));
            } else {
                let keep: &Vec<usize> = if ok.is_empty() { g } else { &ok };
                drop.extend(g.iter().copied().filter(|k| !keep.contains(k)));
                guess.extend(keep.iter().copied());
            }
        }
        let mut k = 0;
        v.retain_mut(|(_, c)| {
            let keep = !drop.contains(&k);
            if keep && guess.contains(&k) && *c != "name" {
                *c = "heuristic";
            }
            k += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_and_acceptance() {
        assert_eq!(param_types("Item get(String name)"), vec!["String"]);
        assert_eq!(param_types("Map<K, V> put(final Map<String, Integer> m, int... xs)"), vec!["Map", "int"]);
        assert_eq!(param_types("fun create(name: String, n: Int?)"), vec!["String", "Int"]);
        assert!(accepts("String", "String"));
        assert!(!accepts("Integer", "String"));
        assert!(accepts("Integer", "int"));
        assert!(accepts("long", "int"));
        assert!(!accepts("Long", "int"));
        assert!(!accepts("Owner", "String"));
        assert!(accepts("Owner", "Pet"));
        assert!(accepts("Object", "String"));
        assert!(accepts("T", "int"));
        assert_eq!(call_args("  void a(Box b) { b.get(\"x\", f(1, 2)); }", "get"), Some(vec!["\"x\"".into(), "f(1, 2)".into()]));
        assert_eq!(arg_type("id", &["void a(Integer id) {", "  b.get(id);"]), "Integer");
        assert_eq!(arg_type("7", &[]), "int");
        assert_eq!(arg_type("x.y()", &[]), "");
    }
}
