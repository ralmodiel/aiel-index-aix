//! The shared walker behind every tree-sitter language in [`super`]: declarations become `Member`s, calls become
//! `Ref`s whose receiver type comes from what the file itself says (`this`, a typed parameter or field, a local
//! initialised with a constructor, a class name, an import alias), and functions used as values become `ref`s.

use std::collections::HashMap;

use tree_sitter::Node;

use super::*;
use crate::codegraph::{Member, Ref};
use crate::ts_util::*;

#[derive(Clone, Default)]
struct Cx {
    container: Option<String>,
    /// Qualified-name prefix of the enclosing types (`Outer.Inner`).
    qprefix: String,
    this_type: Option<String>,
    this_vars: Vec<String>,
    /// (qname, declaration line) of the enclosing member.
    caller: Option<(String, u32)>,
    scope: HashMap<String, String>,
    /// Every parameter / local name in scope, typed or not (a bare name handed to a macro is a variable, not a fn).
    names: std::collections::HashSet<String>,
}

struct St<'a> {
    lang: &'a dyn Lang,
    f: &'a SourceFile,
    src: &'a str,
    fields: HashMap<(String, String), String>,
    imports: HashMap<String, String>,
    extra_supers: Vec<(String, Vec<String>)>,
    /// Types named by an explicit container (Go receivers, Lua tables): a bare use of the name is that type.
    containers: std::collections::HashSet<String>,
}

pub fn run(lang: &dyn Lang, f: &SourceFile, rows: &mut Rows) {
    let pre = lang.preprocess(&f.text);
    let text: &str = pre.as_deref().unwrap_or(&f.text);
    let Some(tree) = parse(&lang.language(), text) else { return };
    let mut st = St { lang, f, src: text, fields: HashMap::new(), imports: HashMap::new(), extra_supers: vec![], containers: Default::default() };
    let root = tree.root_node();
    walk(root, |x| {
        for im in lang.imports(x, text) {
            if im.local != "*" && !im.local.is_empty() {
                st.imports.insert(im.local, im.module);
            }
        }
        true
    });
    st.prepass(root, &Cx::default());
    let first = rows.members.len();
    let first_ref = rows.refs.len();
    st.visit(root, &mut Cx::default(), rows);
    if lang.synthesize_containers() {
        let have: std::collections::HashSet<String> =
            rows.members[first..].iter().filter(|m| matches!(m.kind.as_str(), "class" | "interface" | "enum" | "record")).map(|m| m.name.clone()).collect();
        let mut spans: std::collections::BTreeMap<String, (u32, u32)> = Default::default();
        for m in rows.members[first..].iter() {
            if let Some(c) = &m.container {
                if !have.contains(c) {
                    let e = spans.entry(c.clone()).or_insert((m.line, m.end_line));
                    e.0 = e.0.min(m.line);
                    e.1 = e.1.max(m.end_line);
                }
            }
        }
        for (name, (a, b)) in spans {
            rows.members.push(Member {
                file: f.path.clone(),
                line: a,
                end_line: b,
                name: name.clone(),
                container: None,
                qname: name.clone(),
                kind: "class".into(),
                sig: format!("table {name}"),
                vis: "public".into(),
                annos: vec![],
                is_static: false,
                supers: vec![],
                ret: String::new(),
            });
        }
    }
    // a function used as a value is only an edge when it names a function of this file (Go: this package, so any exported name)
    let fns: std::collections::HashSet<String> = rows.members[first..]
        .iter()
        .filter(|m| m.container.is_none() && m.kind == "function")
        .map(|m| m.name.clone())
        .collect();
    let go = lang.tag() == "go";
    let mut i = first_ref;
    while i < rows.refs.len() {
        let r = &rows.refs[i];
        if r.kind == "ref" && r.recv.is_empty() && !fns.contains(&r.callee) && !(go && caps(&r.callee)) {
            rows.refs.swap_remove(i);
        } else {
            i += 1;
        }
    }
    for (ty, sup) in std::mem::take(&mut st.extra_supers) {
        if let Some(m) = rows.members[first..].iter_mut().find(|m| m.name == ty && matches!(m.kind.as_str(), "class" | "enum" | "record")) {
            for s in sup {
                if !m.supers.contains(&s) {
                    m.supers.push(s);
                }
            }
        }
    }
}

const BUILTIN: &[&str] = &[
    "int", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "bool", "char",
    "str", "string", "String", "Int", "Long", "Short", "Byte", "Double", "Float", "Boolean", "Char", "Unit", "Any", "Nothing",
    "void", "object", "byte", "rune", "error", "float", "float32", "float64", "int8", "int16", "int32", "uint", "uint8",
    "uint16", "uint32", "uint64", "uintptr", "double", "long", "short", "any", "var", "dynamic", "mixed", "self", "Self", "this",
    "array", "callable", "iterable", "null", "never", "Object", "Integer", "Void", "nil", "number",
];

const WRAPPERS: &[&str] = &[
    "Arc", "Box", "Rc", "Option", "Mutex", "RwLock", "RefCell", "Cell", "Cow", "Pin", "Lazy", "OnceCell", "Optional", "Lazy",
    "Task", "ValueTask", "Nullable", "Maybe", "lateinit", "Result", "Future", "Deferred", "Lock",
];

/// `&mut Arc<store::Db>` / `Db?` / `*pkg.Db` / `[]Db` / `\App\Db` -> `Db`; "" for builtins and unknowns.
pub fn simple_type(t: &str) -> String {
    let mut t = t.trim();
    loop {
        let before = t;
        for p in ["&mut ", "&", "*", "mut ", "dyn ", "impl ", "const ", "readonly ", "?", "[]", "...", "ref ", "out ", "in ", "final ", "static ", "lateinit "] {
            if let Some(r) = t.strip_prefix(p) {
                t = r.trim_start();
            }
        }
        t = t.trim_end_matches(['?', '!', '*', '&']).trim();
        if t == before {
            break;
        }
    }
    if t.starts_with("func(") || t.starts_with("fn(") || t.starts_with("map[") || t.starts_with("chan ") || t.starts_with("struct{") || t.starts_with("interface{") || t.starts_with("(") {
        return String::new();
    }
    // Rust lifetimes `&'a T`
    if let Some(r) = t.strip_prefix('\'') {
        t = r.split_once(char::is_whitespace).map(|x| x.1.trim()).unwrap_or("");
    }
    // generics: wrapper types give their first argument, everything else loses its arguments
    let (head, args) = match t.find(['<', '[']) {
        Some(i) if i > 0 && (t.as_bytes()[i] == b'<' || t.ends_with(']')) => (&t[..i], Some(&t[i + 1..])),
        _ => (t, None),
    };
    let head_simple = head.rsplit(['.', ':', '\\']).next().unwrap_or("");
    if let Some(a) = args {
        if WRAPPERS.contains(&head_simple) {
            let inner = a.trim_end_matches(['>', ']']);
            let mut depth = 0;
            let mut end = inner.len();
            for (i, c) in inner.char_indices() {
                match c {
                    '<' | '[' | '(' => depth += 1,
                    '>' | ']' | ')' => depth -= 1,
                    ',' if depth == 0 => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
            }
            return simple_type(&inner[..end]);
        }
    }
    let h = head_simple.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_'));
    if h.is_empty() || BUILTIN.contains(&h) || !h.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') {
        return String::new();
    }
    h.to_string()
}

fn caps(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_uppercase())
}

impl<'a> St<'a> {
    /// Simple type name of a declared type; Go types qualified by an import alias (`store.DB`) become `mod:<path>#DB`.
    fn typed(&self, raw: &str) -> String {
        if raw.starts_with("ret:") || raw.starts_with("mod:") || raw == "Self" {
            return raw.to_string();
        }
        if self.lang.tag() == "go" {
            let t = raw.trim_start_matches(['*', '&', '[', ']']).trim_start_matches("...");
            if let Some((alias, rest)) = t.split_once('.') {
                if let Some(path) = self.imports.get(alias) {
                    let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() {
                        return format!("mod:{path}#{name}");
                    }
                }
            }
        }
        simple_type(raw)
    }

    fn txt(&self, n: Node) -> &'a str {
        text(n, self.src)
    }

    fn prepass(&mut self, n: Node, cx: &Cx) {
        let ds = self.lang.decls(n, self.src);
        if ds.is_empty() {
            for c in children(n) {
                self.prepass(c, cx);
            }
            return;
        }
        for d in ds {
            match d.role {
                Role::Type | Role::Wrapper => {
                    let cn = d.container.clone().unwrap_or_else(|| d.name.clone());
                    let cx2 = Cx { container: Some(cn), ..Cx::default() };
                    let kids = if d.walk.is_empty() { children(d.node) } else { d.walk };
                    for c in kids {
                        self.prepass(c, &cx2);
                    }
                }
                Role::Field => {
                    let c = d.container.clone().or_else(|| cx.container.clone());
                    let ty = if d.ty_raw.is_empty() { d.ret.clone() } else { self.typed(&d.ty_raw) };
                    if let (Some(c), false) = (c, ty.is_empty()) {
                        self.fields.insert((c, d.name.clone()), ty);
                    }
                }
                Role::Func => {
                    if let Some(c) = &d.container {
                        self.containers.insert(c.clone());
                    }
                    // untyped languages (Ruby): `@repo = Repo.new` types the field
                    if let Some(c) = d.container.clone().or_else(|| cx.container.clone()) {
                        let lang = self.lang;
                        let src = self.src;
                        let mut found = vec![];
                        let kids = if d.walk.is_empty() { children(d.node) } else { d.walk.clone() };
                        for b in &kids {
                            walk(*b, |x| {
                                for (nm, ts) in lang.locals(x, src) {
                                    if nm.starts_with('@') {
                                        let t = match ts {
                                            TypeSrc::Declared(t) => simple_type(&t),
                                            TypeSrc::Init(e) => lang.init_type(e, src),
                                        };
                                        if !t.is_empty() {
                                            found.push((nm, t));
                                        }
                                    }
                                }
                                true
                            });
                        }
                        for (nm, t) in found {
                            self.fields.entry((c.clone(), nm)).or_insert(t);
                        }
                    }
                }
            }
        }
    }

    fn visit(&mut self, n: Node, cx: &mut Cx, rows: &mut Rows) {
        let ds = self.lang.decls(n, self.src);
        if !ds.is_empty() {
            for d in ds {
                self.decl(d, cx, rows);
            }
            return;
        }
        for im in self.lang.imports(n, self.src) {
            self.import(im, rows);
        }
        for (name, ts) in self.lang.locals(n, self.src) {
            let ty = match ts {
                TypeSrc::Declared(t) => self.typed(&t),
                TypeSrc::Init(e) => self.typed(&self.lang.init_type(e, self.src)),
            };
            let ty = if ty == "Self" { cx.this_type.clone().unwrap_or_default() } else { ty };
            cx.names.insert(name.clone());
            if !ty.is_empty() {
                cx.scope.insert(name, ty);
            } else {
                // a shadowing local of unknown type hides the outer binding
                cx.scope.remove(&name);
            }
        }
        if let Some(c) = self.lang.call(n, self.src) {
            self.call(c, n, cx, rows);
        }
        if let Some(ps) = self.lang.closure_params(n, self.src) {
            // the literal's parameters shadow outer names (a receiver `h`, a local) inside it only
            let mut cx2 = cx.clone();
            for (p, t) in &ps {
                let t = self.typed(t);
                cx2.names.insert(p.clone());
                cx2.this_vars.retain(|v| v != p);
                if t.is_empty() {
                    cx2.scope.remove(p);
                } else {
                    cx2.scope.insert(p.clone(), t);
                }
            }
            for c in children(n) {
                self.visit(c, &mut cx2, rows);
            }
            return;
        }
        for h in self.lang.hidden_calls(n, self.src) {
            if h.value && (cx.scope.contains_key(&h.callee) || cx.names.contains(&h.callee)) {
                continue; // a local variable / parameter handed to the macro, not a function
            }
            let rt = h.static_type.clone().unwrap_or_default();
            let (caller, cl) = cx.caller.clone().unwrap_or_default();
            rows.refs.push(Ref {
                file: self.f.path.clone(),
                line: h.line,
                caller,
                caller_line: cl,
                callee: h.callee,
                recv: trunc_recv(&h.recv),
                recv_type: rt.clone(),
                kind: if h.value { "ref" } else { "call" }.into(),
                conf: if rt.is_empty() { "name" } else { "exact" }.into(),
                argc: -1,
            });
        }
        for c in children(n) {
            self.visit(c, cx, rows);
        }
    }

    fn import(&mut self, im: ImportRow, rows: &mut Rows) {
        if im.local != "*" && !im.local.is_empty() {
            self.imports.insert(im.local.clone(), im.module.clone());
        }
        rows.refs.push(Ref {
            file: self.f.path.clone(),
            line: im.line,
            caller: String::new(),
            caller_line: 0,
            callee: im.callee,
            recv: im.module,
            recv_type: im.local,
            kind: "import".into(),
            conf: "exact".into(),
            argc: -1,
        });
    }

    fn decl(&mut self, d: Decl, cx: &mut Cx, rows: &mut Rows) {
        let container = d.container.clone().or_else(|| cx.container.clone());
        let qname = match (&d.container, cx.qprefix.is_empty()) {
            (Some(c), _) => format!("{c}.{}", d.name),
            (None, true) => d.name.clone(),
            (None, false) => format!("{}.{}", cx.qprefix, d.name),
        };
        let line0 = line(d.start);
        let is_wrapper = matches!(d.role, Role::Wrapper);
        // a transparent wrapper (`mod x {}`, `namespace X {}`, a Kotlin companion): what is inside stays in the enclosing type
        if is_wrapper && d.name.is_empty() {
            let kids = if d.walk.is_empty() { children(d.node) } else { d.walk };
            for c in kids {
                self.visit(c, cx, rows);
            }
            return;
        }
        let mut d = d;
        if d.ret == "Self" {
            d.ret = container.clone().unwrap_or_default();
        }
        if d.kind == "function" && container.is_some() {
            d.kind = "method";
        }
        let qname = if d.kind == "ctor" && (d.name == "constructor" || d.name == "init") && container.is_some() {
            d.name = container.clone().unwrap_or_default();
            format!("{}.{}", container.clone().unwrap_or_default(), d.name)
        } else {
            qname
        };
        if !is_wrapper && !d.hidden {
            rows.members.push(Member {
                file: self.f.path.clone(),
                line: line0,
                end_line: end_line(d.node).max(line0),
                name: d.name.clone(),
                container: container.clone(),
                qname: qname.clone(),
                kind: d.kind.into(),
                sig: trunc(&d.sig, 200),
                vis: d.vis.clone(),
                annos: d.annos.clone(),
                is_static: d.is_static,
                supers: d.supers.clone(),
                ret: d.ret.clone(),
            });
        } else if !d.supers.is_empty() {
            self.extra_supers.push((d.name.clone(), d.supers.clone()));
        }
        let mut kids = if d.walk.is_empty() && !matches!(d.role, Role::Field) { children(d.node) } else { d.walk };
        let mut seen = std::collections::HashSet::new();
        kids.retain(|k| seen.insert(k.id()));
        match d.role {
            Role::Type | Role::Wrapper => {
                let mut cx2 = Cx {
                    container: Some(d.name.clone()),
                    qprefix: if is_wrapper { d.name.clone() } else { qname },
                    this_type: Some(d.name.clone()),
                    ..Cx::default()
                };
                for c in kids {
                    self.visit(c, &mut cx2, rows);
                }
            }
            Role::Func => {
                let mut cx2 = cx.clone();
                cx2.container = container.clone();
                cx2.this_type = container.clone().or_else(|| cx.this_type.clone());
                cx2.caller = Some((qname, line0));
                if let Some(v) = &d.this_var {
                    cx2.this_vars.push(v.clone());
                    if let Some(c) = &container {
                        cx2.scope.insert(v.clone(), c.clone());
                    }
                }
                for (p, t) in &d.params {
                    let t = self.typed(t);
                    cx2.names.insert(p.clone());
                    if t.is_empty() {
                        cx2.scope.remove(p);
                    } else {
                        cx2.scope.insert(p.clone(), t);
                    }
                }
                for c in kids {
                    self.visit(c, &mut cx2, rows);
                }
            }
            Role::Field => {
                let mut cx2 = cx.clone();
                cx2.caller = Some((qname, line0));
                for c in kids {
                    self.visit(c, &mut cx2, rows);
                }
            }
        }
    }

    /// Type of an expression (class name, `mod:<path>#*` for an import alias, `ret:<fn>` for a call result), "" if unknown.
    fn type_of(&self, e: Node, cx: &Cx) -> String {
        match self.lang.expr(e, self.src) {
            Expr::This => cx.this_type.clone().unwrap_or_default(),
            Expr::Ident(name) => {
                if let Some(t) = cx.scope.get(&name) {
                    return t.clone();
                }
                if let Some(c) = &cx.this_type {
                    if let Some(t) = self.fields.get(&(c.clone(), name.clone())) {
                        return t.clone();
                    }
                }
                if let Some(m) = self.imports.get(&name) {
                    if self.lang.tag() == "go" {
                        return format!("mod:{m}#*");
                    }
                }
                if self.containers.contains(&name) || (self.lang.caps_are_types() && caps(&name)) {
                    return name;
                }
                String::new()
            }
            Expr::Member(obj, field) => {
                let t = self.type_of(obj, cx);
                if t.is_empty() || t.starts_with("ret:") || t.starts_with("mod:") {
                    // `pkg.Type` used as a receiver: a capitalised member of a package is a type
                    if t.starts_with("mod:") && self.lang.caps_are_types() && caps(&field) {
                        return field;
                    }
                    return String::new();
                }
                self.fields.get(&(t, field)).cloned().unwrap_or_default()
            }
            Expr::Other => {
                let t = self.typed(&self.lang.init_type(e, self.src));
                if !t.is_empty() {
                    return t;
                }
                // `make().f()`: the declared result type of the plain function `make` (the resolver looks it up)
                match self.lang.call(e, self.src) {
                    Some(c) if c.recv.is_none() && c.static_type.is_none() && c.kind == "call" && !c.callee.is_empty() => format!("ret:{}", c.callee),
                    _ => String::new(),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_ref(&self, rows: &mut Rows, n: Node, cx: &Cx, callee: &str, recv: &str, rt: String, kind: &str, conf: &str, argc: i32) {
        let (caller, cl) = cx.caller.clone().unwrap_or_default();
        rows.refs.push(Ref {
            file: self.f.path.clone(),
            line: line(n),
            caller,
            caller_line: cl,
            callee: callee.to_string(),
            recv: trunc_recv(recv),
            recv_type: rt,
            kind: kind.into(),
            conf: conf.into(),
            argc,
        });
    }

    fn call(&mut self, c: Call, n: Node, cx: &mut Cx, rows: &mut Rows) {
        if c.callee.is_empty() {
            return;
        }
        let (recv_text, rt) = match (&c.static_type, c.recv) {
            (Some(t), _) => (t.clone(), t.clone()),
            (None, Some(r)) => (self.txt(r).to_string(), self.type_of(r, cx)),
            (None, None) => (String::new(), String::new()),
        };
        let rt = if matches!(rt.as_str(), "Self" | "self" | "static") { cx.this_type.clone().unwrap_or_default() } else { rt };
        // `super.f()` (Kotlin, Swift, Dart, Scala; `super<T>.f()`), `base.F()` (C#), `parent::f()` (PHP): the parent's
        // method, never the override that makes the call (the resolver walks the class's supers from `super:<Cls>`)
        let parent_call = match self.lang.tag() {
            "csharp" => recv_text == "base",
            "php" => recv_text == "parent",
            "kotlin" | "swift" | "dart" | "scala" => recv_text == "super" || recv_text.starts_with("super<") || recv_text.starts_with("super["),
            _ => false,
        };
        let rt = match (&cx.this_type, parent_call) {
            (Some(c), true) => format!("super:{c}"),
            _ => rt,
        };
        let conf = if rt.is_empty() { "name" } else { "exact" };
        self.push_ref(rows, n, cx, &c.callee, &recv_text, rt, c.kind, conf, c.argc);
        // functions and methods passed as values
        for a in c.args {
            match self.lang.expr(a, self.src) {
                Expr::Ident(name) => {
                    if name.len() >= 3 && !cx.scope.contains_key(&name) {
                        self.push_ref(rows, a, cx, &name, "", String::new(), "ref", "name", -1);
                    }
                }
                Expr::Member(obj, field) => {
                    let t = self.type_of(obj, cx);
                    if !t.is_empty() && !t.starts_with("mod:") && !t.starts_with("ret:") {
                        let rtext = self.txt(obj).to_string();
                        self.push_ref(rows, a, cx, &field, &rtext, t, "ref", "exact", -1);
                    }
                }
                _ => {}
            }
        }
    }
}

fn trunc_recv(s: &str) -> String {
    let s = squash(s);
    if s.chars().count() > 80 {
        s.chars().take(80).collect()
    } else {
        s
    }
}

fn trunc(s: &str, n: usize) -> String {
    let s = squash(s);
    if s.chars().count() <= n {
        s
    } else {
        let mut o: String = s.chars().take(n).collect();
        o.push('…');
        o
    }
}

/// Header text of a declaration: from its first token to where the body starts.
pub fn header(n: Node, body: Option<Node>, src: &str) -> String {
    let end = body.map(|b| b.start_byte()).unwrap_or_else(|| n.end_byte()).max(n.start_byte());
    squash(src[n.start_byte()..end].trim_end_matches(['{', ';', ':', '=', ' ', '\n']))
}

/// Child by field name.
pub fn fld<'t>(n: Node<'t>, name: &str) -> Option<Node<'t>> {
    n.child_by_field_name(name)
}

/// Text of the child with this field name.
pub fn fld_text<'a>(n: Node, name: &str, src: &'a str) -> &'a str {
    n.child_by_field_name(name).map(|c| text(c, src)).unwrap_or("")
}

/// All children carrying this field name.
pub fn flds<'t>(n: Node<'t>, name: &str) -> Vec<Node<'t>> {
    let mut c = n.walk();
    n.children_by_field_name(name, &mut c).collect()
}

/// First child of one of these kinds.
pub fn kid<'t>(n: Node<'t>, kinds: &[&str]) -> Option<Node<'t>> {
    let mut c = n.walk();
    let r = n.children(&mut c).find(|k| kinds.contains(&k.kind()));
    r
}

/// Argument count of an argument-list node (named children, comments skipped); -1 when a spread makes it unknown.
pub fn argc(args: Option<Node>, src: &str) -> i32 {
    let Some(a) = args else { return 0 };
    let t = text(a, src);
    if t.contains("...") || t.contains("*args") {
        return -1;
    }
    named_children(a).into_iter().filter(|c| !c.kind().contains("comment")).count() as i32
}

/// Named children of an argument-list node.
pub fn arg_nodes<'t>(args: Option<Node<'t>>) -> Vec<Node<'t>> {
    args.map(|a| named_children(a).into_iter().filter(|c| !c.kind().contains("comment")).collect()).unwrap_or_default()
}
