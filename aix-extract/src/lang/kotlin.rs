//! Kotlin (1.9 / 2.x: data / sealed / value classes, objects, companions, extension and suspend functions, context
//! parameters) on tree-sitter-kotlin-ng. Constructor `val` / `var` parameters are fields; a capitalised bare call is a
//! constructor call; `x.f()` is typed from parameters, properties, `val x = Foo()` and `val x: Foo`.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Kotlin;

fn mods<'t>(n: Node<'t>) -> Option<Node<'t>> {
    kid(n, &["modifiers"])
}

fn vis(n: Node, src: &str, default: &str) -> String {
    let Some(m) = mods(n) else { return default.into() };
    for c in named_children(m) {
        if c.kind() == "visibility_modifier" {
            return match text(c, src) {
                "private" => "private",
                "protected" => "protected",
                "internal" => "package",
                _ => "public",
            }
            .into();
        }
    }
    default.into()
}

fn annos(n: Node, src: &str) -> Vec<String> {
    let Some(m) = mods(n) else { return vec![] };
    named_children(m)
        .into_iter()
        .filter(|c| c.kind() == "annotation")
        .map(|c| squash(text(c, src).trim_start_matches('@')))
        .collect()
}

fn has_mod(n: Node, src: &str, w: &str) -> bool {
    mods(n).is_some_and(|m| named_children(m).iter().any(|c| text(*c, src) == w))
}

/// Type node of a declaration (the child that is a `*_type`), skipping the receiver type of an extension function.
fn type_text(n: Node, src: &str) -> String {
    named_children(n)
        .into_iter()
        .find(|c| matches!(c.kind(), "user_type" | "nullable_type" | "function_type" | "parenthesized_type"))
        .map(|c| text(c, src).to_string())
        .unwrap_or_default()
}

fn ident_of<'a>(n: Node, src: &'a str) -> &'a str {
    kid(n, &["identifier"]).map(|c| text(c, src)).unwrap_or("")
}

fn params(list: Option<Node>, src: &str) -> Vec<(String, String)> {
    let Some(l) = list else { return vec![] };
    named_children(l)
        .into_iter()
        .filter(|p| p.kind() == "parameter")
        .map(|p| (ident_of(p, src).to_string(), type_text(p, src)))
        .collect()
}

impl Lang for Kotlin {
    fn language(&self) -> Language {
        tree_sitter_kotlin_ng::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "kotlin"
    }
    /// tree-sitter-kotlin-ng does not know `fun interface` (Kotlin 1.4): blank the `fun` so the rest of the file parses.
    /// It also needs a terminator before the `}` of a one-line class body (`class A { fun x() {} }` otherwise turns
    /// the whole file into one ERROR): the blank before that `}` becomes `;` (same length, same lines).
    fn preprocess(&self, text: &str) -> Option<String> {
        static ONE: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new(r"(?m)^(.*\b(?:class|object|interface)\b[^\n]*\{[^\n]*[^\s{;])[ \t]\}[ \t]*$").unwrap());
        let mut out: Option<String> = None;
        if text.contains("fun interface") {
            let re = regex::Regex::new(r"\bfun(\s+)interface\b").unwrap();
            out = Some(re.replace_all(text, |c: &regex::Captures| format!("   {}interface", &c[1])).into_owned());
        }
        let cur = out.as_deref().unwrap_or(text);
        if ONE.is_match(cur) {
            let fixed = ONE.replace_all(cur, |c: &regex::Captures| {
                let whole = c.get(0).unwrap().as_str();
                let head = c.get(1).unwrap().as_str();
                format!("{head};{}", &whole[head.len() + 1..])
            });
            out = Some(fixed.into_owned());
        }
        out
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "class_declaration" | "object_declaration" => {
                let name = fld_text(n, "name", src);
                let is_iface = children(n).iter().any(|c| c.kind() == "interface");
                let kind = if n.kind() == "object_declaration" {
                    "class"
                } else if is_iface {
                    "interface"
                } else if has_mod(n, src, "enum") {
                    "enum"
                } else if has_mod(n, src, "data") || has_mod(n, src, "value") {
                    "record"
                } else {
                    "class"
                };
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.vis = vis(n, src, "public");
                d.annos = annos(n, src);
                let ctor = kid(n, &["primary_constructor"]);
                d.sig = format!(
                    "{} {name}{}",
                    kind,
                    ctor.map(|c| squash(text(c, src))).unwrap_or_default()
                );
                if let Some(ds) = kid(n, &["delegation_specifiers"]) {
                    for s in named_children(ds) {
                        let t = simple_type(text(s, src).split('(').next().unwrap_or(""));
                        let t = if t.is_empty() { simple_type(text(s, src)) } else { t };
                        if !t.is_empty() {
                            d.supers.push(t);
                        }
                    }
                }
                d.walk = children(n).into_iter().filter(|c| matches!(c.kind(), "class_body" | "enum_class_body")).collect();
                let mut out = vec![];
                // `class C(val a: A)`: constructor properties are fields
                if let Some(c) = ctor {
                    if let Some(ps) = kid(c, &["class_parameters"]) {
                        for p in named_children(ps).into_iter().filter(|p| p.kind() == "class_parameter") {
                            if children(p).iter().any(|k| matches!(k.kind(), "val" | "var")) || text(p, src).contains("val ") || text(p, src).contains("var ") {
                                let mut f = Decl::new(Role::Field, ident_of(p, src), "field", p);
                                f.container = Some(name.to_string());
                                f.vis = vis(p, src, "public");
                                f.ret = simple_type(&type_text(p, src));
                                f.sig = squash(text(p, src));
                                out.push(f);
                            }
                        }
                    }
                }
                out.insert(0, d);
                out
            }
            "companion_object" => {
                let mut d = Decl::new(Role::Wrapper, "", "class", n);
                d.walk = kid(n, &["class_body"]).into_iter().collect();
                vec![d]
            }
            "secondary_constructor" => {
                let mut d = Decl::new(Role::Func, "constructor", "ctor", n);
                d.vis = vis(n, src, "public");
                let body = kid(n, &["block", "function_body"]);
                d.sig = header(n, body, src);
                d.params = params(kid(n, &["function_value_parameters"]), src);
                d.walk = body.into_iter().collect();
                // named after its class by the caller: the engine's container is the class
                vec![d]
            }
            "function_declaration" => {
                let mut name = fld_text(n, "name", src);
                // `fun String.ext()` after an expression-bodied function can parse as a qualified type with a missing name
                if name.is_empty() {
                    if let Some(u) = kid(n, &["user_type"]) {
                        let ids: Vec<Node> = named_children(u).into_iter().filter(|c| c.kind() == "identifier").collect();
                        if ids.len() >= 2 {
                            name = text(*ids.last().unwrap(), src);
                        }
                    }
                }
                let body = kid(n, &["function_body"]);
                let mut d = Decl::new(Role::Func, name, "function", n);
                d.vis = vis(n, src, "public");
                d.annos = annos(n, src);
                let pl = kid(n, &["function_value_parameters"]);
                d.sig = format!("fun {name}{}", pl.map(|p| squash(text(p, src))).unwrap_or_default());
                d.params = params(pl, src);
                // result type: the type child after the parameter list
                if let Some(p) = pl {
                    d.ret = named_children(n)
                        .into_iter()
                        .filter(|c| c.start_byte() > p.end_byte() && matches!(c.kind(), "user_type" | "nullable_type"))
                        .map(|c| simple_type(text(c, src)))
                        .next()
                        .unwrap_or_default();
                }
                d.walk = body.into_iter().chain(pl).collect();
                vec![d]
            }
            "property_declaration" => {
                let top = n.parent().is_some_and(|p| matches!(p.kind(), "class_body" | "source_file" | "enum_class_body"));
                if !top {
                    return vec![];
                }
                let Some(v) = kid(n, &["variable_declaration"]) else { return vec![] };
                let name = ident_of(v, src);
                let is_member = n.parent().is_some_and(|p| p.kind() != "source_file");
                let mut d = Decl::new(Role::Field, name, if is_member { "field" } else { "const" }, n);
                d.vis = vis(n, src, "public");
                d.annos = annos(n, src);
                let declared = type_text(v, src);
                d.ret = if !declared.is_empty() {
                    simple_type(&declared)
                } else {
                    named_children(n).into_iter().find(|c| !matches!(c.kind(), "modifiers" | "variable_declaration")).map(|e| self.init_type(e, src)).unwrap_or_default()
                };
                d.sig = squash(text(n, src)).chars().take(120).collect();
                vec![d]
            }
            "enum_entry" => {
                let mut d = Decl::new(Role::Field, ident_of(n, src), "const", n);
                d.sig = squash(text(n, src)).chars().take(80).collect();
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        match n.kind() {
            "callable_reference" => {
                let ids: Vec<Node> = named_children(n).into_iter().filter(|c| c.kind() == "identifier" || c.kind() == "user_type").collect();
                let callee = ids.last().map(|c| text(*c, src).to_string())?;
                let recv = if ids.len() > 1 { ids.first().copied() } else { None };
                Some(Call { callee, recv, static_type: None, kind: "ref", argc: -1, args: vec![] })
            }
            "call_expression" => {
                let f = n.named_child(0)?;
                let va = kid(n, &["value_arguments"]);
                let lambda = kid(n, &["annotated_lambda"]).is_some() as i32;
                let args = arg_nodes(va);
                let count = args.len() as i32 + lambda;
                let (callee, recv, kind) = match f.kind() {
                    "identifier" => {
                        let c = text(f, src);
                        (c.to_string(), None, if c.chars().next().is_some_and(|x| x.is_uppercase()) { "new" } else { "call" })
                    }
                    "navigation_expression" => {
                        let ids = named_children(f);
                        let last = ids.last().filter(|l| l.kind() == "identifier")?;
                        (text(*last, src).to_string(), ids.first().copied(), "call")
                    }
                    _ => return None,
                };
                Some(Call { callee, recv, static_type: None, kind, argc: count, args })
            }
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "import" {
            return vec![];
        }
        let full = kid(n, &["qualified_identifier"]).map(|q| text(q, src)).unwrap_or("");
        if full.is_empty() {
            return vec![];
        }
        let wildcard = text(n, src).trim_end().ends_with(".*");
        let alias = kid(n, &["identifier"]).map(|a| text(a, src).to_string());
        if wildcard {
            return vec![ImportRow { line: line(n), callee: "*".into(), module: full.to_string(), local: "*".into() }];
        }
        let (m, name) = full.rsplit_once('.').unwrap_or(("", full));
        vec![ImportRow { line: line(n), callee: name.to_string(), module: m.to_string(), local: alias.unwrap_or(name.to_string()) }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() != "property_declaration" {
            return vec![];
        }
        let Some(v) = kid(n, &["variable_declaration"]) else { return vec![] };
        let name = ident_of(v, src).to_string();
        let declared = type_text(v, src);
        if !declared.is_empty() {
            return vec![(name, TypeSrc::Declared(declared))];
        }
        match named_children(n).into_iter().find(|c| !matches!(c.kind(), "modifiers" | "variable_declaration" | "type_constraints")) {
            Some(e) => vec![(name, TypeSrc::Init(e))],
            None => vec![],
        }
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "this_expression" => Expr::This,
            "navigation_expression" => {
                let k = named_children(n);
                match (k.first(), k.last()) {
                    (Some(o), Some(f)) if f.kind() == "identifier" && k.len() >= 2 => Expr::Member(*o, text(*f, src).to_string()),
                    _ => Expr::Other,
                }
            }
            "value_argument" => n.named_child(n.named_child_count().saturating_sub(1) as u32).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            "parenthesized_expression" | "postfix_expression" | "as_expression" => n.named_child(0).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        if n.kind() == "call_expression" {
            if let Some(f) = n.named_child(0) {
                if f.kind() == "identifier" {
                    let c = text(f, src);
                    if c.chars().next().is_some_and(|x| x.is_uppercase()) {
                        return simple_type(c);
                    }
                }
            }
        }
        String::new()
    }
}
