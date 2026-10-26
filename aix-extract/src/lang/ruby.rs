//! Ruby (2.7 - 3.4: endless methods, pattern matching, argument forwarding, `Data.define`, numbered / `it` block
//! params) on tree-sitter-ruby. Modules and classes are types; `attr_*` declares fields; `private` sections set
//! visibility; `Foo.new` is a constructor call; instance variables are typed from `@x = Foo.new` / `@x = param`.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Ruby;

fn last_const(s: &str) -> String {
    s.rsplit("::").next().unwrap_or(s).to_string()
}

/// private / protected / public in effect for a method: a bare `private` above it in the body, or `private def x`.
fn vis(n: Node, src: &str) -> String {
    if let Some(p) = n.parent() {
        if p.kind() == "argument_list" {
            if let Some(c) = p.parent() {
                if let Some(m) = fld(c, "method") {
                    if matches!(text(m, src), "private" | "protected") {
                        return text(m, src).to_string();
                    }
                }
            }
        }
    }
    let mut s = n.prev_sibling();
    while let Some(x) = s {
        if x.kind() == "identifier" {
            match text(x, src) {
                "private" => return "private".into(),
                "protected" => return "protected".into(),
                "public" => return "public".into(),
                _ => {}
            }
        }
        if x.kind() == "class" || x.kind() == "module" {
            break;
        }
        s = x.prev_sibling();
    }
    "public".into()
}

fn param_names(list: Option<Node>, src: &str) -> Vec<(String, String)> {
    let Some(l) = list else { return vec![] };
    named_children(l)
        .into_iter()
        .filter_map(|p| {
            let nm = match p.kind() {
                "identifier" => text(p, src).to_string(),
                _ => fld(p, "name").map(|x| text(x, src).to_string())?,
            };
            Some((nm, String::new()))
        })
        .collect()
}

fn sig(n: Node, name: &str, src: &str) -> String {
    let p = fld(n, "parameters").map(|p| squash(text(p, src))).unwrap_or_default();
    let p = if p.is_empty() { "()".to_string() } else if p.starts_with('(') { p } else { format!("({p})") };
    format!("def {name}{p}")
}

impl Lang for Ruby {
    fn language(&self) -> Language {
        tree_sitter_ruby::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "ruby"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "class" | "module" => {
                let name = last_const(fld_text(n, "name", src));
                let mut d = Decl::new(Role::Type, name.clone(), if n.kind() == "module" { "interface" } else { "class" }, n);
                d.sig = format!("{} {name}", n.kind());
                if let Some(s) = fld(n, "superclass") {
                    let t = s.named_child(0).map(|c| last_const(text(c, src))).unwrap_or_default();
                    if !t.is_empty() {
                        d.supers.push(t);
                    }
                }
                d.walk = fld(n, "body").map(named_children).unwrap_or_default();
                // include / extend / prepend M
                for c in &d.walk {
                    if c.kind() == "call" && fld(*c, "receiver").is_none() && matches!(fld_text(*c, "method", src), "include" | "extend" | "prepend") {
                        for a in arg_nodes(fld(*c, "arguments")) {
                            if matches!(a.kind(), "constant" | "scope_resolution") {
                                d.supers.push(last_const(text(a, src)));
                            }
                        }
                    }
                }
                vec![d]
            }
            "method" | "singleton_method" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Func, name, if name == "initialize" { "ctor" } else { "function" }, n);
                d.vis = if name == "initialize" { "public".into() } else { vis(n, src) };
                d.is_static = n.kind() == "singleton_method";
                d.sig = sig(n, name, src);
                d.params = param_names(fld(n, "parameters"), src);
                d.walk = fld(n, "body").into_iter().chain(fld(n, "parameters")).collect();
                vec![d]
            }
            "call" if fld(n, "receiver").is_none() => {
                let m = fld_text(n, "method", src);
                // ActiveRecord `belongs_to :rubygem` / `has_one :owner, class_name: "User"`: the reader returns that
                // model, so `rubygem.touch` in a callback or method is a call on Rubygem (typing only, no member row)
                if matches!(m, "belongs_to" | "has_one") {
                    let args = arg_nodes(fld(n, "arguments"));
                    let Some(a) = args.first().filter(|a| a.kind() == "simple_symbol") else { return vec![] };
                    let name = text(*a, src).trim_start_matches(':');
                    let explicit = args.iter().filter(|x| x.kind() == "pair").find_map(|p| {
                        let k = fld(*p, "key").map(|k| text(k, src).trim_end_matches(':').trim_start_matches(':').to_string()).unwrap_or_default();
                        (k == "class_name").then(|| fld(*p, "value").map(|v| last_const(text(v, src).trim_matches(['"', '\'']))).unwrap_or_default())
                    });
                    if args.iter().any(|x| x.kind() == "pair" && text(*x, src).contains("polymorphic")) {
                        return vec![];
                    }
                    let ty = explicit.unwrap_or_else(|| name.split('_').map(|w| { let mut c = w.chars(); c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default() }).collect());
                    let mut d = Decl::new(Role::Field, name, "field", n);
                    d.ret = ty;
                    d.hidden = true;
                    return vec![d];
                }
                if !matches!(m, "attr_reader" | "attr_writer" | "attr_accessor") {
                    return vec![];
                }
                arg_nodes(fld(n, "arguments"))
                    .into_iter()
                    .filter(|a| a.kind() == "simple_symbol")
                    .map(|a| {
                        let mut d = Decl::new(Role::Field, text(a, src).trim_start_matches(':'), "field", n);
                        d.sig = format!("{m} {}", text(a, src));
                        d
                    })
                    .collect()
            }
            "assignment" => {
                // CONSTANT = ...
                let l = fld(n, "left");
                if let Some(l) = l.filter(|l| l.kind() == "constant") {
                    let mut d = Decl::new(Role::Field, text(l, src), "const", n);
                    d.sig = squash(text(n, src)).chars().take(100).collect();
                    d.walk = fld(n, "right").into_iter().collect();
                    return vec![d];
                }
                vec![]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "call" {
            return None;
        }
        let m = fld(n, "method")?;
        let callee = text(m, src).to_string();
        let args = fld(n, "arguments");
        let a = arg_nodes(args);
        let argc = if a.iter().any(|x| x.kind() == "splat_argument" || x.kind() == "hash_splat_argument") { -1 } else { a.len() as i32 };
        let recv = fld(n, "receiver");
        match recv {
            None => {
                if callee == "new" || matches!(
                    callee.as_str(),
                    "require" | "require_relative" | "load" | "include" | "extend" | "prepend" | "attr_reader" | "attr_writer" | "attr_accessor"
                        | "private" | "protected" | "public" | "raise" | "puts" | "p" | "print" | "private_constant" | "module_function" | "autoload"
                ) {
                    return None;
                }
                Some(Call { callee, recv: None, static_type: None, kind: "call", argc, args: a })
            }
            Some(r) if callee == "new" && matches!(r.kind(), "constant" | "scope_resolution") => {
                Some(Call { callee: last_const(text(r, src)), recv: None, static_type: None, kind: "new", argc, args: a })
            }
            Some(r) => {
                if matches!(r.kind(), "constant" | "scope_resolution") {
                    return Some(Call { callee, recv: None, static_type: Some(last_const(text(r, src))), kind: "call", argc, args: a });
                }
                Some(Call { callee, recv: Some(r), static_type: None, kind: "call", argc, args: a })
            }
        }
    }

    /// A bare word (`prepare`) is a call when the enclosing class / module defines a method of that name and no local
    /// variable or parameter of the enclosing method shadows it.
    fn hidden_calls(&self, n: Node, src: &str) -> Vec<HiddenCall> {
        if n.kind() == "call" {
            return callback_uses(n, src);
        }
        if n.kind() != "identifier" {
            return vec![];
        }
        let name = text(n, src);
        let Some(p) = n.parent() else { return vec![] };
        let field_of_parent = |f: &str| fld(p, f).is_some_and(|x| x.id() == n.id());
        match p.kind() {
            "call" if field_of_parent("method") => return vec![],
            "method" | "singleton_method" if field_of_parent("name") => return vec![],
            "assignment" | "operator_assignment" if field_of_parent("left") => return vec![],
            "method_parameters" | "block_parameters" | "lambda_parameters" | "parameters" | "optional_parameter" | "keyword_parameter" | "splat_parameter"
            | "hash_splat_parameter" | "block_parameter" | "destructured_parameter" | "left_assignment_list" | "pair" | "for" | "rest_assignment"
            | "exception_variable" | "alias" | "undef" | "symbol_array" | "string_array" | "mlhs" => return vec![],
            _ => {}
        }
        // enclosing method and class
        let (mut meth, mut class) = (None, None);
        let mut cur = p;
        loop {
            match cur.kind() {
                "method" | "singleton_method" if meth.is_none() => meth = Some(cur),
                "class" | "module" => {
                    class = Some(cur);
                    break;
                }
                _ => {}
            }
            match cur.parent() {
                Some(x) => cur = x,
                None => break,
            }
        }
        let (Some(meth), Some(class)) = (meth, class) else { return vec![] };
        // a local (assigned or a parameter) of the enclosing method hides the method
        let mut local = false;
        walk(meth, |x| {
            if local {
                return false;
            }
            let hit = match x.kind() {
                "assignment" | "operator_assignment" => fld(x, "left").is_some_and(|l| l.kind() == "identifier" && text(l, src) == name),
                "identifier" => {
                    x.id() != n.id()
                        && text(x, src) == name
                        && x.parent().is_some_and(|q| {
                            matches!(q.kind(), "method_parameters" | "block_parameters" | "lambda_parameters" | "parameters" | "left_assignment_list" | "exception_variable" | "for")
                                || (matches!(q.kind(), "optional_parameter" | "keyword_parameter" | "splat_parameter" | "hash_splat_parameter" | "block_parameter") && fld(q, "name").is_some_and(|nm| nm.id() == x.id()))
                        })
                }
                _ => false,
            };
            if hit {
                local = true;
            }
            true
        });
        if local {
            return vec![];
        }
        let defined = fld(class, "body").map(named_children).unwrap_or_default().into_iter().any(|c| {
            matches!(c.kind(), "method" | "singleton_method") && fld_text(c, "name", src) == name
                || (c.kind() == "call" && matches!(fld_text(c, "method", src), "attr_reader" | "attr_accessor") && text(c, src).contains(&format!(":{name}")))
        });
        if !defined {
            return vec![];
        }
        let cname = last_const(fld_text(class, "name", src));
        vec![HiddenCall { line: line(n), callee: name.to_string(), recv: cname.clone(), static_type: Some(cname), value: false }]
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "call" || fld(n, "receiver").is_some() {
            return vec![];
        }
        if !matches!(fld_text(n, "method", src), "require" | "require_relative" | "load" | "autoload") {
            return vec![];
        }
        let Some(s) = arg_nodes(fld(n, "arguments")).into_iter().find(|a| a.kind() == "string") else { return vec![] };
        let path = text(s, src).trim_matches(['"', '\'']).to_string();
        let last = path.rsplit('/').next().unwrap_or("").to_string();
        vec![ImportRow { line: line(n), callee: "*".into(), module: path, local: last }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() != "assignment" {
            return vec![];
        }
        let (Some(l), Some(r)) = (fld(n, "left"), fld(n, "right")) else { return vec![] };
        if matches!(l.kind(), "identifier" | "instance_variable") {
            return vec![(text(l, src).to_string(), TypeSrc::Init(r))];
        }
        vec![]
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" | "instance_variable" => Expr::Ident(text(n, src).to_string()),
            "constant" => Expr::Ident(text(n, src).to_string()),
            "scope_resolution" => Expr::Ident(last_const(text(n, src))),
            "self" => Expr::This,
            "call" if fld(n, "arguments").is_none() && fld(n, "receiver").is_some() => {
                // `repo.client` (a call without arguments) reads like a field
                Expr::Member(fld(n, "receiver").unwrap(), fld_text(n, "method", src).to_string())
            }
            "parenthesized_statements" => n.named_child(0).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        if n.kind() == "call" {
            if let (Some(r), "new") = (fld(n, "receiver"), fld_text(n, "method", src)) {
                if matches!(r.kind(), "constant" | "scope_resolution") {
                    return last_const(text(r, src));
                }
            }
        }
        String::new()
    }
}

/// Rails callbacks name methods by symbol (`before_action :require_login`, `after_save :reorder`, `validate :check`):
/// each symbol is a use of that method of the enclosing class (or an ancestor).
fn callback_uses(n: Node, src: &str) -> Vec<HiddenCall> {
    if fld(n, "receiver").is_some() {
        return vec![];
    }
    let m = fld_text(n, "method", src);
    let dsl = m.starts_with("before_")
        || m.starts_with("after_")
        || m.starts_with("around_")
        || m.starts_with("prepend_before_")
        || m.starts_with("append_before_")
        || matches!(m, "validate" | "helper_method" | "rescue_from");
    if !dsl {
        return vec![];
    }
    let mut cur = n.parent();
    let class = loop {
        match cur {
            Some(c) if matches!(c.kind(), "class" | "module") => break Some(c),
            Some(c) => cur = c.parent(),
            None => break None,
        }
    };
    let Some(class) = class else { return vec![] };
    let cname = last_const(fld_text(class, "name", src));
    let mut out = vec![];
    for a in arg_nodes(fld(n, "arguments")) {
        // `rescue_from E, with: :handler` / `before_action :x, if: :y`: symbols in `with:` / `if:` / `unless:` too
        let syms: Vec<Node> = match a.kind() {
            "simple_symbol" => vec![a],
            "pair" => {
                let k = fld(a, "key").map(|k| text(k, src).trim_end_matches(':').trim_start_matches(':').to_string()).unwrap_or_default();
                if matches!(k.as_str(), "with" | "if" | "unless") {
                    fld(a, "value").filter(|v| v.kind() == "simple_symbol").into_iter().collect()
                } else {
                    vec![]
                }
            }
            _ => vec![],
        };
        for s in syms {
            let name = text(s, src).trim_start_matches(':');
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '?' || c == '!') {
                out.push(HiddenCall { line: line(s), callee: name.to_string(), recv: cname.clone(), static_type: Some(cname.clone()), value: false });
            }
        }
    }
    out
}
