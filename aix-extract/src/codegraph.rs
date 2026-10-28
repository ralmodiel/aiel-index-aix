//! Code graph extractor: every member (methods, constructors, fields, functions, components, inner classes)
//! with its line range, signature, visibility and annotations, plus one `Ref` per call / `new` / JSX use /
//! field access / type use inside a member, with the receiver text and, when the file itself says so, the
//! receiver type (injected fields, constructor params, locals, `this`, `Class.static`, import bindings).
//!
//! Java, TypeScript/JavaScript and Python are walked here; every other language lives in `crate::lang` (Go, Rust,
//! Kotlin, C#, PHP, Ruby, Swift, Scala, C, C++, Dart, Lua, Vue / Svelte scripts). Cross-file resolution happens later
//! in aix-core, from these rows only.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;
use tree_sitter::Node;

use crate::model::*;
use crate::ts_util::*;
use crate::Extractor;

/// One declared member of a file.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Member {
    pub file: String,
    /// First line of the declaration (annotations included, like `Endpoint.line`).
    pub line: u32,
    pub end_line: u32,
    pub name: String,
    /// Simple name of the enclosing class/object (innermost), if any.
    pub container: Option<String>,
    /// `Outer.Inner.name`.
    pub qname: String,
    /// class | interface | enum | record | method | ctor | field | function | component | const | type
    pub kind: String,
    pub sig: String,
    /// public | protected | package | private | export | local
    pub vis: String,
    /// Annotation / decorator texts without the `@`, e.g. `Path("/x")`.
    pub annos: Vec<String>,
    pub is_static: bool,
    /// Simple names of the superclass and interfaces (types only).
    pub supers: Vec<String>,
    /// Return type (methods) or declared type (fields), simple name.
    pub ret: String,
}

/// One use inside a member.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Ref {
    pub file: String,
    pub line: u32,
    /// Qualified name of the enclosing member ("" at file level).
    pub caller: String,
    /// Declaration line of the enclosing member (0 at file level).
    pub caller_line: u32,
    pub callee: String,
    pub recv: String,
    /// Receiver type when known: a class name, or `mod:<module>#<imported name>` for an import binding.
    pub recv_type: String,
    /// call | new | jsx | field | type | import | reexport | ref (a function used as a value)
    pub kind: String,
    /// exact (receiver type known from a declaration, `this` or a class name) | name
    pub conf: String,
    /// Argument count at a call site (-1 = unknown or not a call).
    pub argc: i32,
}

pub struct CodeGraph;

const EXTS: &[&str] = &["java", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "sjs", "py"];

impl Extractor for CodeGraph {
    fn name(&self) -> &'static str {
        "codegraph"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        let e = ext_of(path);
        EXTS.contains(&e) || crate::lang::EXTS.contains(&e)
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let before = rows.members.len();
            match f.ext() {
                "java" => java_file(f, &mut rows),
                "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" | "sjs" => ts_file(f, &mut rows),
                "py" => py_file(f, &mut rows),
                e if crate::lang::EXTS.contains(&e) => crate::lang::file(f, &mut rows),
                _ => {}
            }
            // a tree too deep to walk (see ts_util::MAX_DEPTH): top-level declarations by line, so the file still has members
            if rows.members.len() == before && crate::ts_util::peek_too_deep() {
                if crate::lang::EXTS.contains(&f.ext()) {
                    crate::lang::flat_scan(f, &mut rows);
                } else {
                    flat_scan(f, &mut rows);
                }
            }
        }
        rows
    }
}

/// Top-level declarations of a file whose syntax tree was too deep: one member per declaration line, each running to
/// the next one. No calls. Strings and comments are masked first, so a quoted `class X` is not a declaration.
fn flat_scan(f: &SourceFile, rows: &mut Rows) {
    use std::sync::LazyLock;
    static TS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(function\*?|class|interface|enum|type|const|let|var)\s+(\w+)").unwrap()
    });
    static PY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^(?:async\s+)?(def|class)\s+(\w+)").unwrap());
    static JV: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s{0,8}(?:(?:public|protected|private|static|final|abstract|sealed|default|synchronized)\s+)*(class|interface|enum|record)\s+(\w+)").unwrap()
    });
    let re: &regex::Regex = match f.ext() {
        "py" => &PY,
        "java" => &JV,
        _ => &TS,
    };
    let masked = mask_lines(&f.text, if f.ext() == "py" { "rb" } else { "kt" });
    let mut found: Vec<(usize, String, &str)> = vec![];
    for (i, l) in masked.iter().enumerate() {
        if let Some(c) = re.captures(l) {
            let kw = c.get(1).map(|m| m.as_str()).unwrap_or("");
            let kind = match kw {
                "function" | "function*" | "def" => "function",
                "class" | "record" => "class",
                "interface" => "interface",
                "enum" => "enum",
                "type" => "type",
                _ => "const",
            };
            found.push((i, c[2].to_string(), kind));
        }
    }
    let n = f.text.lines().count();
    for (k, (i, name, kind)) in found.iter().enumerate() {
        let end = found.get(k + 1).map(|x| x.0).unwrap_or(n).max(i + 1);
        rows.members.push(Member {
            file: f.path.clone(),
            line: *i as u32 + 1,
            end_line: end as u32,
            name: name.clone(),
            container: None,
            qname: name.clone(),
            kind: (*kind).into(),
            sig: trunc(f.text.lines().nth(*i).unwrap_or("").trim(), 160),
            vis: "public".into(),
            annos: vec![],
            is_static: false,
            supers: vec![],
            ret: String::new(),
        });
    }
}

fn trunc(s: &str, n: usize) -> String {
    let s = squash(s);
    if s.chars().count() <= n {
        s
    } else {
        let mut o: String = s.chars().take(n).collect();
        o.push('~');
        o
    }
}

const NOISE_TYPES: &[&str] = &[
    "String",
    "Object",
    "List",
    "Map",
    "Set",
    "Optional",
    "Long",
    "Integer",
    "Boolean",
    "Double",
    "Void",
    "Class",
    "Exception",
    "Collection",
    "Iterable",
    "Number",
    "Date",
    "UUID",
    "BigDecimal",
    "LocalDate",
    "LocalDateTime",
    "Instant",
    "Response",
    "Promise",
    "Array",
    "Record",
    "Partial",
    "Omit",
    "Pick",
    "Readonly",
    "Date",
    "Error",
    "Function",
    "ReactNode",
];

// ---------------------------------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------------------------------

fn type_simple(n: Node, src: &str) -> String {
    match n.kind() {
        "type_identifier" | "identifier" => text(n, src).to_string(),
        "generic_type" => named_children(n).first().map(|c| type_simple(*c, src)).unwrap_or_default(),
        "scoped_type_identifier" | "scoped_identifier" => {
            named_children(n).last().map(|c| type_simple(*c, src)).unwrap_or_default()
        }
        "array_type" => n.child_by_field_name("element").map(|c| type_simple(c, src)).unwrap_or_default(),
        "annotated_type" => named_children(n).last().map(|c| type_simple(*c, src)).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Class names mentioned directly by a `extends`/`implements` clause (type arguments skipped).
fn super_names(n: Node, src: &str) -> Vec<String> {
    let mut out = vec![];
    walk(n, |c| match c.kind() {
        "type_arguments" => false,
        "type_identifier" => {
            out.push(text(c, src).to_string());
            false
        }
        "scoped_type_identifier" => {
            out.push(type_simple(c, src));
            false
        }
        _ => true,
    });
    out
}

struct JMods {
    vis: String,
    is_static: bool,
    annos: Vec<String>,
}

fn jmods(decl: Node, src: &str, in_interface: bool) -> JMods {
    let mut m =
        JMods { vis: if in_interface { "public".into() } else { "package".into() }, is_static: false, annos: vec![] };
    let Some(mods) = named_children(decl).into_iter().find(|c| c.kind() == "modifiers") else {
        return m;
    };
    for c in children(mods) {
        match c.kind() {
            "marker_annotation" | "annotation" => m.annos.push(trunc(text(c, src).trim_start_matches('@'), 80)),
            _ => match text(c, src) {
                "public" | "private" | "protected" => m.vis = text(c, src).to_string(),
                "static" => m.is_static = true,
                _ => {}
            },
        }
    }
    m
}

struct JCtx<'a> {
    f: &'a SourceFile,
    src: &'a str,
}

fn java_file(f: &SourceFile, rows: &mut Rows) {
    let Some(tree) = parse(&java(), &f.text) else {
        return;
    };
    let cx = JCtx { f, src: &f.text };
    for n in named_children(tree.root_node()) {
        if n.kind() == "import_declaration" {
            let t = squash(text(n, &f.text));
            let t = t
                .trim_start_matches("import")
                .trim()
                .trim_start_matches("static ")
                .trim()
                .trim_end_matches(';')
                .trim()
                .to_string();
            if let Some((pkg, last)) = t.rsplit_once('.') {
                rows.refs.push(Ref {
                    file: f.path.clone(),
                    line: line(n),
                    caller: String::new(),
                    caller_line: 0,
                    callee: last.to_string(),
                    recv: pkg.to_string(),
                    recv_type: String::new(),
                    kind: "import".into(),
                    conf: "exact".into(),
                    argc: -1,
                });
            }
        } else {
            java_type(&cx, n, None, &HashMap::new(), rows);
        }
    }
}

fn java_type(cx: &JCtx, n: Node, outer: Option<(&str, &str)>, outer_fields: &HashMap<String, String>, rows: &mut Rows) {
    let src = cx.src;
    let kind = match n.kind() {
        "class_declaration" => "class",
        "interface_declaration" | "annotation_type_declaration" => "interface",
        "enum_declaration" => "enum",
        "record_declaration" => "record",
        _ => return,
    };
    let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
        return;
    };
    let qname = match outer {
        Some((_, oq)) => format!("{oq}.{name}"),
        None => name.clone(),
    };
    let m = jmods(n, src, outer.is_some() && false);
    let mut supers = vec![];
    for c in named_children(n) {
        match c.kind() {
            "superclass" | "super_interfaces" | "extends_interfaces" => supers.extend(super_names(c, src)),
            _ => {}
        }
    }
    let sig = {
        let end = n.child_by_field_name("body").map(|b| b.start_byte()).unwrap_or(n.end_byte());
        let start =
            children(n).into_iter().find(|c| c.kind() != "modifiers").map(|c| c.start_byte()).unwrap_or(n.start_byte());
        trunc(&src[start.min(end)..end], 160)
    };
    rows.members.push(Member {
        file: cx.f.path.clone(),
        line: line(n),
        end_line: end_line(n),
        name: name.clone(),
        container: outer.map(|o| o.0.to_string()),
        qname: qname.clone(),
        kind: kind.into(),
        sig,
        vis: m.vis,
        annos: m.annos,
        is_static: m.is_static,
        supers,
        ret: String::new(),
    });
    let Some(body) = n.child_by_field_name("body") else {
        return;
    };
    // members, flattening enum bodies
    let mut items: Vec<Node> = vec![];
    for c in named_children(body) {
        if c.kind() == "enum_body_declarations" {
            items.extend(named_children(c));
        } else {
            items.push(c);
        }
    }
    let in_iface = kind == "interface";
    // field types: this class's fields, constructor-injected or not, over the outer class's
    let mut fields: HashMap<String, String> = outer_fields.clone();
    if kind == "record" {
        if let Some(ps) = n.child_by_field_name("parameters") {
            for p in named_children(ps) {
                if let (Some(t), Some(nm)) = (p.child_by_field_name("type"), p.child_by_field_name("name")) {
                    fields.insert(text(nm, src).to_string(), type_simple(t, src));
                }
            }
        }
    }
    for it in &items {
        if it.kind() == "field_declaration" {
            if let Some(t) = it.child_by_field_name("type") {
                let ty = type_simple(t, src);
                for d in named_children(*it).into_iter().filter(|d| d.kind() == "variable_declarator") {
                    if let Some(dn) = d.child_by_field_name("name") {
                        let ty2 = if ty.is_empty() || ty == "var" {
                            new_type(d.child_by_field_name("value"), src)
                        } else {
                            ty.clone()
                        };
                        fields.insert(text(dn, src).to_string(), ty2);
                    }
                }
            }
        }
    }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for it in items {
        match it.kind() {
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
                let Some(mname) = it.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                    continue;
                };
                let mm = jmods(it, src, in_iface);
                let is_ctor = it.kind() != "method_declaration";
                // a record's compact constructor has no parameter list of its own: it takes the record components
                let params = it
                    .child_by_field_name("parameters")
                    .or_else(|| if it.kind() == "compact_constructor_declaration" { n.child_by_field_name("parameters") } else { None })
                    .map(|p| param_list(p, src))
                    .unwrap_or_default();
                let ret = it.child_by_field_name("type").map(|t| type_simple(t, src)).unwrap_or_default();
                let rtext = it.child_by_field_name("type").map(|t| trunc(text(t, src), 40)).unwrap_or_default();
                let sig = if is_ctor { format!("{mname}{params}") } else { format!("{rtext} {mname}{params}") };
                let mq = format!("{qname}.{mname}");
                rows.members.push(Member {
                    file: cx.f.path.clone(),
                    line: line(it),
                    end_line: end_line(it),
                    name: mname.clone(),
                    container: Some(name.clone()),
                    qname: mq.clone(),
                    kind: if is_ctor { "ctor" } else { "method" }.into(),
                    sig: trunc(&sig, 200),
                    vis: mm.vis,
                    annos: mm.annos,
                    is_static: mm.is_static,
                    supers: vec![],
                    ret,
                });
                // scope: params + locals
                let mut scope = fields.clone();
                collect_locals(it, src, &mut scope);
                let mut env =
                    JRefs { cx, caller: &mq, caller_line: line(it), cls: &name, scope: &scope, fields: &fields, seen: &mut seen };
                // declared parameter / return types
                for part in ["parameters", "type"] {
                    if let Some(p) = it.child_by_field_name(part) {
                        env.walk_refs(p, rows);
                    }
                }
                if let Some(b) = it.child_by_field_name("body") {
                    env.walk_refs(b, rows);
                }
            }
            "field_declaration" => {
                let mm = jmods(it, src, in_iface);
                let tnode = it.child_by_field_name("type");
                let ty = tnode.map(|t| type_simple(t, src)).unwrap_or_default();
                let ttext = tnode.map(|t| trunc(text(t, src), 40)).unwrap_or_default();
                for d in named_children(it).into_iter().filter(|d| d.kind() == "variable_declarator") {
                    let Some(dn) = d.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                        continue;
                    };
                    let fq = format!("{qname}.{dn}");
                    rows.members.push(Member {
                        file: cx.f.path.clone(),
                        line: line(it),
                        end_line: end_line(it),
                        name: dn,
                        container: Some(name.clone()),
                        qname: fq.clone(),
                        kind: "field".into(),
                        sig: trunc(&format!("{ttext} {}", text(d.child_by_field_name("name").unwrap(), src)), 120),
                        vis: mm.vis.clone(),
                        annos: mm.annos.clone(),
                        is_static: mm.is_static,
                        supers: vec![],
                        ret: ty.clone(),
                    });
                    let mut env =
                        JRefs { cx, caller: &fq, caller_line: line(it), cls: &name, scope: &fields, fields: &fields, seen: &mut seen };
                    if let Some(t) = tnode {
                        env.walk_refs(t, rows);
                    }
                    if let Some(v) = d.child_by_field_name("value") {
                        env.walk_refs(v, rows);
                    }
                }
            }
            _ => java_type(cx, it, Some((&name, &qname)), &fields, rows),
        }
    }
}

/// `(Type a, Type b)` without parameter annotations.
fn param_list(p: Node, src: &str) -> String {
    let parts: Vec<String> = named_children(p)
        .into_iter()
        .filter(|c| matches!(c.kind(), "formal_parameter" | "spread_parameter" | "receiver_parameter"))
        .map(|c| {
            let t = c.child_by_field_name("type").map(|t| squash(text(t, src))).unwrap_or_else(|| {
                named_children(c)
                    .iter()
                    .find(|x| x.kind() != "modifiers")
                    .map(|x| squash(text(*x, src)))
                    .unwrap_or_default()
            });
            let nm = c
                .child_by_field_name("name")
                .or_else(|| named_children(c).into_iter().find(|x| x.kind() == "variable_declarator"))
                .map(|x| text(x, src).to_string())
                .unwrap_or_default();
            let dots = if c.kind() == "spread_parameter" { "..." } else { "" };
            format!("{t}{dots} {nm}")
        })
        .collect();
    format!("({})", parts.join(", "))
}

fn new_type(v: Option<Node>, src: &str) -> String {
    match v {
        Some(v) if v.kind() == "object_creation_expression" => {
            v.child_by_field_name("type").map(|t| type_simple(t, src)).unwrap_or_default()
        }
        Some(v) if v.kind() == "method_invocation" => static_lookup_type(v, src),
        _ => String::new(),
    }
}

/// `var x = Entity.findById(id)` / `Entity.findByIdOptional(id).orElseThrow()`: the entity type of a static finder call.
fn static_lookup_type(mut v: Node, src: &str) -> String {
    for _ in 0..4 {
        let name = v.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
        let obj = v.child_by_field_name("object");
        match obj {
            Some(o) if o.kind() == "method_invocation" && matches!(name, "orElseThrow" | "get" | "orElse" | "orElseGet" | "firstResult" | "singleResult") => v = o,
            Some(o) if o.kind() == "identifier" && text(o, src).chars().next().is_some_and(|c| c.is_uppercase()) && (name.starts_with("find") || name.starts_with("get") || name.starts_with("load")) => {
                return text(o, src).to_string();
            }
            _ => return String::new(),
        }
    }
    String::new()
}

/// Is local `id` (in the method `root`) initialised from an expression other than `new` (a lookup, so a managed entity),
/// or the loop variable of an enhanced for?
fn bound_local(root: Node, id: &str, src: &str) -> bool {
    let mut found = false;
    walk(root, |c| {
        match c.kind() {
            "variable_declarator" => {
                if c.child_by_field_name("name").is_some_and(|n| text(n, src) == id) && c.child_by_field_name("value").is_some_and(|v| v.kind() != "object_creation_expression") {
                    found = true;
                }
            }
            "enhanced_for_statement" => {
                if c.child_by_field_name("name").is_some_and(|n| text(n, src) == id) {
                    found = true;
                }
            }
            _ => {}
        }
        !found
    });
    found
}

/// Calls whose single lambda parameter is an element of the receiver's collection / stream / optional.
const ELEM_LAMBDA: &[&str] = &[
    "filter", "map", "flatMap", "forEach", "forEachOrdered", "anyMatch", "allMatch", "noneMatch", "peek", "removeIf", "takeWhile",
    "dropWhile", "mapToInt", "mapToLong", "mapToDouble", "mapToObj", "ifPresent", "allSatisfy", "anySatisfy", "noneSatisfy",
    "filteredOn", "min", "max", "groupingBy",
];
/// Calls that keep the element type of their receiver (stream stages, AssertJ iterable assertions).
const ELEM_PASS: &[&str] = &[
    "stream", "parallelStream", "filter", "sorted", "distinct", "peek", "limit", "skip", "hasSize", "isNotEmpty", "isNotNull",
    "isEmpty", "hasSizeGreaterThan", "hasSizeLessThan", "contains", "containsExactly", "containsOnly", "containsExactlyInAnyOrder",
    "doesNotContain", "allMatch", "anyMatch", "noneMatch", "allSatisfy", "anySatisfy", "filteredOn", "as", "describedAs",
];
const COLLECTIONS: &[&str] = &[
    "List", "Set", "Collection", "Iterable", "Stream", "Optional", "ArrayList", "LinkedList", "HashSet", "LinkedHashSet", "TreeSet",
    "SortedSet", "Deque", "Queue", "ArrayDeque",
];

/// `List<Visit>` -> `Visit` (one-argument collection types only).
fn elem_type(t: Node, src: &str) -> Option<String> {
    let t = if t.kind() == "annotated_type" { named_children(t).last().copied()? } else { t };
    if t.kind() != "generic_type" {
        return None;
    }
    let kids = named_children(t);
    let outer = type_simple(*kids.first()?, src);
    if !COLLECTIONS.contains(&outer.as_str()) {
        return None;
    }
    let args = kids.iter().find(|k| k.kind() == "type_arguments")?;
    let a = named_children(*args);
    if a.len() != 1 {
        return None;
    }
    let e = type_simple(a[0], src);
    (!e.is_empty() && !NOISE_TYPES.contains(&e.as_str())).then_some(e)
}

/// The element type of the collection a call chain starts from: a typed local / parameter (`elem:<name>` in scope), an
/// `assertThat(xs)` root, or `obj.getXs()` on a typed receiver, left to the resolver as `elem:<Type>.<method>` (the
/// method's declared `List<X>` result names X).
fn elem_of(o: Node, src: &str, scope: &HashMap<String, String>, depth: u32) -> Option<String> {
    if depth > 8 {
        return None;
    }
    match o.kind() {
        "identifier" => scope.get(&format!("elem:{}", text(o, src))).cloned(),
        "method_invocation" => {
            let name = o.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
            let obj = o.child_by_field_name("object");
            let args = o.child_by_field_name("arguments").map(named_children).unwrap_or_default();
            if name == "assertThat" && args.len() == 1 {
                return elem_of(args[0], src, scope, depth + 1);
            }
            if ELEM_PASS.contains(&name) {
                return elem_of(obj?, src, scope, depth + 1);
            }
            // a getter on a typed receiver: its declared result decides (resolved later)
            let obj = obj?;
            if !args.is_empty() {
                return None;
            }
            let ty = match obj.kind() {
                "identifier" => scope.get(text(obj, src)).cloned()?,
                _ => return None,
            };
            Some(format!("elem:{ty}.{name}"))
        }
        _ => None,
    }
}

fn collect_locals(m: Node, src: &str, scope: &mut HashMap<String, String>) {
    walk(m, |c| {
        match c.kind() {
            "formal_parameter" | "catch_formal_parameter" | "spread_parameter" => {
                let t = c.child_by_field_name("type").or_else(|| {
                    named_children(c).into_iter().find(|x| x.kind().ends_with("type") || x.kind() == "type_identifier")
                });
                let nm = c.child_by_field_name("name").or_else(|| {
                    named_children(c)
                        .into_iter()
                        .find(|x| x.kind() == "variable_declarator")
                        .and_then(|d| d.child_by_field_name("name"))
                });
                if let (Some(t), Some(nm)) = (t, nm) {
                    let ty = type_simple(t, src);
                    if !ty.is_empty() {
                        scope.insert(text(nm, src).to_string(), ty);
                    }
                    if let Some(e) = elem_type(t, src) {
                        scope.insert(format!("elem:{}", text(nm, src)), e);
                    }
                }
            }
            "local_variable_declaration" | "enhanced_for_statement" => {
                let t = c.child_by_field_name("type");
                let ty = t.map(|t| type_simple(t, src)).unwrap_or_default();
                if c.kind() == "enhanced_for_statement" {
                    if let Some(nm) = c.child_by_field_name("name") {
                        if !ty.is_empty() && ty != "var" {
                            scope.insert(text(nm, src).to_string(), ty);
                        }
                    }
                } else {
                    for d in named_children(c).into_iter().filter(|d| d.kind() == "variable_declarator") {
                        if let Some(dn) = d.child_by_field_name("name") {
                            let ty2 = if ty.is_empty() || ty == "var" {
                                new_type(d.child_by_field_name("value"), src)
                            } else {
                                ty.clone()
                            };
                            if !ty2.is_empty() {
                                scope.insert(text(dn, src).to_string(), ty2);
                            }
                            if let Some(e) = t.and_then(|t| elem_type(t, src)) {
                                scope.insert(format!("elem:{}", text(dn, src)), e);
                            }
                        }
                    }
                }
            }
            "lambda_expression" => {
                // `xs.stream().filter(x -> x.m())`, `xs.forEach(x -> ..)`, `assertThat(xs).allMatch(x -> ..)`: a lone
                // untyped parameter is an element of the collection the call chain starts from
                let p = c.child_by_field_name("parameters");
                let name = match p {
                    Some(p) if p.kind() == "identifier" => Some(text(p, src).to_string()),
                    Some(p) if p.kind() == "inferred_parameters" && p.named_child_count() == 1 => p.named_child(0).map(|x| text(x, src).to_string()),
                    _ => None,
                };
                let call = c.parent().filter(|a| a.kind() == "argument_list").and_then(|a| a.parent()).filter(|m| m.kind() == "method_invocation");
                if let (Some(name), Some(call)) = (name, call) {
                    let meth = call.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
                    if ELEM_LAMBDA.contains(&meth) && !scope.contains_key(&name) {
                        if let Some(e) = call.child_by_field_name("object").and_then(|o| elem_of(o, src, scope, 0)) {
                            scope.insert(name, e);
                        }
                    }
                }
            }
            "instanceof_expression" => {
                // `x instanceof Foo f`
                if let Some(p) = c.child_by_field_name("pattern").or_else(|| c.child_by_field_name("right")) {
                    if p.kind() == "type_pattern" || p.kind() == "record_pattern" {
                        let ns = named_children(p);
                        if ns.len() >= 2 {
                            scope.insert(text(ns[ns.len() - 1], src).to_string(), type_simple(ns[0], src));
                        }
                    }
                }
            }
            _ => {}
        }
        true
    });
    // `<T extends Base>` on the method or an enclosing class: a `T` receiver is a `Base`
    let mut bounds: HashMap<String, String> = HashMap::new();
    let mut cur = Some(m);
    while let Some(n) = cur {
        if let Some(tps) = n.child_by_field_name("type_parameters") {
            for tp in named_children(tps).into_iter().filter(|x| x.kind() == "type_parameter") {
                let kids = named_children(tp);
                let name = kids.iter().find(|x| x.kind() == "type_identifier" || x.kind() == "identifier").map(|x| text(*x, src).to_string());
                let bound = kids.iter().find(|x| x.kind() == "type_bound").and_then(|b| named_children(*b).into_iter().next()).map(|t| type_simple(t, src));
                if let (Some(nm), Some(b)) = (name, bound) {
                    if !b.is_empty() {
                        bounds.entry(nm).or_insert(b);
                    }
                }
            }
        }
        cur = n.parent();
    }
    if !bounds.is_empty() {
        for v in scope.values_mut() {
            if let Some(b) = bounds.get(v.as_str()) {
                *v = b.clone();
            }
        }
    }
}

struct JRefs<'a, 'b> {
    cx: &'a JCtx<'a>,
    caller: &'a str,
    caller_line: u32,
    cls: &'a str,
    scope: &'a HashMap<String, String>,
    /// the class's fields only (`this.x` is never a local named `x`)
    fields: &'a HashMap<String, String>,
    seen: &'b mut HashSet<(String, String)>,
}

impl JRefs<'_, '_> {
    fn push(&self, rows: &mut Rows, n: Node, callee: &str, recv: String, rt: String, kind: &str, exact: bool) {
        rows.refs.push(Ref {
            file: self.cx.f.path.clone(),
            line: line(n),
            caller: self.caller.to_string(),
            caller_line: self.caller_line,
            callee: callee.to_string(),
            recv,
            recv_type: rt,
            kind: kind.into(),
            conf: if exact { "exact" } else { "name" }.into(),
            argc: -1,
        });
    }

    /// (receiver text, receiver type, known)
    fn recv_of(&self, obj: Option<Node>) -> (String, String, bool) {
        let src = self.cx.src;
        let Some(o) = obj else {
            return (String::new(), self.cls.to_string(), true);
        };
        let t = trunc(text(o, src), 80);
        match o.kind() {
            "this" => ("this".into(), self.cls.to_string(), true),
            // `super.m()` names the parent's `m`, never the override it is written in
            "super" => ("super".into(), if self.cls.is_empty() { String::new() } else { format!("super:{}", self.cls) }, true),
            "identifier" => {
                let id = text(o, src);
                if let Some(ty) = self.scope.get(id) {
                    (t, ty.clone(), true)
                } else if id.chars().next().is_some_and(|c| c.is_uppercase()) {
                    (t, id.to_string(), true)
                } else {
                    (t, String::new(), false)
                }
            }
            "field_access" => {
                let obj2 = o.child_by_field_name("object");
                let fld = o.child_by_field_name("field").map(|x| text(x, src)).unwrap_or("");
                if obj2.is_some_and(|x| x.kind() == "this") {
                    if let Some(ty) = self.fields.get(fld) {
                        return (t, ty.clone(), true);
                    }
                }
                if fld.chars().next().is_some_and(|c| c.is_uppercase()) {
                    return (t, fld.to_string(), true);
                }
                (t, String::new(), false)
            }
            "object_creation_expression" => (t, new_type(Some(o), src), true),
            "parenthesized_expression" => {
                let inner = o.named_child(0);
                match inner {
                    Some(i) if i.kind() == "cast_expression" => {
                        let ty = i.child_by_field_name("type").map(|x| type_simple(x, src)).unwrap_or_default();
                        (t, ty, true)
                    }
                    _ => (t, String::new(), false),
                }
            }
            _ => (t, String::new(), false),
        }
    }

    /// The mocked object of a Mockito-style wrapper call used as a receiver: `verify(x, times(2))`, `Mockito.verify(x)`,
    /// `when(x)` / `given(x)` / `then(x)` (also after `doReturn(v).` / `willReturn(v).`) and `then(x).should(...)`.
    fn mock_target<'t>(&self, o: Node<'t>) -> Option<Node<'t>> {
        let src = self.cx.src;
        if o.kind() != "method_invocation" {
            return None;
        }
        let name = o.child_by_field_name("name").map(|x| text(x, src))?;
        if name == "should" {
            return o.child_by_field_name("object").and_then(|i| self.mock_target(i));
        }
        if !matches!(name, "verify" | "when" | "given" | "then") {
            return None;
        }
        // static import, `Mockito.verify` / `BDDMockito.then`, or the stubbing chain `doReturn(v).when(x)`
        let chained = match o.child_by_field_name("object") {
            None => true,
            Some(ob) => matches!(text(ob, src), "Mockito" | "BDDMockito" | "MockitoJUnit") || ob.kind() == "method_invocation",
        };
        if !chained {
            return None;
        }
        let a0 = o.child_by_field_name("arguments").and_then(|a| named_children(a).into_iter().next())?;
        // `when(x.m())` stubs a call, it does not name a mock; only an identifier / field names the mocked object
        matches!(a0.kind(), "identifier" | "field_access").then_some(a0)
    }

    fn walk_refs(&mut self, root: Node, rows: &mut Rows) {
        let src = self.cx.src;
        // collect first (the closure cannot borrow self mutably twice)
        let mut nodes: Vec<Node> = vec![];
        walk(root, |c| {
            match c.kind() {
                "method_invocation"
                | "object_creation_expression"
                | "field_access"
                | "method_reference"
                | "type_identifier" => nodes.push(c),
                _ => {}
            }
            true
        });
        for c in nodes {
            match c.kind() {
                "method_invocation" => {
                    let Some(name) = c.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                        continue;
                    };
                    let obj = c.child_by_field_name("object");
                    let (mut recv, mut rt, mut known) = self.recv_of(obj);
                    // Mockito `verify(x).m()` / `when(x)...` / `doReturn(v).when(x).m()` / `then(x).should().m()`: the call
                    // lands on `x`, so the receiver is typed as `x` (a heuristic: the edge is labelled as such)
                    let mut mock = false;
                    if let Some(m) = obj.and_then(|o| self.mock_target(o)) {
                        let (r2, t2, k2) = self.recv_of(Some(m));
                        if k2 && !t2.is_empty() {
                            (recv, rt, known, mock) = (r2, t2, true, true);
                        }
                    }
                    // a setter on a looked-up local: JPA dirty checking writes it at commit (`fwrite`)
                    if known && !rt.is_empty() && name.len() > 3 && name.starts_with("set") && name[3..].chars().next().is_some_and(|ch| ch.is_uppercase()) {
                        if let Some(o) = c.child_by_field_name("object").filter(|o| o.kind() == "identifier") {
                            if bound_local(root, text(o, src), src) {
                                self.push(rows, c, &name, recv.clone(), rt.clone(), "fwrite", true);
                            }
                        }
                    }
                    self.push(rows, c, &name, recv, rt, "call", known);
                    let n = c.child_by_field_name("arguments").map(|a| crate::lang::engine::arg_nodes(Some(a)).len() as i32).unwrap_or(-1);
                    if let Some(r) = rows.refs.last_mut() {
                        r.argc = n;
                        if mock {
                            r.conf = "heuristic".into();
                        }
                    }
                }
                "object_creation_expression" => {
                    if let Some(t) = c.child_by_field_name("type") {
                        let tn = type_simple(t, src);
                        if !tn.is_empty() {
                            self.push(rows, c, &tn, String::new(), tn.clone(), "new", true);
                        }
                    }
                }
                "method_reference" => {
                    let ns = named_children(c);
                    if ns.len() >= 2 {
                        let (recv, rt, known) = self.recv_of(Some(ns[0]));
                        let nm = text(ns[ns.len() - 1], src).to_string();
                        if nm != "new" {
                            self.push(rows, c, &nm, recv, rt, "call", known);
                        }
                    }
                }
                "field_access" => {
                    let Some(o) = c.child_by_field_name("object") else { continue };
                    let Some(fld) = c.child_by_field_name("field").map(|x| text(x, src).to_string()) else { continue };
                    if o.kind() == "identifier" {
                        let (recv, rt, known) = self.recv_of(Some(o));
                        if known && !rt.is_empty() {
                            // `x.f = v` / `x.f += v` / `x.f++` on a looked-up local: a dirty-checked write (`fwrite`)
                            let assigned = c.parent().is_some_and(|p| {
                                (p.kind() == "assignment_expression" && p.child_by_field_name("left").is_some_and(|l| l.id() == c.id())) || p.kind() == "update_expression"
                            });
                            if assigned && bound_local(root, text(o, src), src) {
                                self.push(rows, c, &fld, recv.clone(), rt.clone(), "fwrite", true);
                            }
                            self.push(rows, c, &fld, recv, rt, "field", true);
                        }
                    }
                }
                "type_identifier" => {
                    let t = text(c, src);
                    if NOISE_TYPES.contains(&t) || t == self.cls {
                        continue;
                    }
                    if self.seen.insert((self.caller.to_string(), t.to_string())) {
                        self.push(rows, c, t, String::new(), t.to_string(), "type", true);
                    }
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// TypeScript / JavaScript
// ---------------------------------------------------------------------------------------------------

struct Ts<'a> {
    src: &'a str,
    f: &'a SourceFile,
    imports: HashMap<String, (String, String)>,
    seen_types: HashSet<(String, String)>,
    exported: bool,
}

#[derive(Clone, Default)]
struct TCx {
    caller: String,
    caller_line: u32,
    /// class or object name for members declared here
    container: Option<String>,
    /// class whose `this` we are in
    cls: Option<String>,
    fields: HashMap<String, String>,
    depth: u32,
}

const WRAPPERS: &[&str] = &[
    "memo",
    "forwardRef",
    "useCallback",
    "observer",
    "React.memo",
    "React.forwardRef",
    "React.useCallback",
    "withRouter",
    "useMemo",
];

pub(crate) fn ts_file(f: &SourceFile, rows: &mut Rows) {
    let lang = match f.ext() {
        "tsx" | "jsx" | "js" | "mjs" | "cjs" | "sjs" => tsx(),
        _ => typescript(),
    };
    let Some(tree) = parse(&lang, &f.text) else {
        return;
    };
    let mut ts = Ts { src: &f.text, f, imports: HashMap::new(), seen_types: HashSet::new(), exported: false };
    ts.collect_imports(tree.root_node(), rows);
    ts.visit(tree.root_node(), &TCx::default(), rows);
}

impl Ts<'_> {
    fn collect_imports(&mut self, root: Node, rows: &mut Rows) {
        let src = self.src;
        for n in named_children(root) {
            if n.kind() == "import_statement" {
                let Some(source) = n.child_by_field_name("source").and_then(|s| js_string(s, src)) else { continue };
                let mut bound: Vec<(String, String)> = vec![];
                for c in named_children(n) {
                    if c.kind() != "import_clause" {
                        continue;
                    }
                    for k in named_children(c) {
                        match k.kind() {
                            "identifier" => bound.push((text(k, src).to_string(), "default".into())),
                            "namespace_import" => {
                                if let Some(i) = named_children(k).first() {
                                    bound.push((text(*i, src).to_string(), "*".into()));
                                }
                            }
                            "named_imports" => {
                                for s in named_children(k) {
                                    if s.kind() != "import_specifier" {
                                        continue;
                                    }
                                    let orig = s
                                        .child_by_field_name("name")
                                        .map(|x| text(x, src).to_string())
                                        .unwrap_or_default();
                                    let local = s
                                        .child_by_field_name("alias")
                                        .map(|x| text(x, src).to_string())
                                        .unwrap_or_else(|| orig.clone());
                                    bound.push((local, orig));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                for (local, orig) in bound {
                    rows.refs.push(Ref {
                        file: self.f.path.clone(),
                        line: line(n),
                        caller: String::new(),
                        caller_line: 0,
                        callee: if orig == "default" || orig == "*" { local.clone() } else { orig.clone() },
                        recv: source.clone(),
                        recv_type: String::new(),
                        kind: "import".into(),
                        conf: "exact".into(),
                        argc: -1,
                    });
                    self.imports.insert(local, (source.clone(), orig));
                }
            }
        }
        // `export * from './x'`, `export * as ns from './x'`, `export { a, b as c } from './x'`: barrels. One `reexport` ref per
        // name: callee = the name in the source module ("*" for all), recv = the specifier, recv_type = the exported name.
        for n in named_children(root) {
            if n.kind() != "export_statement" {
                continue;
            }
            let Some(source) = n.child_by_field_name("source").and_then(|s| js_string(s, src)) else { continue };
            let mut names: Vec<(String, String)> = vec![];
            let mut star = true;
            for c in named_children(n) {
                match c.kind() {
                    "export_clause" => {
                        star = false;
                        for sp in named_children(c) {
                            if sp.kind() != "export_specifier" {
                                continue;
                            }
                            let orig = sp.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
                            let al = sp.child_by_field_name("alias").map(|x| text(x, src).to_string()).unwrap_or_else(|| orig.clone());
                            names.push((orig, al));
                        }
                    }
                    "namespace_export" => {
                        star = false;
                        if let Some(i) = named_children(c).first() {
                            names.push(("*".into(), text(*i, src).to_string()));
                        }
                    }
                    _ => {}
                }
            }
            if star {
                names.push(("*".into(), "*".into()));
            }
            for (orig, al) in names {
                rows.refs.push(Ref {
                    file: self.f.path.clone(),
                    line: line(n),
                    caller: String::new(),
                    caller_line: 0,
                    callee: orig,
                    recv: source.clone(),
                    recv_type: al,
                    kind: "reexport".into(),
                    conf: "exact".into(),
                    argc: -1,
                });
            }
        }
        // lazy(() => import('./X'))
        walk(root, |c| {
            if c.kind() == "variable_declarator" {
                if let (Some(nm), Some(v)) = (c.child_by_field_name("name"), c.child_by_field_name("value")) {
                    let mut found = None;
                    walk(v, |d| {
                        if d.kind() == "call_expression"
                            && d.child_by_field_name("function").is_some_and(|f| text(f, src) == "import")
                        {
                            if let Some(a) =
                                d.child_by_field_name("arguments").and_then(|a| named_children(a).first().copied())
                            {
                                found = js_string(a, src);
                            }
                        }
                        found.is_none()
                    });
                    if let Some(s) = found {
                        self.imports.insert(text(nm, src).to_string(), (s, "default".into()));
                    } else if self.f.ext() == "sjs" {
                        crate::lang::xquery::sjs_require(self.f, c, nm, v, src, &mut self.imports, rows);
                    }
                }
            }
            true
        });
    }

    fn member(
        &self,
        rows: &mut Rows,
        n: Node,
        name: &str,
        kind: &str,
        cx: &TCx,
        sig: String,
        vis: &str,
        ret: String,
        annos: Vec<String>,
        is_static: bool,
    ) -> String {
        let q = match &cx.container {
            Some(c) => format!("{c}.{name}"),
            None => name.to_string(),
        };
        rows.members.push(Member {
            file: self.f.path.clone(),
            line: line(n),
            end_line: end_line(n),
            name: name.to_string(),
            container: cx.container.clone(),
            qname: q.clone(),
            kind: kind.into(),
            sig: trunc(&sig, 200),
            vis: vis.into(),
            annos,
            is_static,
            supers: vec![],
            ret,
        });
        q
    }

    fn ref_(
        &self,
        rows: &mut Rows,
        n: Node,
        cx: &TCx,
        callee: &str,
        recv: String,
        rt: String,
        kind: &str,
        exact: bool,
    ) {
        rows.refs.push(Ref {
            file: self.f.path.clone(),
            line: line(n),
            caller: cx.caller.clone(),
            caller_line: cx.caller_line,
            callee: callee.to_string(),
            recv,
            recv_type: rt,
            kind: kind.into(),
            conf: if exact { "exact" } else { "name" }.into(),
            argc: -1,
        });
    }

    fn visit_children(&mut self, n: Node, cx: &TCx, rows: &mut Rows) {
        for c in children(n) {
            self.visit(c, cx, rows);
        }
    }

    fn vis(&self) -> &'static str {
        if self.exported {
            "export"
        } else {
            "local"
        }
    }

    fn visit(&mut self, n: Node, cx: &TCx, rows: &mut Rows) {
        let src = self.src;
        match n.kind() {
            "export_statement" => {
                let was = self.exported;
                self.exported = true;
                self.visit_children(n, cx, rows);
                self.exported = was;
                // `export default function mul` / `export default Foo`: the module's `default` names that member (a
                // `defaultexport` row: callee = its name), so `export { default as times } from './math'` and default
                // imports under another name reach it
                if children(n).iter().any(|c| c.kind() == "default") {
                    let named = n
                        .child_by_field_name("declaration")
                        .and_then(|d| d.child_by_field_name("name"))
                        .or_else(|| n.child_by_field_name("value").filter(|v| v.kind() == "identifier"));
                    if let Some(nm) = named {
                        self.ref_(rows, n, &TCx { caller: String::new(), caller_line: 0, ..cx.clone() }, text(nm, src), String::new(), "default".into(), "defaultexport", true);
                    }
                }
            }
            "function_declaration" | "generator_function_declaration" => {
                let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                    return;
                };
                self.declare_fn(n, &name, cx, rows);
            }
            "class_declaration" | "abstract_class_declaration" => self.declare_class(n, cx, rows),
            // overload signature (`function f(a: string): void;`): listed like the implementation
            "function_signature" => {
                if let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) {
                    let kind = if name.chars().next().is_some_and(|c| c.is_uppercase()) { "component" } else { "function" };
                    let sig = format!("{name}{}", self.params_text(n));
                    let vis = self.vis();
                    self.member(rows, n, &name, kind, cx, sig, vis, String::new(), vec![], false);
                }
                self.exported = false;
            }
            // `namespace X { .. }` / `declare module "x" { .. }`: the namespace is a member, its body is walked
            "internal_module" | "module" => {
                if let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).trim_matches(['"', '\'']).to_string()) {
                    let vis = self.vis();
                    self.member(rows, n, &name, "namespace", cx, format!("namespace {name}"), vis, String::new(), vec![], false);
                }
                self.exported = false;
                self.visit_children(n, cx, rows);
            }
            "interface_declaration" | "type_alias_declaration" | "enum_declaration" => {
                if cx.caller.is_empty() {
                    if let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) {
                        let kind = match n.kind() {
                            "interface_declaration" => "interface",
                            "enum_declaration" => "enum",
                            _ => "type",
                        };
                        let cx2 = TCx::default();
                        let vis = self.vis();
                        self.member(
                            rows,
                            n,
                            &name,
                            kind,
                            &cx2,
                            format!("{kind} {name}"),
                            vis,
                            String::new(),
                            vec![],
                            false,
                        );
                    }
                }
                self.exported = false;
            }
            "lexical_declaration" | "variable_declaration" => {
                let was = self.exported;
                for d in named_children(n) {
                    if d.kind() == "variable_declarator" {
                        self.declare_var(d, n, cx, rows);
                    }
                }
                self.exported = was && false;
            }
            "call_expression" => {
                if self.route_handler(n, cx, rows) {
                    return;
                }
                self.call_ref(n, cx, rows);
                self.visit_children(n, cx, rows);
            }
            "arguments" => {
                for a in named_children(n) {
                    if matches!(a.kind(), "identifier" | "member_expression") {
                        self.value_ref(rows, a, cx);
                    }
                }
                self.visit_children(n, cx, rows);
            }
            "pair" => {
                if let Some(v) = n.child_by_field_name("value") {
                    if matches!(v.kind(), "identifier" | "member_expression") {
                        self.value_ref(rows, v, cx);
                    }
                }
                self.visit_children(n, cx, rows);
            }
            "jsx_expression" => {
                if let Some(v) = named_children(n).first() {
                    if matches!(v.kind(), "identifier" | "member_expression") {
                        self.value_ref(rows, *v, cx);
                    }
                }
                self.visit_children(n, cx, rows);
            }
            "new_expression" => {
                if let Some(c) = n.child_by_field_name("constructor") {
                    if c.kind() == "identifier" {
                        let nm = text(c, src);
                        let (rt, known) = match self.imports.get(nm) {
                            Some((s, o)) => (format!("mod:{s}#{o}"), true),
                            None => (nm.to_string(), true),
                        };
                        let callee = self
                            .imports
                            .get(nm)
                            .map(|(_, o)| if o == "default" || o == "*" { nm.to_string() } else { o.clone() })
                            .unwrap_or_else(|| nm.to_string());
                        self.ref_(rows, n, cx, &callee, String::new(), rt, "new", known);
                    }
                }
                self.visit_children(n, cx, rows);
            }
            "jsx_opening_element" | "jsx_self_closing_element" => {
                if let Some(nm) = n.child_by_field_name("name") {
                    let t = text(nm, src);
                    if t.chars().next().is_some_and(|c| c.is_uppercase()) {
                        if let Some((a, b)) = t.split_once('.') {
                            let (rt, _) = self.binding(a);
                            self.ref_(rows, n, cx, b, a.to_string(), rt, "jsx", true);
                        } else {
                            let (rt, callee) = self.binding_bare(t);
                            self.ref_(rows, n, cx, &callee, String::new(), rt, "jsx", true);
                        }
                    }
                }
                self.visit_children(n, cx, rows);
            }
            "type_identifier" => {
                let t = text(n, src);
                if !NOISE_TYPES.contains(&t)
                    && !cx.caller.is_empty()
                    && self.seen_types.insert((cx.caller.clone(), t.to_string()))
                {
                    let (rt, callee) = self.binding_bare(t);
                    self.ref_(
                        rows,
                        n,
                        cx,
                        &callee,
                        String::new(),
                        if rt.is_empty() { t.to_string() } else { rt },
                        "type",
                        true,
                    );
                }
            }
            _ => self.visit_children(n, cx, rows),
        }
    }

    /// (`mod:src#orig` or "", known) for an identifier that may be an import binding.
    fn binding(&self, id: &str) -> (String, bool) {
        match self.imports.get(id) {
            Some((s, o)) => (format!("mod:{s}#{o}"), true),
            None => (String::new(), false),
        }
    }
    fn binding_bare(&self, id: &str) -> (String, String) {
        match self.imports.get(id) {
            Some((s, o)) => {
                (format!("mod:{s}#{o}"), if o == "default" || o == "*" { id.to_string() } else { o.clone() })
            }
            None => (String::new(), id.to_string()),
        }
    }

    fn call_ref(&mut self, n: Node, cx: &TCx, rows: &mut Rows) {
        let src = self.src;
        let Some(func) = n.child_by_field_name("function") else { return };
        match func.kind() {
            "identifier" => {
                let id = text(func, src);
                let (rt, callee) = self.binding_bare(id);
                self.ref_(rows, n, cx, &callee, String::new(), rt.clone(), "call", !rt.is_empty());
                let argc = n.child_by_field_name("arguments").map(|a| crate::lang::engine::arg_nodes(Some(a)).len() as i32).unwrap_or(-1);
                if let Some(r) = rows.refs.last_mut() {
                    r.argc = argc;
                }
            }
            "member_expression" => {
                let (Some(obj), Some(prop)) =
                    (func.child_by_field_name("object"), func.child_by_field_name("property"))
                else {
                    return;
                };
                let pname = text(prop, src).to_string();
                let recv = trunc(text(obj, src), 80);
                let (rt, known) = self.recv_info(obj, cx);
                self.ref_(rows, n, cx, &pname, recv, rt, "call", known);
                if matches!(pname.as_str(), "bind" | "call" | "apply") {
                    self.value_ref(rows, obj, cx);
                }
                let argc = n.child_by_field_name("arguments").map(|a| crate::lang::engine::arg_nodes(Some(a)).len() as i32).unwrap_or(-1);
                if let Some(r) = rows.refs.last_mut() {
                    r.argc = argc;
                }
            }
            _ => {}
        }
    }

    /// (receiver type, known) of the object of a member expression.
    fn recv_info(&self, obj: Node, cx: &TCx) -> (String, bool) {
        let src = self.src;
        match obj.kind() {
            "identifier" => {
                let (b, k) = self.binding(text(obj, src));
                if k {
                    (b, true)
                } else {
                    (String::new(), false)
                }
            }
            "this" => (cx.cls.clone().unwrap_or_default(), cx.cls.is_some()),
            // `super.m()`: the parent's `m` (resolved through the class's supers)
            "super" => (cx.cls.as_ref().map(|c| format!("super:{c}")).unwrap_or_default(), cx.cls.is_some()),
            "member_expression" => {
                let o2 = obj.child_by_field_name("object");
                let p2 = obj.child_by_field_name("property").map(|p| text(p, src)).unwrap_or("");
                match (o2, cx.fields.get(p2)) {
                    (Some(o2), Some(ty)) if o2.kind() == "this" => (ty.clone(), true),
                    _ => (String::new(), false),
                }
            }
            _ => (String::new(), false),
        }
    }

    /// A function used as a value (argument, object property value, JSX attribute, `.bind` target): a `ref`.
    fn value_ref(&self, rows: &mut Rows, v: Node, cx: &TCx) {
        let src = self.src;
        match v.kind() {
            "identifier" => {
                let id = text(v, src);
                if matches!(id, "undefined" | "null" | "NaN" | "Infinity") {
                    return;
                }
                let (rt, callee) = self.binding_bare(id);
                self.ref_(rows, v, cx, &callee, String::new(), rt.clone(), "ref", !rt.is_empty());
            }
            "member_expression" => {
                let (Some(obj), Some(prop)) = (v.child_by_field_name("object"), v.child_by_field_name("property")) else {
                    return;
                };
                if !matches!(obj.kind(), "identifier" | "this" | "member_expression") {
                    return;
                }
                let (rt, known) = self.recv_info(obj, cx);
                if known {
                    let recv = trunc(text(obj, src), 80);
                    self.ref_(rows, v, cx, text(prop, src), recv, rt, "ref", true);
                }
            }
            _ => {}
        }
    }

    /// `router.get('/x', async (req, res) => {...})`: the callback is a member named `router.get /x handler`.
    fn route_handler(&mut self, n: Node, cx: &TCx, rows: &mut Rows) -> bool {
        let src = self.src;
        let Some(func) = n.child_by_field_name("function") else { return false };
        if func.kind() != "member_expression" {
            return false;
        }
        let (Some(obj), Some(prop)) = (func.child_by_field_name("object"), func.child_by_field_name("property")) else {
            return false;
        };
        let verb = text(prop, src);
        if obj.kind() != "identifier"
            || !matches!(verb, "get" | "post" | "put" | "patch" | "delete" | "all" | "use" | "head" | "options")
        {
            return false;
        }
        let Some(args) = n.child_by_field_name("arguments") else { return false };
        let args = named_children(args);
        let Some(f) = args.iter().rev().find(|a| matches!(a.kind(), "arrow_function" | "function_expression" | "function")) else {
            return false;
        };
        let path = args.first().and_then(|a| js_string(*a, src)).unwrap_or_default();
        let name = if path.is_empty() {
            format!("{}.{verb} handler", text(obj, src))
        } else {
            format!("{}.{verb} {path} handler", text(obj, src))
        };
        // callbacks that are not the route handler (middleware calls first) are still walked as plain expressions
        let sig = format!("{name}{}", self.params_text(*f));
        let qn = self.member(rows, n, &name, "function", &TCx::default(), sig, "local", String::new(), vec![], false);
        if let Some(m) = rows.members.last_mut() {
            m.end_line = end_line(n);
        }
        let cx2 = TCx {
            caller: qn,
            caller_line: line(n),
            container: Some(name),
            cls: cx.cls.clone(),
            fields: cx.fields.clone(),
            depth: cx.depth + 1,
        };
        // the call itself (router.get) and non-function arguments (auth.required, middleware) belong to the handler
        self.call_ref(n, &cx2, rows);
        for a in &args {
            if std::ptr::eq(a, f) {
                continue;
            }
            self.visit(*a, &cx2, rows);
            if matches!(a.kind(), "identifier" | "member_expression") {
                self.value_ref(rows, *a, &cx2);
            }
        }
        if let Some(p) = f.child_by_field_name("parameters") {
            self.visit(p, &cx2, rows);
        }
        if let Some(b) = f.child_by_field_name("body") {
            self.visit(b, &cx2, rows);
        }
        true
    }

    fn params_text(&self, n: Node) -> String {
        n.child_by_field_name("parameters")
            .or_else(|| n.child_by_field_name("parameter"))
            .map(|p| {
                let t = text(p, self.src);
                if p.kind() == "identifier" {
                    format!("({t})")
                } else {
                    squash(t)
                }
            })
            .unwrap_or_else(|| "()".into())
    }

    fn declare_fn(&mut self, n: Node, name: &str, cx: &TCx, rows: &mut Rows) {
        let kind = if name.chars().next().is_some_and(|c| c.is_uppercase()) { "component" } else { "function" };
        let sig = format!("{name}{}", self.params_text(n));
        let ret = n
            .child_by_field_name("return_type")
            .map(|r| trunc(text(r, self.src).trim_start_matches(':'), 40))
            .unwrap_or_default();
        let vis = self.vis();
        let q = self.member(rows, n, name, kind, cx, sig, vis, ret, vec![], false);
        self.exported = false;
        let cx2 = TCx {
            caller: q.clone(),
            caller_line: line(n),
            container: Some(name.to_string()),
            cls: cx.cls.clone(),
            fields: cx.fields.clone(),
            depth: cx.depth + 1,
        };
        // parameters (type annotations) and body
        if let Some(p) = n.child_by_field_name("parameters") {
            self.visit(p, &cx2, rows);
        }
        if let Some(b) = n.child_by_field_name("body") {
            self.visit(b, &cx2, rows);
        }
    }

    fn declare_class(&mut self, n: Node, cx: &TCx, rows: &mut Rows) {
        let src = self.src;
        let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else { return };
        let vis = self.vis();
        let mut supers = vec![];
        for c in named_children(n) {
            if c.kind() == "class_heritage" {
                walk(c, |d| {
                    if matches!(d.kind(), "identifier" | "type_identifier") {
                        supers.push(text(d, src).to_string());
                        false
                    } else if d.kind() == "type_arguments" {
                        false
                    } else {
                        true
                    }
                });
            }
        }
        self.exported = false;
        let mut annos: Vec<String> = vec![];
        for c in named_children(n) {
            if c.kind() == "decorator" {
                annos.push(trunc(text(c, src).trim_start_matches('@'), 80));
            }
        }
        let q = self.member(rows, n, &name, "class", cx, format!("class {name}"), vis, String::new(), annos, false);
        if let Some(m) = rows.members.last_mut() {
            m.supers = supers;
        }
        let Some(body) = n.child_by_field_name("body") else { return };
        // field types: declared fields and constructor parameter properties
        let mut fields: HashMap<String, String> = HashMap::new();
        for it in named_children(body) {
            match it.kind() {
                "public_field_definition" => {
                    if let (Some(nm), Some(t)) = (it.child_by_field_name("name"), it.child_by_field_name("type")) {
                        fields.insert(text(nm, src).to_string(), ts_type(t, src));
                    }
                }
                "method_definition"
                    if it.child_by_field_name("name").is_some_and(|x| text(x, src) == "constructor") =>
                {
                    if let Some(ps) = it.child_by_field_name("parameters") {
                        for p in named_children(ps) {
                            let has_mod = named_children(p)
                                .iter()
                                .any(|c| c.kind() == "accessibility_modifier" || c.kind() == "readonly");
                            if has_mod {
                                if let (Some(nm), Some(t)) = (
                                    p.child_by_field_name("pattern").or_else(|| p.child_by_field_name("name")),
                                    p.child_by_field_name("type"),
                                ) {
                                    fields.insert(text(nm, src).to_string(), ts_type(t, src));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let ccx = TCx {
            caller: String::new(),
            caller_line: 0,
            container: Some(name.clone()),
            cls: Some(name.clone()),
            fields,
            depth: cx.depth + 1,
        };
        for it in named_children(body) {
            let mut annos: Vec<String> = vec![];
            let mut is_static = false;
            let mut vis = "public".to_string();
            for c in children(it) {
                match c.kind() {
                    "decorator" => annos.push(trunc(text(c, src).trim_start_matches('@'), 80)),
                    "accessibility_modifier" => vis = text(c, src).to_string(),
                    "static" => is_static = true,
                    _ => {}
                }
            }
            match it.kind() {
                "method_definition" | "abstract_method_signature" | "method_signature" => {
                    let Some(nm) = it.child_by_field_name("name").map(|x| text(x, src).to_string()) else { continue };
                    if it.child_by_field_name("name").is_some_and(|x| x.kind() == "private_property_identifier") {
                        vis = "private".into();
                    }
                    let kind = if nm == "constructor" { "ctor" } else { "method" };
                    let ret = it
                        .child_by_field_name("return_type")
                        .map(|r| trunc(text(r, src).trim_start_matches(':'), 40))
                        .unwrap_or_default();
                    let q = self.member(
                        rows,
                        it,
                        &nm,
                        kind,
                        &ccx,
                        format!("{nm}{}", self.params_text(it)),
                        &vis,
                        ret,
                        annos,
                        is_static,
                    );
                    let cx2 = TCx {
                        caller: q,
                        caller_line: line(it),
                        container: Some(nm.clone()),
                        cls: ccx.cls.clone(),
                        fields: ccx.fields.clone(),
                        depth: ccx.depth + 1,
                    };
                    for part in ["parameters", "body"] {
                        if let Some(p) = it.child_by_field_name(part) {
                            self.visit(p, &cx2, rows);
                        }
                    }
                }
                "public_field_definition" => {
                    let Some(nm) = it.child_by_field_name("name").map(|x| text(x, src).to_string()) else { continue };
                    let val = it.child_by_field_name("value");
                    let is_fn =
                        val.is_some_and(|v| matches!(v.kind(), "arrow_function" | "function_expression" | "function"));
                    let ty = it.child_by_field_name("type").map(|t| ts_type(t, src)).unwrap_or_default();
                    let q = self.member(
                        rows,
                        it,
                        &nm,
                        if is_fn { "method" } else { "field" },
                        &ccx,
                        nm.to_string(),
                        &vis,
                        ty,
                        annos,
                        is_static,
                    );
                    if let Some(v) = val {
                        let cx2 = TCx {
                            caller: q,
                            caller_line: line(it),
                            container: Some(nm.clone()),
                            cls: ccx.cls.clone(),
                            fields: ccx.fields.clone(),
                            depth: ccx.depth + 1,
                        };
                        self.visit(v, &cx2, rows);
                    }
                }
                _ => {}
            }
        }
        let _ = q;
    }

    fn declare_var(&mut self, d: Node, stmt: Node, cx: &TCx, rows: &mut Rows) {
        let src = self.src;
        let (Some(nm), val) = (d.child_by_field_name("name"), d.child_by_field_name("value")) else { return };
        if nm.kind() != "identifier" {
            if let Some(v) = val {
                self.visit(v, cx, rows);
            }
            return;
        }
        let name = text(nm, src).to_string();
        let Some(mut v) = val else { return };
        while matches!(
            v.kind(),
            "as_expression" | "satisfies_expression" | "parenthesized_expression" | "non_null_expression"
        ) {
            match v.named_child(0) {
                Some(x) => v = x,
                None => break,
            }
        }
        let top = cx.caller.is_empty();
        let vis = self.vis();
        let nested_ok = cx.depth < 3;
        // arrow / function expression
        if matches!(v.kind(), "arrow_function" | "function_expression" | "function" | "generator_function") {
            if !top && !nested_ok {
                self.visit(v, cx, rows);
                return;
            }
            let kind =
                if name.chars().next().is_some_and(|c| c.is_uppercase()) && top { "component" } else { "function" };
            let cxm = if top {
                TCx { container: None, ..cx.clone() }
            } else {
                TCx { container: cx.container.clone().or_else(|| Some(cx.caller.clone())), ..cx.clone() }
            };
            let ret = v
                .child_by_field_name("return_type")
                .map(|r| trunc(text(r, src).trim_start_matches(':'), 40))
                .unwrap_or_default();
            let q = self.member(
                rows,
                stmt,
                &name,
                kind,
                &cxm,
                format!("{name} = {}", self.params_text(v)),
                if top { vis } else { "local" },
                ret,
                vec![],
                false,
            );
            self.exported = false;
            let cx2 = TCx {
                caller: q,
                caller_line: line(stmt),
                container: Some(name.clone()),
                cls: cx.cls.clone(),
                fields: cx.fields.clone(),
                depth: cx.depth + 1,
            };
            self.visit(v, &cx2, rows);
            return;
        }
        // memo(...), forwardRef(...), useCallback(...)
        if v.kind() == "call_expression" {
            let callee = v.child_by_field_name("function").map(|f| text(f, src)).unwrap_or("");
            let first = v.child_by_field_name("arguments").and_then(|a| {
                named_children(a)
                    .into_iter()
                    .find(|x| matches!(x.kind(), "arrow_function" | "function_expression" | "function"))
            });
            if WRAPPERS.contains(&callee) && first.is_some() && (top || nested_ok) {
                let kind =
                    if name.chars().next().is_some_and(|c| c.is_uppercase()) && top { "component" } else { "function" };
                let cxm = if top {
                    TCx { container: None, ..cx.clone() }
                } else {
                    TCx { container: cx.container.clone().or_else(|| Some(cx.caller.clone())), ..cx.clone() }
                };
                let q = self.member(
                    rows,
                    stmt,
                    &name,
                    kind,
                    &cxm,
                    format!("{name} = {callee}(...)"),
                    if top { vis } else { "local" },
                    String::new(),
                    vec![],
                    false,
                );
                self.exported = false;
                let cx2 = TCx {
                    caller: q,
                    caller_line: line(stmt),
                    container: Some(name.clone()),
                    cls: cx.cls.clone(),
                    fields: cx.fields.clone(),
                    depth: cx.depth + 1,
                };
                self.visit(v, &cx2, rows);
                return;
            }
        }
        // exported object of functions: an API client or a service object
        if v.kind() == "object" && top {
            let q = self.member(
                rows,
                stmt,
                &name,
                "const",
                cx,
                format!("const {name} = {{...}}"),
                vis,
                String::new(),
                vec![],
                false,
            );
            self.exported = false;
            let ocx = TCx {
                caller: q.clone(),
                caller_line: line(stmt),
                container: Some(name.clone()),
                cls: None,
                fields: HashMap::new(),
                depth: cx.depth + 1,
            };
            for p in named_children(v) {
                match p.kind() {
                    "pair" => {
                        let (Some(k), Some(pv)) = (p.child_by_field_name("key"), p.child_by_field_name("value")) else {
                            continue;
                        };
                        let kn = text(k, src).trim_matches(|c| c == '"' || c == '\'').to_string();
                        if matches!(pv.kind(), "arrow_function" | "function_expression" | "function") {
                            let mq = self.member(
                                rows,
                                p,
                                &kn,
                                "method",
                                &ocx,
                                format!("{kn}{}", self.params_text(pv)),
                                "export",
                                String::new(),
                                vec![],
                                false,
                            );
                            let c2 = TCx {
                                caller: mq,
                                caller_line: line(p),
                                container: Some(kn.clone()),
                                depth: ocx.depth + 1,
                                ..ocx.clone()
                            };
                            self.visit(pv, &c2, rows);
                        } else {
                            if matches!(pv.kind(), "identifier" | "member_expression") {
                                self.value_ref(rows, pv, &ocx);
                            }
                            self.visit(pv, &ocx, rows);
                        }
                    }
                    "method_definition" => {
                        let Some(k) = p.child_by_field_name("name") else { continue };
                        let kn = text(k, src).to_string();
                        let mq = self.member(
                            rows,
                            p,
                            &kn,
                            "method",
                            &ocx,
                            format!("{kn}{}", self.params_text(p)),
                            "export",
                            String::new(),
                            vec![],
                            false,
                        );
                        let c2 = TCx {
                            caller: mq,
                            caller_line: line(p),
                            container: Some(kn.clone()),
                            depth: ocx.depth + 1,
                            ..ocx.clone()
                        };
                        for part in ["parameters", "body"] {
                            if let Some(x) = p.child_by_field_name(part) {
                                self.visit(x, &c2, rows);
                            }
                        }
                    }
                    _ => self.visit(p, &ocx, rows),
                }
            }
            return;
        }
        if top {
            let q =
                self.member(rows, stmt, &name, "const", cx, format!("const {name}"), vis, String::new(), vec![], false);
            self.exported = false;
            let cx2 = TCx {
                caller: q,
                caller_line: line(stmt),
                container: None,
                cls: None,
                fields: HashMap::new(),
                depth: cx.depth + 1,
            };
            self.visit(v, &cx2, rows);
        } else {
            self.visit(v, cx, rows);
        }
    }
}

fn ts_type(t: Node, src: &str) -> String {
    let mut out = String::new();
    walk(t, |c| {
        if out.is_empty() && c.kind() == "type_identifier" {
            out = text(c, src).to_string();
        }
        out.is_empty()
    });
    out
}

// ---------------------------------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------------------------------

struct Py<'a> {
    src: &'a str,
    f: &'a SourceFile,
    imports: HashMap<String, (String, String)>,
}

#[derive(Clone, Default)]
struct PCx {
    caller: String,
    caller_line: u32,
    container: Option<String>,
    cls: Option<String>,
    scope: HashMap<String, String>,
    fields: HashMap<String, String>,
    in_func: bool,
}

fn py_file(f: &SourceFile, rows: &mut Rows) {
    let Some(tree) = parse(&python(), &f.text) else { return };
    let mut p = Py { src: &f.text, f, imports: HashMap::new() };
    p.collect_imports(tree.root_node(), rows);
    p.visit(tree.root_node(), &PCx::default(), rows, vec![]);
}

impl Py<'_> {
    fn collect_imports(&mut self, root: Node, rows: &mut Rows) {
        let src = self.src;
        walk(root, |n| {
            match n.kind() {
                "import_statement" => {
                    for c in named_children(n) {
                        let (module, local) = match c.kind() {
                            "dotted_name" => {
                                (text(c, src).to_string(), text(c, src).split('.').next().unwrap_or("").to_string())
                            }
                            "aliased_import" => (
                                c.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default(),
                                c.child_by_field_name("alias").map(|x| text(x, src).to_string()).unwrap_or_default(),
                            ),
                            _ => continue,
                        };
                        // `import a.b` binds `a`; the module for attribute calls is `a`
                        let module = if c.kind() == "dotted_name" { local.clone() } else { module };
                        self.imports.insert(local.clone(), (module.clone(), "*".into()));
                        self.imp_ref(rows, n, &local, &module, &local);
                    }
                    false
                }
                "import_from_statement" => {
                    let module =
                        n.child_by_field_name("module_name").map(|m| text(m, src).to_string()).unwrap_or_default();
                    for c in named_children(n) {
                        if Some(c.id()) == n.child_by_field_name("module_name").map(|m| m.id()) {
                            continue;
                        }
                        match c.kind() {
                            "dotted_name" => {
                                let nm = text(c, src).to_string();
                                self.imports.insert(nm.clone(), (module.clone(), nm.clone()));
                                self.imp_ref(rows, n, &nm, &module, &nm);
                            }
                            "aliased_import" => {
                                let nm =
                                    c.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
                                let al = c
                                    .child_by_field_name("alias")
                                    .map(|x| text(x, src).to_string())
                                    .unwrap_or_else(|| nm.clone());
                                self.imports.insert(al.clone(), (module.clone(), nm.clone()));
                                self.imp_ref(rows, n, &nm, &module, &al);
                            }
                            "wildcard_import" => self.imp_ref(rows, n, "*", &module, "*"),
                            _ => {}
                        }
                    }
                    false
                }
                _ => true,
            }
        });
    }

    fn imp_ref(&self, rows: &mut Rows, n: Node, callee: &str, module: &str, local: &str) {
        rows.refs.push(Ref {
            file: self.f.path.clone(),
            line: line(n),
            caller: String::new(),
            caller_line: 0,
            callee: callee.into(),
            recv: module.into(),
            recv_type: local.into(),
            kind: "import".into(),
            conf: "exact".into(),
            argc: -1,
        });
    }

    fn member(
        &self,
        rows: &mut Rows,
        n: Node,
        name: &str,
        kind: &str,
        cx: &PCx,
        sig: String,
        annos: Vec<String>,
        supers: Vec<String>,
        ret: String,
        start: Node,
    ) -> String {
        let q = match &cx.container {
            Some(c) => format!("{c}.{name}"),
            None => name.to_string(),
        };
        rows.members.push(Member {
            file: self.f.path.clone(),
            line: line(start),
            end_line: end_line(n),
            name: name.to_string(),
            container: cx.container.clone(),
            qname: q.clone(),
            kind: kind.into(),
            sig: trunc(&sig, 200),
            vis: if name.starts_with('_') && !name.starts_with("__") { "private" } else { "public" }.into(),
            annos,
            is_static: false,
            supers,
            ret,
        });
        q
    }

    fn visit(&mut self, n: Node, cx: &PCx, rows: &mut Rows, annos: Vec<String>) {
        let src = self.src;
        match n.kind() {
            "decorated_definition" => {
                let decos: Vec<String> = named_children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "decorator")
                    .map(|c| trunc(text(c, src).trim_start_matches('@'), 80))
                    .collect();
                // a decorator uses what it names: `@cached` (a function as a value), `@router.get(..., dependencies=[Depends(x)])`
                for c in named_children(n).into_iter().filter(|c| c.kind() == "decorator") {
                    for e in named_children(c) {
                        if e.kind() == "call" {
                            self.visit(e, cx, rows, vec![]);
                        } else {
                            self.value_ref(rows, e, cx);
                        }
                    }
                }
                if let Some(d) = n.child_by_field_name("definition") {
                    self.visit_def(d, n, cx, rows, decos);
                }
            }
            "function_definition" | "class_definition" => self.visit_def(n, n, cx, rows, annos),
            "call" => {
                self.call_ref(n, cx, rows);
                // functions passed as values: Depends(get_db), map(fn, xs), callback=handler
                if let Some(args) = n.child_by_field_name("arguments") {
                    for a in named_children(args) {
                        let v = if a.kind() == "keyword_argument" { a.child_by_field_name("value").unwrap_or(a) } else { a };
                        self.value_ref(rows, v, cx);
                    }
                }
                for c in children(n) {
                    self.visit(c, cx, rows, vec![]);
                }
            }
            "expression_statement"
            | "block"
            | "module"
            | "if_statement"
            | "try_statement"
            | "with_statement"
            | "for_statement"
            | "while_statement"
            | "else_clause"
            | "elif_clause"
            | "except_clause"
            | "finally_clause"
            | "match_statement"
            | "case_clause" => {
                for c in children(n) {
                    self.visit(c, cx, rows, vec![]);
                }
            }
            "assignment" => {
                // module / class level constants and fields
                if !cx.in_func {
                    if let Some(l) = n.child_by_field_name("left") {
                        if l.kind() == "identifier" {
                            let nm = text(l, src);
                            if nm.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') {
                                let kind = if cx.cls.is_some() { "field" } else { "const" };
                                if kind == "field"
                                    || nm.chars().all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
                                {
                                    let ret = n
                                        .child_by_field_name("type")
                                        .map(|t| trunc(text(t, src), 30))
                                        .unwrap_or_default();
                                    let q = self.member(
                                        rows,
                                        n,
                                        nm,
                                        kind,
                                        cx,
                                        trunc(text(n, src), 80),
                                        vec![],
                                        vec![],
                                        ret,
                                        n,
                                    );
                                    if let Some(r) = n.child_by_field_name("right") {
                                        let c2 = PCx { caller: q, caller_line: line(n), ..cx.clone() };
                                        self.visit(r, &c2, rows, vec![]);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
                for c in children(n) {
                    self.visit(c, cx, rows, vec![]);
                }
            }
            "type" | "identifier" if false => {}
            _ => {
                for c in children(n) {
                    self.visit(c, cx, rows, vec![]);
                }
            }
        }
    }

    fn visit_def(&mut self, d: Node, outer: Node, cx: &PCx, rows: &mut Rows, annos: Vec<String>) {
        let src = self.src;
        let Some(name) = d.child_by_field_name("name").map(|x| text(x, src).to_string()) else { return };
        if d.kind() == "class_definition" {
            let supers: Vec<String> = d
                .child_by_field_name("superclasses")
                .map(|s| {
                    named_children(s)
                        .into_iter()
                        .filter_map(|c| match c.kind() {
                            "identifier" => Some(text(c, src).to_string()),
                            "attribute" => c.child_by_field_name("attribute").map(|a| text(a, src).to_string()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let q =
                self.member(rows, d, &name, "class", cx, format!("class {name}"), annos, supers, String::new(), outer);
            // self.x = Foo() / self.x: Foo in methods
            let mut fields = HashMap::new();
            if let Some(b) = d.child_by_field_name("body") {
                walk(b, |c| {
                    if c.kind() == "assignment" {
                        if let Some(l) = c.child_by_field_name("left") {
                            if l.kind() == "attribute"
                                && l.child_by_field_name("object").is_some_and(|o| text(o, src) == "self")
                            {
                                let attr = l
                                    .child_by_field_name("attribute")
                                    .map(|a| text(a, src).to_string())
                                    .unwrap_or_default();
                                let ty = c
                                    .child_by_field_name("type")
                                    .map(|t| text(t, src).to_string())
                                    .or_else(|| py_ctor(c.child_by_field_name("right"), src));
                                if let Some(ty) = ty {
                                    fields.insert(attr, ty);
                                }
                            }
                        }
                    }
                    true
                });
            }
            let ccx = PCx {
                caller: q,
                caller_line: line(outer),
                container: Some(name.clone()),
                cls: Some(name.clone()),
                scope: HashMap::new(),
                fields,
                in_func: false,
            };
            if let Some(b) = d.child_by_field_name("body") {
                // class-level statements: members get their own caller; reset caller for plain statements
                let ccx2 = PCx { caller: String::new(), caller_line: 0, ..ccx };
                self.visit(b, &ccx2, rows, vec![]);
            }
            return;
        }
        if cx.in_func && cx.container.is_some() && cx.cls.is_none() && false {
            return;
        }
        let params = d.child_by_field_name("parameters").map(|p| squash(text(p, src))).unwrap_or_else(|| "()".into());
        let ret = d.child_by_field_name("return_type").map(|r| trunc(text(r, src), 40)).unwrap_or_default();
        let kind = if cx.cls.is_some() && !cx.in_func { "method" } else { "function" };
        let q = self.member(
            rows,
            d,
            &name,
            if name == "__init__" { "ctor" } else { kind },
            cx,
            format!("{name}{params}"),
            annos,
            vec![],
            ret,
            outer,
        );
        // scope: annotated params and `x = Foo()` locals
        let mut scope = cx.scope.clone();
        if let Some(ps) = d.child_by_field_name("parameters") {
            for p in named_children(ps) {
                if matches!(p.kind(), "typed_parameter" | "typed_default_parameter") {
                    let nm = p
                        .child_by_field_name("name")
                        .or_else(|| named_children(p).into_iter().find(|c| c.kind() == "identifier"));
                    let ty = p.child_by_field_name("type");
                    if let (Some(nm), Some(ty)) = (nm, ty) {
                        let t = text(ty, src)
                            .trim_matches(|c| c == '"' || c == '\'')
                            .split(['[', '|'])
                            .next()
                            .unwrap_or("")
                            .trim()
                            .rsplit('.')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if !t.is_empty() {
                            scope.insert(text(nm, src).to_string(), t);
                        }
                    }
                }
            }
        }
        if let Some(b) = d.child_by_field_name("body") {
            walk(b, |c| {
                if c.kind() == "assignment" {
                    if let (Some(l), Some(ty)) =
                        (c.child_by_field_name("left"), py_ctor(c.child_by_field_name("right"), src))
                    {
                        if l.kind() == "identifier" {
                            scope.insert(text(l, src).to_string(), ty);
                        }
                    }
                }
                true
            });
        }
        let fcx = PCx {
            caller: q.clone(),
            caller_line: line(outer),
            container: if cx.in_func {
                cx.container.clone()
            } else {
                Some(name.clone()).filter(|_| false).or(cx.container.clone())
            },
            cls: cx.cls.clone(),
            scope,
            fields: cx.fields.clone(),
            in_func: true,
        };
        if let Some(ps) = d.child_by_field_name("parameters") {
            self.visit(ps, &fcx, rows, vec![]);
        }
        if let Some(b) = d.child_by_field_name("body") {
            // nested defs become members named under this function
            let ncx = PCx { container: Some(name.clone()), ..fcx.clone() };
            let _ = ncx;
            self.visit(b, &fcx, rows, vec![]);
        }
    }

    /// A name or `obj.attr` used as a value: a `ref` (resolved only for imports, `self.x`, known receivers and same-file defs).
    fn value_ref(&self, rows: &mut Rows, v: Node, cx: &PCx) {
        let src = self.src;
        let mk = |recv: String, rt: String, callee: &str, exact: bool| Ref {
            file: self.f.path.clone(),
            line: line(v),
            caller: cx.caller.clone(),
            caller_line: cx.caller_line,
            callee: callee.to_string(),
            recv,
            recv_type: rt,
            kind: "ref".into(),
            conf: if exact { "exact" } else { "name" }.into(),
            argc: -1,
        };
        match v.kind() {
            "identifier" => {
                let id = text(v, src);
                if matches!(id, "None" | "True" | "False" | "self" | "cls") {
                    return;
                }
                if let Some((m, o)) = self.imports.get(id) {
                    let callee = if o == "*" { id.to_string() } else { o.clone() };
                    rows.refs.push(mk(String::new(), format!("mod:{m}#{o}"), &callee, true));
                } else {
                    rows.refs.push(mk(String::new(), String::new(), id, false));
                }
            }
            "attribute" => {
                let (Some(obj), Some(attr)) = (v.child_by_field_name("object"), v.child_by_field_name("attribute")) else {
                    return;
                };
                let (rt, known) = self.recv_type_of(obj, cx);
                if known {
                    rows.refs.push(mk(trunc(text(obj, src), 80), rt, text(attr, src), true));
                }
            }
            _ => {}
        }
    }

    /// (receiver type, known) of the object of an attribute access.
    fn recv_type_of(&self, obj: Node, cx: &PCx) -> (String, bool) {
        let src = self.src;
        match obj.kind() {
            "identifier" => {
                let id = text(obj, src);
                if id == "self" || id == "cls" {
                    (cx.cls.clone().unwrap_or_default(), cx.cls.is_some())
                } else if let Some(t) = cx.scope.get(id) {
                    (t.clone(), true)
                } else if let Some((m, o)) = self.imports.get(id) {
                    (format!("mod:{m}#{o}"), true)
                } else if id.chars().next().is_some_and(|c| c.is_uppercase()) {
                    (id.to_string(), true)
                } else {
                    (String::new(), false)
                }
            }
            "attribute" => {
                let o2 = obj.child_by_field_name("object").map(|o| text(o, src)).unwrap_or("");
                let a2 = obj.child_by_field_name("attribute").map(|o| text(o, src)).unwrap_or("");
                if let Some(t) = cx.fields.get(a2).filter(|_| o2 == "self") {
                    return (t.clone(), true);
                }
                // `import a.b` then `a.b.fn()`: the dotted chain names the module
                let chain = text(obj, src);
                let root = chain.split('.').next().unwrap_or("");
                if let Some((m, o)) = self.imports.get(root) {
                    if o == "*" && m == root && chain.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
                        return (format!("mod:{chain}#*"), true);
                    }
                }
                (String::new(), false)
            }
            "call" if obj.child_by_field_name("function").is_some_and(|f| text(f, src) == "super") => {
                (cx.cls.as_ref().map(|c| format!("super:{c}")).unwrap_or_default(), cx.cls.is_some())
            }
            _ => (String::new(), false),
        }
    }

    fn call_ref(&mut self, n: Node, cx: &PCx, rows: &mut Rows) {
        let src = self.src;
        let Some(func) = n.child_by_field_name("function") else { return };
        let argc = n.child_by_field_name("arguments").map(|a| crate::lang::engine::arg_nodes(Some(a)).len() as i32).unwrap_or(-1);
        let first = rows.refs.len();
        let mk = |recv: String, rt: String, callee: &str, exact: bool| Ref {
            file: self.f.path.clone(),
            line: line(n),
            caller: cx.caller.clone(),
            caller_line: cx.caller_line,
            callee: callee.to_string(),
            recv,
            recv_type: rt,
            kind: "call".into(),
            conf: if exact { "exact" } else { "name" }.into(),
            argc: -1,
        };
        match func.kind() {
            "identifier" => {
                let id = text(func, src);
                if let Some((m, o)) = self.imports.get(id) {
                    let callee = if o == "*" { id.to_string() } else { o.clone() };
                    let kind_new = id.chars().next().is_some_and(|c| c.is_uppercase());
                    let mut r = mk(String::new(), format!("mod:{m}#{o}"), &callee, true);
                    if kind_new {
                        r.kind = "new".into();
                    }
                    rows.refs.push(r);
                } else {
                    let mut r = mk(String::new(), String::new(), id, false);
                    if id.chars().next().is_some_and(|c| c.is_uppercase()) {
                        r.kind = "new".into();
                        r.recv_type = id.to_string();
                        r.conf = "exact".into();
                    }
                    rows.refs.push(r);
                }
            }
            "attribute" => {
                let (Some(obj), Some(attr)) =
                    (func.child_by_field_name("object"), func.child_by_field_name("attribute"))
                else {
                    return;
                };
                let an = text(attr, src);
                let recv = trunc(text(obj, src), 80);
                let (rt, known) = self.recv_type_of(obj, cx);
                rows.refs.push(mk(recv, rt, an, known));
            }
            _ => {}
        }
        for r in &mut rows.refs[first..] {
            r.argc = argc;
        }
    }
}

fn py_ctor(right: Option<Node>, src: &str) -> Option<String> {
    let r = right?;
    if r.kind() != "call" {
        return None;
    }
    let f = r.child_by_field_name("function")?;
    let t = match f.kind() {
        "identifier" => text(f, src).to_string(),
        "attribute" => text(f.child_by_field_name("attribute")?, src).to_string(),
        _ => return None,
    };
    t.chars().next().filter(|c| c.is_uppercase()).map(|_| t)
}

// ---------------------------------------------------------------------------------------------------
// Comment / string masking for the flat scan of a too-deep file
// ---------------------------------------------------------------------------------------------------

fn mask_lines(text: &str, ext: &str) -> Vec<String> {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Code,
        Block,
        Raw,
        Str(char),
    }
    let (go, rs) = (ext == "go", ext == "rs");
    let hash = matches!(ext, "rb" | "php");
    let mut st = St::Code;
    let mut out = vec![];
    for line in text.lines() {
        let cs: Vec<char> = line.chars().collect();
        let mut o: Vec<char> = Vec::with_capacity(cs.len());
        let mut i = 0;
        while i < cs.len() {
            let c = cs[i];
            match st {
                St::Block => {
                    if c == '*' && cs.get(i + 1) == Some(&'/') {
                        o.extend([' ', ' ']);
                        i += 2;
                        st = St::Code;
                        continue;
                    }
                    o.push(' ');
                    i += 1;
                }
                St::Raw => {
                    if c == '`' {
                        o.push('`');
                        st = St::Code;
                    } else {
                        o.push(' ');
                    }
                    i += 1;
                }
                St::Str(q) => {
                    if c == '\\' {
                        o.push(' ');
                        if i + 1 < cs.len() {
                            o.push(' ');
                        }
                        i += 2;
                        continue;
                    }
                    if c == q {
                        o.push(q);
                        st = St::Code;
                    } else {
                        o.push(' ');
                    }
                    i += 1;
                }
                St::Code => {
                    if (c == '/' && cs.get(i + 1) == Some(&'/')) || (hash && c == '#') {
                        o.extend(std::iter::repeat(' ').take(cs.len() - i));
                        i = cs.len();
                        continue;
                    }
                    if c == '/' && cs.get(i + 1) == Some(&'*') {
                        o.extend([' ', ' ']);
                        st = St::Block;
                        i += 2;
                        continue;
                    }
                    if c == '`' && go {
                        o.push('`');
                        st = St::Raw;
                        i += 1;
                        continue;
                    }
                    if c == '"' {
                        o.push('"');
                        st = St::Str('"');
                        i += 1;
                        continue;
                    }
                    if c == '\'' {
                        if rs {
                            // a char literal (`'x'`, `'\n'`) or a lifetime (`'a`)
                            if cs.get(i + 1) == Some(&'\\') {
                                let close = (i + 3..cs.len().min(i + 12)).find(|&j| cs[j] == '\'');
                                if let Some(j) = close {
                                    o.extend(std::iter::repeat(' ').take(j + 1 - i));
                                    i = j + 1;
                                    continue;
                                }
                            } else if cs.get(i + 2) == Some(&'\'') {
                                o.extend([' ', ' ', ' ']);
                                i += 3;
                                continue;
                            }
                            o.push(c);
                            i += 1;
                            continue;
                        }
                        o.push('\'');
                        st = St::Str('\'');
                        i += 1;
                        continue;
                    }
                    o.push(c);
                    i += 1;
                }
            }
        }
        if matches!(st, St::Str(_)) {
            st = St::Code; // quoted strings end with their line
        }
        out.push(o.into_iter().collect());
    }
    out
}
