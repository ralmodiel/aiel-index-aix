//! Tree-sitter code-graph extractors for the languages beyond Java / TypeScript / Python.
//!
//! One shared walker ([`engine`]) turns a syntax tree into `Member` and `Ref` rows; each language is a small module
//! implementing [`Lang`] (what a type, function, field, call, import and local variable look like in its grammar).
//! Full support (members with ranges, imports, calls with receiver types, functions used as values, argument counts):
//! Go, Rust, Kotlin, C#, PHP, Ruby. Symbol level (members, imports, name-level calls with `this`/static receivers):
//! Swift, Scala, C, C++, Dart, Lua. Vue / Svelte single-file components hand their `<script>` blocks to the
//! TypeScript extractor ([`sfc`]). XQuery has no grammar crate: [`xquery`] is a lexical scanner producing the same rows.

use tree_sitter::{Language, Node};

use crate::model::*;

pub mod c;
pub mod csharp;
pub mod dart;
pub mod engine;
pub mod go;
pub mod kotlin;
pub mod lua;
pub mod php;
pub mod ruby;
pub mod rust;
pub mod scala;
pub mod sfc;
pub mod swift;
pub mod templates;
pub mod xquery;

/// What a syntax node declares.
pub enum Role {
    /// class / struct / interface / enum / trait / object / module: gets a member and becomes the container of what is inside.
    Type,
    /// function / method / constructor: gets a member; its body is walked for calls.
    Func,
    /// field / property / constant: gets a member (its type feeds receiver typing).
    Field,
    /// `impl X` / `extension X`: no member, but what is inside belongs to `X`.
    Wrapper,
}

/// One declaration found at a node.
pub struct Decl<'t> {
    pub role: Role,
    pub name: String,
    /// class | interface | enum | record | method | ctor | field | function | const | type
    pub kind: &'static str,
    /// Node whose first line is the member's first line (attributes / annotations included).
    pub start: Node<'t>,
    pub node: Node<'t>,
    pub sig: String,
    pub vis: String,
    pub annos: Vec<String>,
    pub is_static: bool,
    pub supers: Vec<String>,
    /// Return type (functions) or declared type (fields), simple name.
    pub ret: String,
    /// Enclosing type when the grammar declares it away from the type (Go receiver, Rust `impl`).
    pub container: Option<String>,
    /// Receiver variable that means "this class" (Go `s` in `func (s *T) m()`).
    pub this_var: Option<String>,
    /// Parameter (name, simple type name) pairs: they type the receivers used in the body.
    pub params: Vec<(String, String)>,
    /// Nodes to visit next (body, members, initialisers).
    pub walk: Vec<Node<'t>>,
    /// Declared type as written (`*store.DB`), when the engine should type receivers from it (Go qualifies it by import).
    pub ty_raw: String,
    /// Typing only: no member row (Go struct fields and package variables stay out of outlines, as before).
    pub hidden: bool,
}

impl<'t> Decl<'t> {
    pub fn new(role: Role, name: impl Into<String>, kind: &'static str, node: Node<'t>) -> Self {
        Decl {
            role,
            name: name.into(),
            kind,
            start: node,
            node,
            sig: String::new(),
            vis: "public".into(),
            annos: vec![],
            is_static: false,
            supers: vec![],
            ret: String::new(),
            container: None,
            this_var: None,
            params: vec![],
            walk: vec![],
            ty_raw: String::new(),
            hidden: false,
        }
    }
}

/// A call-like use found at a node.
pub struct Call<'t> {
    pub callee: String,
    /// Receiver expression (`x` in `x.f()`), None for a bare call.
    pub recv: Option<Node<'t>>,
    /// Receiver written as a type path (`Foo::bar()` / `Foo.bar()`), already known to be a type name.
    pub static_type: Option<String>,
    /// call | new
    pub kind: &'static str,
    pub argc: i32,
    /// Argument expressions (for functions passed as values).
    pub args: Vec<Node<'t>>,
}

/// A call found inside a macro's token tree (or a macro use itself).
pub struct HiddenCall {
    pub line: u32,
    pub callee: String,
    /// Receiver text (a path prefix or empty).
    pub recv: String,
    /// Receiver written as a type path.
    pub static_type: Option<String>,
    /// A function named as a value (a bare identifier argument of a user macro: `ext_impl!(T, "t", h, handler)`),
    /// not a call written out: kept as a `ref`, and only when it names a function of the same file.
    pub value: bool,
}

/// How an expression is spelled, for receiver typing.
pub enum Expr<'t> {
    /// A plain name (local, parameter, field of this, or a type when capitalised).
    Ident(String),
    /// `this` / `self` / `$this` / `Self`.
    This,
    /// `object.field`.
    Member(Node<'t>, String),
    /// Something we cannot type.
    Other,
}

pub struct ImportRow {
    pub line: u32,
    /// Imported name (`*` for a whole module or wildcard).
    pub callee: String,
    /// Module path as written.
    pub module: String,
    /// Local name bound.
    pub local: String,
}

/// Where a local variable gets its type from.
pub enum TypeSrc<'t> {
    /// A declared type text.
    Declared(String),
    /// An initialiser expression (`Foo::new()`, `new Foo()`, `&T{}`).
    Init(Node<'t>),
}

pub trait Lang: Sync {
    fn language(&self) -> Language;
    /// Language tag used by the walker for visibility and keyword decisions.
    fn tag(&self) -> &'static str;
    /// Declarations at this node (usually 0 or 1; a field line can declare several names).
    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>>;
    /// Is this node a call (or `new`) expression?
    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>>;
    fn imports(&self, _n: Node, _src: &str) -> Vec<ImportRow> {
        vec![]
    }
    /// Local variables bound at this node.
    fn locals<'t>(&self, _n: Node<'t>, _src: &str) -> Vec<(String, TypeSrc<'t>)> {
        vec![]
    }
    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t>;
    /// Type of an initialiser / expression that constructs a value: `new Foo()` -> Foo; "" when unknown.
    fn init_type(&self, _n: Node, _src: &str) -> String {
        String::new()
    }
    /// Call-like uses the grammar hides in unparsed token trees (Rust macro arguments); each is a name-level `call`.
    fn hidden_calls(&self, _n: Node, _src: &str) -> Vec<HiddenCall> {
        vec![]
    }
    /// A closure / function literal: its parameters (name, declared type) shadow outer bindings inside it only.
    fn closure_params(&self, _n: Node, _src: &str) -> Option<Vec<(String, String)>> {
        None
    }
    /// Rewrites source the grammar cannot parse into same-length source it can (offsets and lines must not move).
    fn preprocess(&self, _text: &str) -> Option<String> {
        None
    }
    /// Container names that have no type declaration of their own (Lua tables) get a synthetic `class` member.
    fn synthesize_containers(&self) -> bool {
        false
    }
    /// Does a bare capitalised name denote a type (so `Foo.bar()` is a static call)?
    fn caps_are_types(&self) -> bool {
        true
    }
    /// Are bare calls inside a type implicitly on `this`? (Kotlin, C#, Scala, Ruby, Swift, Dart: yes.)
    fn full(&self) -> bool {
        true
    }
}

pub fn for_ext(ext: &str) -> Option<&'static dyn Lang> {
    Some(match ext {
        "go" => &go::Go,
        "rs" => &rust::Rust,
        "kt" | "kts" => &kotlin::Kotlin,
        "cs" => &csharp::CSharp,
        "php" => &php::Php,
        "rb" | "rake" => &ruby::Ruby,
        "swift" => &swift::Swift,
        "scala" | "sc" => &scala::Scala,
        "c" | "h" => &c::C,
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => &c::Cpp,
        "dart" => &dart::Dart,
        "lua" => &lua::Lua,
        _ => return None,
    })
}

/// Extensions handled here (the graph extractor's `handles`).
pub const EXTS: &[&str] = &[
    "go", "rs", "kt", "kts", "cs", "php", "rb", "rake", "swift", "scala", "sc", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx",
    "dart", "lua", "vue", "svelte", "xqy", "xq", "xqm", "xql", "xquery", "xqe",
];

/// Rows of one source file in one of these languages (Vue / Svelte go through their script blocks).
pub fn file(f: &SourceFile, rows: &mut Rows) {
    match f.ext() {
        "vue" | "svelte" => sfc::file(f, rows),
        e if xquery::EXTS.contains(&e) => xquery::file(f, rows),
        // a `.h` is C++ when it says so (namespaces, templates, classes, `::`)
        "h" if f.text.contains("namespace ") || f.text.contains("template <") || f.text.contains("template<") || f.text.contains("class ") || f.text.contains("::") => engine::run(&c::Cpp, f, rows),
        e => {
            if let Some(l) = for_ext(e) {
                engine::run(l, f, rows);
            }
        }
    }
}

/// Declarations of a file whose syntax tree was too deep to walk: one member per declaration line, each running to
/// the next declaration (no calls). Comment lines are skipped.
pub fn flat_scan(f: &SourceFile, rows: &mut Rows) {
    use std::sync::LazyLock;
    static FN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s*(?:(?:pub(?:\([^)]*\))?|public|private|protected|internal|static|async|suspend|open|override|abstract|final|extern|unsafe|const|inline)\s+)*(func|fn|fun|def|function)\s+(?:\([^)]*\)\s*)?(?:self\.)?([A-Za-z_]\w*)").unwrap()
    });
    static TY: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\s*(?:(?:pub(?:\([^)]*\))?|public|private|protected|internal|static|final|open|abstract|sealed|data|partial|readonly)\s+)*(class|struct|interface|trait|enum|object|module|record|protocol|actor|type)\s+([A-Za-z_]\w*)").unwrap()
    });
    let lines: Vec<&str> = f.text.lines().collect();
    let mut found: Vec<(usize, String, &str)> = vec![];
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') || t.starts_with("--") {
            continue;
        }
        if let Some(c) = FN.captures(l) {
            found.push((i, c[2].to_string(), "function"));
        } else if let Some(c) = TY.captures(l) {
            found.push((i, c[2].to_string(), if &c[1] == "interface" || &c[1] == "trait" || &c[1] == "protocol" { "interface" } else { "class" }));
        }
    }
    for (k, (i, name, kind)) in found.iter().enumerate() {
        let end = found.get(k + 1).map(|x| x.0).unwrap_or(lines.len()).max(i + 1);
        rows.members.push(crate::codegraph::Member {
            file: f.path.clone(),
            line: *i as u32 + 1,
            end_line: end as u32,
            name: name.clone(),
            container: None,
            qname: name.clone(),
            kind: (*kind).into(),
            sig: lines[*i].trim().chars().take(160).collect(),
            vis: "public".into(),
            annos: vec![],
            is_static: false,
            supers: vec![],
            ret: String::new(),
        });
    }
}
