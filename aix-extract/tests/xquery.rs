//! XQuery / MarkLogic extraction: the lexical scanner skips comments, strings and XML text but reads enclosed
//! expressions; declarations get exact ranges, arity, visibility and annotations; calls carry the namespace their
//! prefix is bound to; REST extensions, rewriters and `xdmp:invoke` come out as endpoints and module edges.
//! Fixtures: `tests/fixtures/lang/xquery` (an ml-gradle style project).

use std::path::{Path, PathBuf};

use aix_extract::codegraph::{Member, Ref};
use aix_extract::{Rows, SourceFile};

const ROOT: &str = "src/main/ml-modules/root";
const UTILS_NS: &str = "http://example.com/utils";
const OTHER_NS: &str = "http://example.com/other";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/lang/xquery")
}

fn run(rel: &str) -> Rows {
    let text = std::fs::read_to_string(fixture().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    aix_extract::extract_file(&fixture(), &aix_extract::all(), &SourceFile::new(rel, text))
}

fn members<'a>(r: &'a Rows, qname: &str) -> Vec<&'a Member> {
    r.members.iter().filter(|m| m.qname == qname).collect()
}

fn calls<'a>(r: &'a Rows, caller: &str, callee: &str) -> Vec<&'a Ref> {
    r.refs.iter().filter(|x| x.caller == caller && x.callee == callee && x.kind != "import").collect()
}

fn eps(r: &Rows) -> Vec<String> {
    let mut v: Vec<String> = r.endpoints.iter().map(|e| format!("{} {} -> {} @{}", e.method, e.path, e.handler, e.line)).collect();
    v.sort();
    v
}

#[test]
fn declarations_ranges_arity_visibility() {
    let r = run(&format!("{ROOT}/lib/utils.xqy"));
    let module = members(&r, "utils.xqy");
    assert_eq!(module.len(), 1);
    assert_eq!((module[0].kind.as_str(), module[0].line, module[0].ret.as_str()), ("module", 1, UTILS_NS));
    assert!(module[0].annos.iter().any(|a| a == "option xdmp:mapping \"false\""), "{:?}", module[0].annos);
    // two arities of one name, each ending at its `};`
    let g = members(&r, "u:greet");
    assert_eq!(g.iter().map(|m| (m.line, m.end_line)).collect::<Vec<_>>(), vec![(17, 20), (22, 25)]);
    assert!(g.iter().all(|m| m.name == "greet" && m.container.as_deref() == Some(UTILS_NS) && m.kind == "function"));
    assert_eq!(g[0].sig, "declare function u:greet($name as xs:string) as xs:string");
    assert_eq!(g[1].sig, "declare function u:greet($name as xs:string, $title as xs:string?) as xs:string");
    let h = members(&r, "u:helper");
    assert_eq!((h[0].line, h[0].end_line, h[0].vis.as_str()), (27, 35, "private"));
    let a = members(&r, "u:apply");
    assert_eq!(a[0].annos, vec!["rest:path(\"/apply\")".to_string()]);
    assert_eq!(a[0].vis, "public");
    // variables are fields
    let v = members(&r, "u:LIMIT");
    assert_eq!((v[0].kind.as_str(), v[0].line, v[0].ret.as_str()), ("field", 13, "xs:integer"));
    assert!(members(&r, "u:CONFIG")[0].sig.ends_with("external"));
    // a declaration inside a nested comment is not one
    assert!(r.members.iter().all(|m| m.name != "fake"), "{:?}", r.members.iter().map(|m| &m.qname).collect::<Vec<_>>());
    // `code file:LINE` reads the symbols: the function around a line, the module outside functions
    assert!(r.symbols.iter().any(|s| s.name == "u:helper" && s.line == 27 && s.end_line == 35 && !s.exported));
}

#[test]
fn calls_skip_comments_strings_and_xml_text() {
    let r = run(&format!("{ROOT}/lib/utils.xqy"));
    // nothing from comments (lines 4, 16), strings (19), XML text / comments / CDATA (30, 32, 33), attribute text (29)
    for l in [4, 16, 19, 30, 32, 33] {
        let at: Vec<&str> = r.refs.iter().filter(|x| x.line == l).map(|x| x.callee.as_str()).collect();
        assert_eq!(at, if l == 19 { vec!["fn:concat"] } else { vec![] }, "line {l}");
    }
    assert!(r.refs.iter().all(|x| x.callee != "bar" && x.callee != "foo:bar"));
    // the overload delegating to the 1-argument one
    let c = calls(&r, "u:greet", "greet");
    assert_eq!(c.iter().map(|x| (x.line, x.argc, x.recv_type.as_str())).collect::<Vec<_>>(), vec![(24, 1, UTILS_NS)]);
    // enclosed expressions inside an attribute value and element content are code
    let c = calls(&r, "u:helper", "greet");
    assert_eq!(c.iter().map(|x| x.line).collect::<Vec<_>>(), vec![29]);
    let c = calls(&r, "u:helper", "shout");
    assert_eq!(c.iter().map(|x| (x.line, x.argc, x.recv_type.as_str(), x.recv.as_str())).collect::<Vec<_>>(), vec![(31, 2, OTHER_NS, "other")]);
    let f = calls(&r, "u:helper", "LIMIT");
    assert_eq!(f.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(), vec!["field"]);
    // `u:greet#1` is a use of the 1-argument function; same-named functions of another module keep their namespace
    let c: Vec<(&str, &str, i32, &str)> = calls(&r, "u:apply", "greet").iter().map(|x| (x.recv.as_str(), x.kind.as_str(), x.argc, x.recv_type.as_str())).collect();
    assert_eq!(c, vec![("u", "ref", 1, UTILS_NS), ("other", "call", 1, OTHER_NS)]);
    // built-ins are library names with their prefix and no namespace
    let lib = r.refs.iter().find(|x| x.callee == "fn:concat").expect("fn:concat");
    assert_eq!((lib.recv_type.as_str(), lib.conf.as_str()), ("", "name"));
    // the import: one ref per location
    let imp: Vec<&Ref> = r.refs.iter().filter(|x| x.kind == "import").collect();
    assert_eq!(imp.iter().map(|x| (x.callee.as_str(), x.recv.as_str(), x.recv_type.as_str())).collect::<Vec<_>>(), vec![(OTHER_NS, "other.xqy", "other")]);
}

#[test]
fn main_module_local_functions_and_invoke() {
    let r = run(&format!("{ROOT}/app/main.xqy"));
    let m = members(&r, "main.xqy");
    assert_eq!((m[0].kind.as_str(), m[0].sig.as_str(), m[0].end_line), ("module", "main module", 14));
    let p = members(&r, "local:page");
    assert_eq!(p[0].container.as_deref(), Some("http://www.w3.org/2005/xquery-local-functions"));
    // the body of a main module belongs to the module member
    let c = calls(&r, "main.xqy", "page");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].caller_line, 1);
    // calls inside a constructor of a local function, to a module imported by an absolute location
    let c = calls(&r, "local:page", "greet");
    assert_eq!(c.iter().map(|x| (x.line, x.argc)).collect::<Vec<_>>(), vec![(7, 2)]);
    // xdmp:invoke / xdmp:spawn with a literal path: an edge to that module; xdmp:eval text is only noted
    let inv: Vec<&Ref> = r.refs.iter().filter(|x| x.recv_type.starts_with("xqmod:")).collect();
    assert_eq!(inv.iter().map(|x| (x.line, x.callee.as_str(), x.recv_type.as_str())).collect::<Vec<_>>(), vec![(10, "job.xqy", "xqmod:/app/job.xqy"), (11, "job.xqy", "xqmod:job.xqy")]);
    assert!(r.notes.iter().any(|n| n.line == 12 && n.kind == "xquery" && n.text.contains("not followed")));
    // an import without a location keeps the namespace (resolved through any module declaring it)
    assert!(r.refs.iter().any(|x| x.kind == "import" && x.callee == OTHER_NS && x.recv.is_empty() && x.recv_type == "o"));
    let c = calls(&r, "main.xqy", "shout");
    assert_eq!(c[0].recv_type, OTHER_NS);
}

#[test]
fn rest_extensions_rewriters_and_sjs() {
    let r = run("src/main/ml-modules/services/hello.xqy");
    assert_eq!(eps(&r), vec!["GET /v1/resources/hello -> hello:get @6", "POST /v1/resources/hello -> hello:post @10"]);
    let r = run("src/main/ml-modules/transforms/stamp.xqy");
    assert!(r.endpoints.is_empty());
    assert!(r.notes.iter().any(|n| n.kind == "marklogic" && n.text.contains("transform 'stamp'")));
    let r = run(&format!("{ROOT}/rewriter.xml"));
    assert_eq!(eps(&r), vec!["ANY /jobs/ -> /app/job.xqy @11", "GET /app/{} -> /app/main.xqy @6", "POST /app/{} -> /app/main.xqy @6"]);
    let r = run(&format!("{ROOT}/url-rewriter.xqy"));
    assert_eq!(eps(&r), vec!["ANY /legacy/{} -> /app/main.xqy @5", "ANY /report/ -> /app/report.xqy @4"]);
    // Server-Side JavaScript: a resource extension, `require` bindings, walked as JavaScript
    let r = run("src/main/ml-modules/services/calc.sjs");
    assert_eq!(eps(&r), vec!["GET /v1/resources/calc -> GET @9"]);
    let imp: Vec<(&str, &str)> = r.refs.iter().filter(|x| x.kind == "import").map(|x| (x.callee.as_str(), x.recv.as_str())).collect();
    assert_eq!(imp, vec![("tools", "/lib/tools.sjs"), ("twice", "/lib/tools.sjs")]);
    let c: Vec<&Ref> = r.refs.iter().filter(|x| x.caller == "get" && x.callee == "twice").collect();
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|x| x.recv_type.starts_with("mod:/lib/tools.sjs#")), "{:?}", c.iter().map(|x| &x.recv_type).collect::<Vec<_>>());
}

#[test]
fn scanner_edge_cases() {
    let src = r#"xquery version "1.0-ml";
module namespace t = "urn:t";
declare function t:a($x) { if ($x <t:b()) then <x a="{t:c(1, 2)}" b='it''s {{t:no()}}'>{t:d()}</x> else $x => t:e(3) };
declare function t:f() { ``[text t:no() `{ t:g() }` more]``, (# pragma t:no() #) "x" };
declare updating function t:u() external;
"#;
    let mut rows = Rows::default();
    aix_extract::lang::xquery::file(&SourceFile::new("t.xqy", src), &mut rows);
    let mut got: Vec<(String, i32)> = rows.refs.iter().filter(|x| x.recv == "t").map(|x| (x.callee.clone(), x.argc)).collect();
    got.sort();
    // `$x <t:b()` is a comparison; `{{` in an attribute is a literal brace; `=>` passes one more argument
    assert_eq!(got, vec![("b".into(), 0), ("c".into(), 2), ("d".into(), 0), ("e".into(), 2), ("g".into(), 0)]);
    let u = rows.members.iter().find(|m| m.name == "u").unwrap();
    assert_eq!((u.line, u.end_line, u.sig.as_str()), (5, 5, "declare updating function t:u()"));
    // truncated and garbled input never panics
    for cut in (0..src.len()).step_by(7) {
        if src.is_char_boundary(cut) {
            let mut r = Rows::default();
            aix_extract::lang::xquery::file(&SourceFile::new("t.xqy", &src[..cut]), &mut r);
        }
    }
    let mut r = Rows::default();
    aix_extract::lang::xquery::file(&SourceFile::new("t.xqy", "<a>{{{(:(:\"'<![CDATA[".repeat(50)), &mut r);
    aix_extract::lang::xquery::file(&SourceFile::new("t.xqy", "<a>".repeat(5000)), &mut r);
    // non-ASCII XML text and names
    let mut r = Rows::default();
    aix_extract::lang::xquery::file(&SourceFile::new("t.xqy", "declare namespace t = \"urn:t\";\n<p>café <!-- é --> { t:z(\"é\") }</p>, t:größe()"), &mut r);
    let got: Vec<&str> = r.refs.iter().filter(|x| x.recv == "t").map(|x| x.callee.as_str()).collect();
    assert_eq!(got, vec!["z", "größe"]);
}
