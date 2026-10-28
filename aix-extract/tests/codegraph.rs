//! Code graph extractor tests: Java / TypeScript / Python members and refs (receiver types, overloads, inner
//! classes, private methods, import bindings, JSX, hooks) on the fixtures under `tests/fixtures/codegraph`.

use std::path::{Path, PathBuf};

use aix_extract::codegraph::{CodeGraph, Member, Ref};
use aix_extract::{Extractor, Rows, SourceFile};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/codegraph")
}

fn run(rel: &str) -> Rows {
    let text = std::fs::read_to_string(fixture().join(rel)).unwrap();
    CodeGraph.extract(&fixture(), &[SourceFile::new(rel, text)])
}

fn member<'a>(r: &'a Rows, q: &str) -> Vec<&'a Member> {
    r.members.iter().filter(|m| m.qname == q).collect()
}

fn refs<'a>(r: &'a Rows, caller: &str, callee: &str) -> Vec<&'a Ref> {
    r.refs.iter().filter(|x| x.caller == caller && x.callee == callee).collect()
}

#[test]
fn java_members() {
    let r = run("java/OrderService.java");
    let cls = &member(&r, "OrderService")[0];
    assert_eq!((cls.kind.as_str(), cls.vis.as_str()), ("class", "public"));
    assert_eq!(cls.supers, vec!["BaseService", "Auditable"]);
    assert!(cls.annos.iter().any(|a| a == "ApplicationScoped"));
    // overloads: two members, distinct line ranges
    let places = member(&r, "OrderService.place");
    assert_eq!(places.len(), 2);
    assert_ne!(places[0].line, places[1].line);
    assert!(places[0].sig.contains("place(String customer, int qty)"), "{}", places[0].sig);
    assert!(places[0].annos.iter().any(|a| a == "Transactional"));
    assert_eq!(places[0].line, 15, "line includes the annotation");
    // private method, static package-private method, constructor, fields
    assert_eq!(member(&r, "OrderService.finish")[0].vis, "private");
    let h = &member(&r, "OrderService.helper")[0];
    assert!(h.is_static && h.vis == "package");
    assert_eq!(member(&r, "OrderService.OrderService")[0].kind, "ctor");
    assert_eq!(member(&r, "OrderService.calc")[0].kind, "field");
    assert_eq!(member(&r, "OrderService.calc")[0].ret, "PriceCalculator");
    // inner class and its members
    let inner = &member(&r, "OrderService.Receipt")[0];
    assert_eq!((inner.kind.as_str(), inner.container.as_deref()), ("class", Some("OrderService")));
    assert_eq!(member(&r, "OrderService.Receipt.render")[0].container.as_deref(), Some("Receipt"));
    assert_eq!(member(&r, "OrderService.Receipt.amount")[0].kind, "field");
}

#[test]
fn java_receivers() {
    let r = run("java/OrderService.java");
    let c = "OrderService.place";
    // injected field, local typed by `new`, unqualified (this class), Panache instance call
    assert!(refs(&r, c, "total").iter().any(|x| x.kind == "call" && x.recv_type == "PriceCalculator"));
    // `o.total` is a field use of Order, not a call
    assert!(refs(&r, c, "total").iter().any(|x| x.kind == "field" && x.recv_type == "Order"));
    assert_eq!(refs(&r, c, "persist")[0].recv_type, "Order");
    assert_eq!(refs(&r, c, "audit")[0].recv_type, "OrderService");
    assert_eq!(refs(&r, c, "finish")[0].recv_type, "OrderService");
    let new_order = refs(&r, c, "Order");
    assert!(new_order.iter().any(|x| x.kind == "new" && x.recv_type == "Order"));
    // constructor-injected final field, Panache static, Class.static
    assert_eq!(refs(&r, "OrderService.finish", "save")[0].recv_type, "OrderRepository");
    assert_eq!(refs(&r, "OrderService.finish", "find")[0].recv_type, "Order");
    assert_eq!(refs(&r, "OrderService.helper", "clamp")[0].recv_type, "Util");
    // inner class calls the outer's static helper unqualified; the receiver is the inner class
    assert_eq!(refs(&r, "OrderService.Receipt.render", "helper")[0].recv_type, "Receipt");
    // overload delegation is a call to `place` from the one-arg overload
    assert!(r.refs.iter().any(|x| x.caller == c && x.callee == "place" && x.line == 25 && x.caller_line == 24));
    // imports are refs too
    assert!(r.refs.iter().any(|x| x.kind == "import" && x.callee == "Inject"));
}

#[test]
fn typescript_members_and_bindings() {
    let api = run("web/api.ts");
    assert_eq!(member(&api, "ordersApi")[0].kind, "const");
    let list = &member(&api, "ordersApi.list")[0];
    assert_eq!((list.kind.as_str(), list.container.as_deref()), ("method", Some("ordersApi")));
    assert_eq!(member(&api, "formatMoney")[0].kind, "function");
    assert!(refs(&api, "ordersApi.list", "get").iter().any(|x| x.recv == "http" && x.recv_type == "mod:./http#http"));

    let o = run("web/Orders.tsx");
    let comp = &member(&o, "Orders")[0];
    assert_eq!(comp.kind, "component");
    // nested arrow function and function declaration inside the component
    assert_eq!(member(&o, "Orders.load")[0].kind, "function");
    assert_eq!(member(&o, "Orders.cancel")[0].kind, "function");
    // import binding: object member, aliased named import, JSX component (default import), hook
    assert_eq!(refs(&o, "Orders.load", "list")[0].recv_type, "mod:./api#ordersApi");
    assert_eq!(refs(&o, "Orders.cancel", "cancel")[0].recv_type, "mod:./api#ordersApi");
    let fm = refs(&o, "Orders.cancel", "formatMoney");
    assert_eq!(fm[0].recv_type, "mod:./api#formatMoney", "alias maps back to the exported name");
    let jsx = refs(&o, "Orders", "OrderRow");
    assert!(jsx.iter().any(|x| x.kind == "jsx" && x.recv_type == "mod:./OrderRow#default"));
    assert!(refs(&o, "Orders", "useState").iter().any(|x| x.recv_type == "mod:react#useState"));
    // class with a constructor parameter property: `this.api.fetchAll()` gets the field type
    assert_eq!(refs(&o, "Store.refresh", "fetchAll")[0].recv_type, "Client");
}

#[test]
fn python_members_and_receivers() {
    let r = run("py/service.py");
    assert_eq!(member(&r, "Service")[0].supers, vec!["Base"]);
    assert_eq!(member(&r, "Service.run")[0].kind, "method");
    assert_eq!(member(&r, "Service.__init__")[0].kind, "ctor");
    assert_eq!(member(&r, "Service._build")[0].vis, "private");
    assert_eq!(member(&r, "main")[0].kind, "function");
    // self.x = Repo() types the field; self.method -> own class; local `x = Foo()` types the local
    assert_eq!(refs(&r, "Service.run", "save")[0].recv_type, "Repo");
    assert_eq!(refs(&r, "Service.run", "_build")[0].recv_type, "Service");
    assert_eq!(refs(&r, "Service._build", "make")[0].recv_type, "Helper");
    // from-import bindings
    assert_eq!(refs(&r, "Service.run", "slugify")[0].recv_type, "mod:util#slugify");
    assert!(r.refs.iter().any(|x| x.kind == "new" && x.callee == "Repo" && x.recv_type == "mod:.repo#Repo"));
}

#[test]
fn name_only_fallback() {
    let go = "package x\n\ntype Svc struct{}\n\nfunc (s *Svc) Run(n int) {\n\ts.helper(n)\n\tLog(n)\n}\n\nfunc (s *Svc) helper(n int) {}\n";
    let r = CodeGraph.extract(Path::new("."), &[SourceFile::new("x/svc.go", go)]);
    assert_eq!(member(&r, "Svc.Run")[0].kind, "method");
    assert_eq!((member(&r, "Svc.Run")[0].line, member(&r, "Svc.Run")[0].end_line), (5, 8));
    assert_eq!(refs(&r, "Svc.Run", "helper")[0].recv_type, "Svc");
    assert!(refs(&r, "Svc.Run", "Log").iter().all(|x| x.recv_type.is_empty()));
}

#[test]
fn java_varargs_sig_comment_args_and_rust_macro_paths() {
    let src = "class A {\n  void va(boolean f, String... also) {}\n  void c(A p) {\n    p.va(true, // why\n      \"x\");\n  }\n}\n";
    let r = CodeGraph.extract(&fixture(), &[SourceFile::new("j/A.java", src)]);
    assert!(member(&r, "A.va")[0].sig.contains("String... also"), "{}", member(&r, "A.va")[0].sig);
    assert_eq!(refs(&r, "A.c", "va")[0].argc, 2, "a comment is not an argument");
    let rs = "mod util { pub fn h(x: i32) -> i32 { x } }\nfn user() { println!(\"{}\", util::h(2)); }\n";
    let r = CodeGraph.extract(&fixture(), &[SourceFile::new("r/lib.rs", rs)]);
    let h: Vec<_> = r.refs.iter().filter(|x| x.callee == "h").collect();
    assert!(!h.is_empty() && h.iter().all(|x| x.recv.is_empty()), "{h:?}");
}
