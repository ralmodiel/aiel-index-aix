//! Row types produced by extractors. Each row belongs to exactly one source file (`file`), so the
//! core engine can drop and re-insert a file's rows when that file changes.

use serde::Serialize;

/// A repo file handed to extractors: the repo-relative path (forward slashes) and its UTF-8 text.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: String,
    pub text: String,
}

impl SourceFile {
    pub fn new(path: impl Into<String>, text: impl Into<String>) -> Self {
        Self { path: path.into(), text: text.into() }
    }
    pub fn ext(&self) -> &str {
        ext_of(&self.path)
    }
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

pub fn ext_of(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(i) if i > 0 => &name[i + 1..],
        _ => "",
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Symbol {
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub name: String,
    /// function | component | class | method | interface | type | const | enum
    pub kind: String,
    pub exported: bool,
    /// Enclosing class for methods.
    pub container: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UiString {
    pub file: String,
    pub line: u32,
    pub text: String,
    /// jsx | prop:<name> | toast | confirm
    pub kind: String,
    /// Enclosing top-level function or component.
    pub component: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Section {
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub level: u8,
    pub heading: String,
    /// Section text up to the next heading (trimmed, capped).
    pub body: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Script {
    pub file: String,
    /// script | regress | audit | check | e2e
    pub kind: String,
    /// Header comment (first lines), redacted.
    pub header: String,
    /// `Usage:` / example lines.
    pub usage: String,
    /// `--flags` the script mentions.
    pub flags: String,
}

/// A backend path a script, test or spec calls (`/api/...`), normalised.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScriptRef {
    pub file: String,
    pub line: u32,
    pub norm_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Task {
    pub file: String,
    pub line: u32,
    /// open | done | dropped
    pub status: String,
    /// DECISION | BLOCKER | Found | task
    pub kind: String,
    /// Leading id like `U12-AB` or `C1`.
    pub round: String,
    /// Commit shas mentioned.
    pub sha: String,
    pub text: String,
    /// Nearest heading above the item.
    pub heading: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Import {
    pub file: String,
    pub line: u32,
    /// Local name bound by the import (default, named, or lazy const).
    pub name: String,
    /// Module specifier as written ("./pages/X", "react").
    pub source: String,
}

/// `obj.member(...)` where `obj` was imported from a local module.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Call {
    pub file: String,
    pub line: u32,
    pub object: String,
    pub member: String,
}

/// A client-side HTTP call: `api.get('/x')` inside `export const xApi = { name: () => ... }`, or a bare
/// `'/api/...'` literal.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ApiCall {
    pub file: String,
    pub line: u32,
    /// Exported client object (e.g. `finalizationApi`), if any.
    pub object: Option<String>,
    /// Property name inside the client object (e.g. `list`), if any.
    pub name: Option<String>,
    /// GET/POST/... or "" when unknown (bare literal).
    pub method: String,
    pub path: String,
    /// Normalised path for joins: `/api/x/{}/y`.
    pub norm_path: String,
}

/// A named constant whose value is a string or string array (role lists, role names).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Const {
    pub file: String,
    pub line: u32,
    /// `NAME` for TS, `Class.NAME` for Java.
    pub name: String,
    /// Resolved strings; unresolved references are kept as `@NAME`.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Route {
    pub file: String,
    pub line: u32,
    pub path: String,
    pub component: Option<String>,
    /// Role names; unresolved references as `@NAME`. Empty = any signed-in user.
    pub roles: Vec<String>,
    /// The role expression as written (`TEACHING`, `[...]`).
    pub role_expr: String,
    /// Feature flag gating the route (`requiredFeature="x"`).
    pub feature: String,
    /// `<Navigate to="x">` target for redirect routes.
    pub redirect: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MenuItem {
    pub file: String,
    pub line: u32,
    /// Exported nav array name (`navigationGroups`).
    pub nav: String,
    pub label: String,
    pub path: String,
    pub group: Option<String>,
    pub keywords: String,
    pub tooltip: String,
    /// `title=key` pairs of in-page tabs.
    pub tabs: Vec<String>,
    pub roles: Vec<String>,
    pub group_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Endpoint {
    pub file: String,
    pub line: u32,
    pub method: String,
    pub path: String,
    pub norm_path: String,
    pub class: String,
    pub handler: String,
    /// Effective roles (method overrides class). `@PermitAll`/`@AnonymousAllowed` -> ["public"]. Unresolved refs kept as written.
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TestCase {
    pub file: String,
    pub line: u32,
    pub id: String,
    pub title: String,
    pub role: String,
    /// Routes visited (`goto`).
    pub routes: Vec<String>,
    /// UI texts the test quotes (expectText, navPresent, click...).
    pub texts: Vec<String>,
}

/// One quoted value inside an e2e step (`goto`, `expectText`, `click.name`, `api.post` ...).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TestStep {
    pub file: String,
    pub line: u32,
    pub sid: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Bug {
    pub file: String,
    pub line: u32,
    /// doc | json | tasks-found | tasks-blocker | commit
    pub kind: String,
    pub date: String,
    pub severity: String,
    /// open | fixed | deferred | rejected | done | reverted | ""
    pub status: String,
    pub round: String,
    pub sha: String,
    pub title: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Feature {
    pub file: String,
    pub line: u32,
    /// menu | tab | help | flow | flag | tip | flag-route
    pub kind: String,
    pub name: String,
    pub route: String,
    pub roles: String,
    pub purpose: String,
    pub extra: String,
}

/// SQL table touched by a migration / SQL file.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DbTable {
    pub file: String,
    pub line: u32,
    pub table: String,
    /// create | alter | drop | insert | update | delete | references | index | create-view ...
    pub op: String,
}

/// Free text worth searching that has no table of its own (learnings, help, page subtitles).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Note {
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub reference: String,
    pub text: String,
}

/// An ORM-mapped class / model / table definition (JPA @Entity, Panache, Spring Data aggregate, SQLAlchemy, Django,
/// Prisma model, TypeORM @Entity, Drizzle table).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EntityDef {
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    /// Class / model / table-variable name.
    pub name: String,
    /// Mapped table ("" for a mapped superclass / embeddable).
    pub table: String,
    /// jpa | panache | sqlalchemy | django | prisma | typeorm | drizzle
    pub orm: String,
    /// Superclass names (for inherited columns).
    pub supers: Vec<String>,
    /// entity | mapped-superclass | embeddable
    pub kind: String,
}

/// One mapped field of an entity.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EntityField {
    pub file: String,
    pub line: u32,
    pub entity: String,
    pub field: String,
    /// Column name ("" for a collection / inverse relation, which has no column).
    pub column: String,
    pub ty: String,
    pub nullable: bool,
    pub transient: bool,
    pub pk: bool,
    /// Target entity for a relation ("" for plain fields).
    pub rel: String,
    /// Extra facts: `unique`, `len 100`, `1:N`, ...
    pub flags: String,
}

/// A schema change from a migration file (SQL, Flyway, Liquibase, Alembic, Rails, Django, Prisma).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Migration {
    pub file: String,
    pub line: u32,
    /// Version as written (`21`, `1.2`, `R` for repeatable, a revision id, a timestamp).
    pub version: String,
    /// flyway | liquibase | alembic | rails | django | prisma | sql
    pub tool: String,
    pub table: String,
    /// create | add | alter | drop
    pub op: String,
    /// table | column | constraint | index | view | function | trigger | data | revision
    pub obj: String,
    pub column: String,
    pub detail: String,
}

/// A foreign key (from a migration, or an entity relation; `to_table` is `entity:<Name>` until resolved).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Fk {
    pub file: String,
    pub line: u32,
    pub from_table: String,
    pub from_col: String,
    pub to_table: String,
    pub to_col: String,
    /// migration | entity
    pub src: String,
}

/// A raw data access fact found in a file; the enclosing member and the entity -> table mapping are resolved
/// in the core after all files are known.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DataRaw {
    pub file: String,
    pub line: u32,
    /// table (target is a table name) | jpql (entity name) | entity (ORM call on an entity) | repo (declaration: target = repository, extra = entity)
    pub kind: String,
    pub target: String,
    /// r | w ("" for a repo declaration)
    pub op: String,
    /// orm | native | jpql | repo
    pub via: String,
    pub extra: String,
}

/// Everything extractors return for a batch of files.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Rows {
    pub symbols: Vec<Symbol>,
    pub ui_strings: Vec<UiString>,
    pub sections: Vec<Section>,
    pub scripts: Vec<Script>,
    pub tasks: Vec<Task>,
    pub imports: Vec<Import>,
    pub calls: Vec<Call>,
    pub api_calls: Vec<ApiCall>,
    pub consts: Vec<Const>,
    pub routes: Vec<Route>,
    pub menu: Vec<MenuItem>,
    pub endpoints: Vec<Endpoint>,
    pub tests: Vec<TestCase>,
    pub test_steps: Vec<TestStep>,
    pub script_refs: Vec<ScriptRef>,
    pub bugs: Vec<Bug>,
    pub features: Vec<Feature>,
    pub db_tables: Vec<DbTable>,
    pub notes: Vec<Note>,
    pub members: Vec<crate::codegraph::Member>,
    pub refs: Vec<crate::codegraph::Ref>,
    pub entities: Vec<EntityDef>,
    pub entity_fields: Vec<EntityField>,
    pub migrations: Vec<Migration>,
    pub fks: Vec<Fk>,
    pub data_raw: Vec<DataRaw>,
}

impl Rows {
    pub fn extend(&mut self, o: Rows) {
        self.symbols.extend(o.symbols);
        self.ui_strings.extend(o.ui_strings);
        self.sections.extend(o.sections);
        self.scripts.extend(o.scripts);
        self.tasks.extend(o.tasks);
        self.imports.extend(o.imports);
        self.calls.extend(o.calls);
        self.api_calls.extend(o.api_calls);
        self.consts.extend(o.consts);
        self.routes.extend(o.routes);
        self.menu.extend(o.menu);
        self.endpoints.extend(o.endpoints);
        self.tests.extend(o.tests);
        self.test_steps.extend(o.test_steps);
        self.script_refs.extend(o.script_refs);
        self.bugs.extend(o.bugs);
        self.features.extend(o.features);
        self.db_tables.extend(o.db_tables);
        self.notes.extend(o.notes);
        self.members.extend(o.members);
        self.refs.extend(o.refs);
        self.entities.extend(o.entities);
        self.entity_fields.extend(o.entity_fields);
        self.migrations.extend(o.migrations);
        self.fks.extend(o.fks);
        self.data_raw.extend(o.data_raw);
    }
    pub fn len(&self) -> usize {
        self.symbols.len()
            + self.ui_strings.len()
            + self.sections.len()
            + self.scripts.len()
            + self.tasks.len()
            + self.imports.len()
            + self.calls.len()
            + self.api_calls.len()
            + self.consts.len()
            + self.routes.len()
            + self.menu.len()
            + self.endpoints.len()
            + self.tests.len()
            + self.test_steps.len()
            + self.script_refs.len()
            + self.bugs.len()
            + self.features.len()
            + self.db_tables.len()
            + self.notes.len()
            + self.members.len()
            + self.refs.len()
            + self.entities.len()
            + self.entity_fields.len()
            + self.migrations.len()
            + self.fks.len()
            + self.data_raw.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Normalise an HTTP path for joins: strip query and trailing slash, collapse `${x}`, `{x}`, `{x: re}`
/// and `:x` segments to `{}`.
/// A path segment that is a literal id: all digits, or a UUID.
fn is_id_segment(seg: &str) -> bool {
    if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let b = seg.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

pub fn norm_path(p: &str) -> String {
    let p = p.split('?').next().unwrap_or("");
    let mut out = String::new();
    for seg in p.split('/') {
        if seg.is_empty() {
            continue;
        }
        out.push('/');
        // `${x}` / `{x}` / `:x` placeholders, and printf-style `%s`/`%d` and f-string `{x}` inside a segment
        // and literal ids in a client call (`/jax/5`, `/jax/3fa85f64-5717-4562-b3fc-2c963f66afa6`)
        if seg.contains("${") || seg.contains('{') || seg.starts_with(':') || seg.contains('%') || is_id_segment(seg) {
            out.push_str("{}");
        } else {
            out.push_str(seg);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn norm() {
        assert_eq!(norm_path("/api/x/${id}/y?z=1"), "/api/x/{}/y");
        assert_eq!(norm_path("/api/x/{id: [0-9]+}/"), "/api/x/{}");
        assert_eq!(norm_path("users/:id"), "/users/{}");
        assert_eq!(ext_of("a/b.test.tsx"), "tsx");
        assert_eq!(ext_of("a/.env"), "");
    }
}
