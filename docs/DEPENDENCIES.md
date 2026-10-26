# Dependencies

Every dependency is pinned to an exact version in `Cargo.toml` and built with `--locked`. A new crate is accepted only
if it is widely used, maintained (by the tree-sitter organisation or the language community), MIT or Apache-2.0,
compatible with the `tree-sitter` version in `Cargo.lock`, and has no open advisory in the RustSec database
(checked against `github.com/rustsec/advisory-db`: none of the grammar crates below has an entry).

## Language grammars (tree-sitter)

All grammars are MIT licensed, share the `tree-sitter-language` ABI crate, and run on `tree-sitter` 0.27.

| Crate | Version | Why |
|---|---|---|
| `tree-sitter-typescript` | 0.23.2 | TypeScript / TSX / JavaScript, Vue and Svelte script blocks |
| `tree-sitter-java` | 0.23.5 | Java |
| `tree-sitter-python` | 0.25.0 | Python |
| `tree-sitter-bash` | 0.25.1 | shell scripts |
| `tree-sitter-go` | 0.25.0 | Go code graph (replaces the line scanner) |
| `tree-sitter-rust` | 0.24.2 | Rust code graph |
| `tree-sitter-kotlin-ng` | 1.1.0 | Kotlin code graph (the older `tree-sitter-kotlin` needs `tree-sitter` < 0.23) |
| `tree-sitter-c-sharp` | 0.23.5 | C# code graph |
| `tree-sitter-php` | 0.25.1 | PHP code graph |
| `tree-sitter-ruby` | 0.23.1 | Ruby code graph |
| `tree-sitter-swift` | 0.7.4 | Swift symbols |
| `tree-sitter-scala` | 0.26.3 | Scala symbols |
| `tree-sitter-c` | 0.24.2 | C symbols |
| `tree-sitter-cpp` | 0.23.4 | C++ symbols |
| `tree-sitter-dart` | 0.2.0 | Dart symbols (community grammar) |
| `tree-sitter-lua` | 0.5.0 | Lua symbols |

Known grammar limits: Kotlin `fun interface` is rewritten before parsing (the grammar does not know it); a one-line
`enum class E { A, B; fun f() = 1 }` and an abstract `fun` followed by `}` on the same line before an `enum` fail to
parse in the Kotlin grammar (the rest of that file is lost; normal formatting is fine). Template files (Jinja, Twig,
ERB, Blade, Thymeleaf, Go templates) and Vue / Svelte templates are read with regular expressions, not a grammar.
XQuery has no maintained tree-sitter grammar on crates.io: `aix-extract/src/lang/xquery.rs` is a lexical scanner of
our own (no crate added). It skips `(: :)` comments, strings, pragmas and XML text, reads enclosed expressions, and
does not follow the code inside `xdmp:eval` strings or functions looked up at run time (`xdmp:function`, `$f()`).

## Other crates

`anyhow`, `regex`, `sha1_smol`, `toml`, `blake3`, `clap`, `ignore`, `rayon`, `rusqlite` (bundled SQLite), `serde`,
`serde_json`, `ureq`, `rmcp`, `tokio`, `schemars`, `tempfile`: see `Cargo.toml` for the pinned versions.

## Crypto (literal masks)

| Crate | Used for | Why this one |
|---|---|---|
| `pbkdf2` 0.12 (feature `hmac`) | the slow salted fingerprint of literal masks (`aix mask add --literal`): PBKDF2-HMAC-SHA256, 600000 iterations (OWASP 2023), stored per mask | RustCrypto, MIT/Apache-2.0, small, widely used and audited primitives; no unsafe KDF code of our own |
| `sha2` 0.10 | SHA-256 for the above | RustCrypto |
| `hmac` 0.12 | HMAC for the above | RustCrypto |

`AIX_MASK_KDF_ITERS` lowers the iteration count when a mask is added (never below 1000); it exists for tests, and the count in force is stored with each mask.
