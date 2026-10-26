// Every markdown file shipped to Claude Code (skills, slash commands) must have a front matter Claude Code can parse:
// an unquoted `description:` containing ": " is a YAML mapping error ("mapping values are not allowed in this context").
use std::path::Path;

fn md_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            md_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

#[test]
fn shipped_markdown_front_matter_is_valid_yaml_scalars() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../integrations");
    let mut files = vec![];
    md_files(&root, &mut files);
    let mut checked = 0;
    for f in files {
        // a CRLF checkout (Git for Windows' default) has the same front matter
        let t = std::fs::read_to_string(&f).unwrap().replace("\r\n", "\n");
        let Some(rest) = t.strip_prefix("---\n") else { continue };
        let head = rest.split("\n---").next().unwrap();
        for line in head.lines() {
            let Some((key, val)) = line.split_once(':') else { continue };
            if key.starts_with(' ') || key.starts_with('-') {
                continue;
            }
            let v = val.trim();
            let quoted = v.starts_with('\'') || v.starts_with('"') || v.starts_with('|') || v.starts_with('>');
            assert!(
                quoted || !(v.contains(": ") || v.contains(" #")),
                "{}: `{key}:` value needs quotes (contains ': ' or ' #'): {v:.80}",
                f.display()
            );
            if v.starts_with('\'') {
                assert!(v.ends_with('\'') && !v[1..v.len() - 1].replace("''", "").contains('\''), "{}: bad single-quoted `{key}`", f.display());
            }
            checked += 1;
        }
    }
    assert!(checked >= 2, "no front matter found under integrations/");
}
