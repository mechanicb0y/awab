//! Embeds every rule file under `<repo>/rules` into the binary at build time,
//! using only the standard library (no `include_dir` crate).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let rules_dir = Path::new(&manifest).join("../../rules");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("builtin_rules.rs");

    let mut entries: Vec<(String, String)> = Vec::new();
    if rules_dir.is_dir() {
        collect(&rules_dir, &rules_dir, &mut entries);
    }
    entries.sort();

    let mut src = String::from("pub static BUILTIN_RULES: &[(&str, &str)] = &[\n");
    for (name, content) in &entries {
        src.push_str(&format!("    ({name:?}, {content:?}),\n"));
    }
    src.push_str("];\n");
    fs::write(&out, src).unwrap();

    println!("cargo:rerun-if-changed={}", rules_dir.display());
    for (_, _) in &entries {}
    // Re-run if any rule file changes.
    emit_rerun(&rules_dir);
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect(root, &p, out);
        } else if is_rule(&p) {
            if let Ok(content) = fs::read_to_string(&p) {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, content));
            }
        }
    }
}

fn is_rule(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

fn emit_rerun(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                emit_rerun(&p);
            } else {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
}
