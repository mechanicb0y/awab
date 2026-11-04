//! Reading inputs: files, directories (recursively), and stdin. Std-only.

use std::io::Read;
use std::path::Path;

pub struct Source {
    pub name: String,
    pub text: String,
}

/// Resolve the given targets into readable text sources. An empty target list
/// means "read stdin".
pub fn collect_sources(targets: &[String]) -> Result<Vec<Source>, String> {
    let mut out = Vec::new();
    if targets.is_empty() {
        read_stdin(&mut out)?;
        return Ok(out);
    }
    for t in targets {
        if t == "-" {
            read_stdin(&mut out)?;
            continue;
        }
        let path = Path::new(t);
        if path.is_dir() {
            read_dir(path, &mut out);
        } else {
            let text = std::fs::read_to_string(path).map_err(|e| read_error(t, &e))?;
            out.push(Source {
                name: t.clone(),
                text,
            });
        }
    }
    Ok(out)
}

/// Turn a file read error into a helpful message. On systemd distros the
/// classic log files often don't exist (logs live in the journal), so point the
/// user at journalctl instead of a bare "not found".
fn read_error(target: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        let looks_like_syslog = target.starts_with("/var/log")
            && !target.ends_with("audit.log")
            && !target.contains("nginx")
            && !target.contains("apache")
            && !target.contains("access");
        if looks_like_syslog {
            return format!(
                "{target}: no such file.\n\
                 On systemd-based distros (Kali, modern Debian/Ubuntu) this log often\n\
                 doesn't exist — the logs live in the journal. Try:\n\
                 \x20 journalctl -o short-iso | awab scan -"
            );
        }
        return format!("{target}: no such file");
    }
    format!("reading {target}: {e}")
}

fn read_stdin(out: &mut Vec<Source>) -> Result<(), String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("reading stdin: {e}"))?;
    if !buf.trim().is_empty() {
        out.push(Source {
            name: "<stdin>".to_string(),
            text: buf,
        });
    }
    Ok(())
}

/// Recursively read every UTF-8 text file under a directory, skipping anything
/// that isn't valid UTF-8 (compressed/binary/rotated files).
fn read_dir(dir: &Path, out: &mut Vec<Source>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            read_dir(&p, out);
        } else if let Ok(text) = std::fs::read_to_string(&p) {
            if !text.trim().is_empty() {
                out.push(Source {
                    name: p.display().to_string(),
                    text,
                });
            }
        }
    }
}
