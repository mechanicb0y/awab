//! Parser for Linux Audit daemon logs (`/var/log/audit/audit.log`).
//!
//! Handles the record types most useful for triage: EXECVE (reconstructs the
//! full command line), SYSCALL (exe / comm / audit key / uid), and the USER_*
//! authentication records. Standard library only.

use crate::event::Event;
use crate::util::format_utc;

/// Heuristic: an auditd line starts with `type=` and carries `msg=audit(`.
pub fn looks_like(line: &str) -> bool {
    line.starts_with("type=") && line.contains("msg=audit(")
}

pub fn parse_line(line: &str, line_no: usize, source: Option<&str>) -> Option<Event> {
    let mut ev = Event {
        parser: "auditd",
        raw: line.to_string(),
        message: line.to_string(),
        line_no,
        source: source.map(|s| s.to_string()),
        ..Default::default()
    };

    let rtype = field(line, "type=").unwrap_or_default();
    if !rtype.is_empty() {
        ev.set("audit_type", &rtype);
    }

    // Timestamp: msg=audit(<epoch>.<ms>:<serial>)
    if let Some(i) = line.find("msg=audit(") {
        let rest = &line[i + "msg=audit(".len()..];
        if let Some(secs) = rest
            .split(['.', ':'])
            .next()
            .and_then(|s| s.parse::<i64>().ok())
        {
            ev.timestamp = Some(secs);
            ev.ts_raw = Some(format_utc(secs));
        }
    }

    match rtype.as_str() {
        "EXECVE" => {
            let mut args: Vec<String> = Vec::new();
            for i in 0..64 {
                match exec_arg(line, i) {
                    Some(a) => args.push(a),
                    None => break,
                }
            }
            if !args.is_empty() {
                ev.set("event_type", "exec");
                ev.set("service", "auditd");
                ev.set("command_bin", args[0].clone());
                ev.set("command", args.join(" "));
            }
        }
        "SYSCALL" => {
            ev.set("event_type", "syscall");
            if let Some(exe) = field(line, "exe=") {
                ev.set("exe", &exe);
                ev.set("command_bin", &exe);
            }
            if let Some(comm) = field(line, "comm=") {
                ev.set("comm", comm);
            }
            if let Some(key) = field(line, "key=") {
                if key != "(null)" {
                    ev.set("audit_key", key);
                }
            }
            if let Some(uid) = field(line, "uid=") {
                ev.set("uid", uid);
            }
            if let Some(auid) = field(line, "auid=") {
                ev.set("auid", auid);
            }
            if let Some(success) = field(line, "success=") {
                ev.set("success", success);
            }
        }
        t if t.starts_with("USER_") || t == "LOGIN" => {
            ev.set("event_type", "auth");
            if let Some(acct) = field(line, "acct=") {
                ev.set("user", acct);
            }
            if let Some(res) = field(line, "res=") {
                ev.set(
                    "outcome",
                    if res == "success" {
                        "success"
                    } else {
                        "failure"
                    },
                );
            }
            if let Some(addr) = field(line, "addr=") {
                if addr != "?" {
                    ev.set("source_ip", addr);
                }
            }
        }
        _ => {
            ev.set("event_type", rtype.to_ascii_lowercase());
        }
    }

    Some(ev)
}

/// Read the value of `key` (which ends with `=`), respecting token boundaries
/// so `uid=` does not match inside `auid=`. Quoted values are unquoted.
fn field(line: &str, key: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    loop {
        let rel = line[from..].find(key)?;
        let pos = from + rel;
        let boundary = pos == 0 || bytes[pos - 1] == b' ';
        if boundary {
            let vstart = pos + key.len();
            let rest = &line[vstart..];
            if let Some(stripped) = rest.strip_prefix('"') {
                let end = stripped.find('"').unwrap_or(stripped.len());
                return Some(stripped[..end].to_string());
            }
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            return Some(rest[..end].to_string());
        }
        from = pos + key.len();
    }
}

/// Extract EXECVE argument `aN`, decoding auditd's hex encoding when present.
fn exec_arg(line: &str, i: usize) -> Option<String> {
    let key = format!("a{i}=");
    let raw = field(line, &key)?;
    // Unquoted all-hex (even length) values are hex-encoded argv.
    if raw.len() >= 2
        && raw.len() % 2 == 0
        && raw.bytes().all(|b| b.is_ascii_hexdigit())
        && !line.contains(&format!("{key}\""))
    {
        if let Some(decoded) = hex_decode(&raw) {
            return Some(decoded);
        }
    }
    Some(raw)
}

fn hex_decode(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let raw = s.as_bytes();
    let mut i = 0;
    while i + 1 < raw.len() + 1 && i + 2 <= raw.len() {
        let hi = (raw[i] as char).to_digit(16)?;
        let lo = (raw[i + 1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_execve() {
        let line = r#"type=EXECVE msg=audit(1632568508.123:456): argc=3 a0="chmod" a1="4755" a2="/bin/bash""#;
        let ev = parse_line(line, 1, Some("audit.log")).unwrap();
        assert_eq!(ev.get("audit_type"), Some("EXECVE"));
        assert_eq!(ev.get("event_type"), Some("exec"));
        assert_eq!(ev.get("command"), Some("chmod 4755 /bin/bash"));
        assert_eq!(ev.get("command_bin"), Some("chmod"));
        assert!(ev.timestamp.is_some());
    }

    #[test]
    fn syscall_uid_not_confused_with_auid() {
        let line = r#"type=SYSCALL msg=audit(1632568508.123:456): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 comm="useradd" exe="/usr/sbin/useradd" key="user_mgmt""#;
        let ev = parse_line(line, 2, None).unwrap();
        assert_eq!(ev.get("uid"), Some("0"));
        assert_eq!(ev.get("auid"), Some("1000"));
        assert_eq!(ev.get("exe"), Some("/usr/sbin/useradd"));
        assert_eq!(ev.get("audit_key"), Some("user_mgmt"));
    }

    #[test]
    fn decodes_hex_args() {
        // "ls -la" with a hex-encoded second arg (2D6C61 = "-la")
        let line = "type=EXECVE msg=audit(1.0:1): argc=2 a0=\"ls\" a1=2D6C61";
        let ev = parse_line(line, 3, None).unwrap();
        assert_eq!(ev.get("command"), Some("ls -la"));
    }

    #[test]
    fn detects_format() {
        assert!(looks_like(
            "type=SYSCALL msg=audit(1632568508.123:456): arch=c000003e syscall=59"
        ));
        assert!(!looks_like("Nov  4 10:18:01 web01 sshd[1]: hello"));
    }
}
