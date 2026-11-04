//! Classic syslog / `auth.log` parser with enrichment for common services
//! (sshd, sudo, useradd/groupadd). Standard library only — no regex crate.

use crate::event::Event;
use crate::util::{current_year, epoch_secs, month_num};

/// Parse one syslog line into an [`Event`].
pub fn parse_line(line: &str, line_no: usize, source: Option<&str>) -> Option<Event> {
    let mut ev = Event {
        parser: "syslog",
        raw: line.to_string(),
        line_no,
        source: source.map(|s| s.to_string()),
        ..Default::default()
    };

    if let Some(h) = parse_header(line) {
        ev.timestamp = h.epoch;
        ev.ts_raw = Some(h.ts_raw);
        ev.host = Some(h.host);
        ev.process = Some(h.process);
        ev.pid = h.pid;
        ev.message = h.message;
    } else {
        ev.message = line.to_string();
    }

    enrich(&mut ev);
    Some(ev)
}

struct Header {
    epoch: Option<i64>,
    ts_raw: String,
    host: String,
    process: String,
    pid: Option<u32>,
    message: String,
}

fn tokens(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b' ' {
            i += 1;
        }
        v.push((start, i));
    }
    v
}

fn is_time(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn parse_header(line: &str) -> Option<Header> {
    let toks = tokens(line);
    if toks.len() < 4 {
        return None;
    }
    let tok = |i: usize| &line[toks[i].0..toks[i].1];

    // Traditional: "Mon  d HH:MM:SS host proc[pid]: msg"
    if toks.len() >= 5 {
        if let Some(mon) = month_num(tok(0)) {
            let day = tok(1);
            if day.chars().all(|c| c.is_ascii_digit()) && !day.is_empty() && is_time(tok(2)) {
                let ts_raw = line[toks[0].0..toks[2].1].to_string();
                let (h, mi, s) = split_time(tok(2));
                let epoch = Some(epoch_secs(
                    current_year(),
                    mon,
                    day.parse().unwrap_or(1),
                    h,
                    mi,
                    s,
                ));
                let host = tok(3).to_string();
                let (process, pid) = parse_proc(tok(4));
                let message = if toks.len() > 5 {
                    line[toks[5].0..].to_string()
                } else {
                    String::new()
                };
                return Some(Header {
                    epoch,
                    ts_raw,
                    host,
                    process,
                    pid,
                    message,
                });
            }
        }
    }

    // ISO / RFC3339: "2026-11-04T10:18:01+08:00 host proc[pid]: msg"
    let t0 = tok(0);
    if t0.len() >= 19 && t0.as_bytes()[4] == b'-' && (t0.contains('T') || t0.contains(' ')) {
        let epoch = parse_iso(t0);
        let host = tok(1).to_string();
        let (process, pid) = parse_proc(tok(2));
        let message = if toks.len() > 3 {
            line[toks[3].0..].to_string()
        } else {
            String::new()
        };
        return Some(Header {
            epoch,
            ts_raw: t0.to_string(),
            host,
            process,
            pid,
            message,
        });
    }

    None
}

fn split_time(s: &str) -> (i64, i64, i64) {
    let mut it = s.split(':');
    let h = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let m = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let sec = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    (h, m, sec)
}

fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse().ok() };
    if b.len() < 19 {
        return None;
    }
    let y = num(0, 4)?;
    let mon = num(5, 7)?;
    let d = num(8, 10)?;
    let h = num(11, 13)?;
    let mi = num(14, 16)?;
    let sec = num(17, 19)?;
    Some(epoch_secs(y, mon, d, h, mi, sec))
}

fn parse_proc(tok: &str) -> (String, Option<u32>) {
    let t = tok.strip_suffix(':').unwrap_or(tok);
    if let Some(open) = t.find('[') {
        let name = t[..open].to_string();
        let pid = t[open + 1..].trim_end_matches(']').parse::<u32>().ok();
        (name, pid)
    } else {
        (t.to_string(), None)
    }
}

// ---- enrichment ----

fn enrich(ev: &mut Event) {
    let proc = ev.process.clone().unwrap_or_default();
    let msg = ev.message.clone();
    let words: Vec<&str> = msg.split_whitespace().collect();

    if proc.starts_with("sshd") && enrich_sshd(ev, &msg, &words) {
        return;
    }
    if proc.starts_with("sudo") && enrich_sudo(ev, &msg) {
        return;
    }
    // useradd/usermod emit BOTH "new group:" and "new user:" lines, so key off
    // the message text, not just the process name.
    if proc.starts_with("useradd") || proc.starts_with("usermod") || proc.starts_with("groupadd") {
        if msg.contains("new user:") {
            ev.set("event_type", "user_add");
            ev.set("service", "useradd");
            if let Some(name) = value_after(&msg, "name=") {
                ev.set("new_user", name.trim_end_matches(','));
            }
            if let Some(u) = value_after(&msg, "UID=") {
                ev.set("uid", u.trim_end_matches(','));
            }
            if let Some(g) = value_after(&msg, "GID=") {
                ev.set("gid", g.trim_end_matches(','));
            }
            if let Some(h) = value_after(&msg, "home=") {
                ev.set("home", h.trim_end_matches(','));
            }
            if let Some(s) = value_after(&msg, "shell=") {
                ev.set("shell", s.trim_end_matches(','));
            }
            return;
        }
        if msg.contains("new group:") {
            ev.set("event_type", "group_add");
            ev.set("service", "groupadd");
            if let Some(name) = value_after(&msg, "name=") {
                ev.set("new_group", name.trim_end_matches(','));
            }
            if let Some(g) = value_after(&msg, "GID=") {
                ev.set("gid", g.trim_end_matches(','));
            }
            return;
        }
    }

    // Generic fallback: pull a source IP out of "from <ip>".
    if !ev.fields.contains_key("source_ip") {
        if let Some(ip) = ip_after_from(&words) {
            ev.set("source_ip", ip);
        }
    }
}

fn enrich_sshd(ev: &mut Event, _msg: &str, words: &[&str]) -> bool {
    if words.len() >= 3 && words[0] == "Failed" && words[1] == "password" && words[2] == "for" {
        ev.set("event_type", "auth_failure");
        ev.set("outcome", "failure");
        ev.set("auth_method", "password");
        ev.set("service", "sshd");
        if words.len() >= 6 && words[3] == "invalid" && words[4] == "user" {
            ev.set("invalid_user", "true");
            ev.set("user", words[5]);
        } else if words.len() >= 4 {
            ev.set("user", words[3]);
        }
        if let Some(ip) = ip_after_from(words) {
            ev.set("source_ip", ip);
        }
        return true;
    }
    if words.len() >= 4 && words[0] == "Accepted" && words[2] == "for" {
        ev.set("event_type", "auth_success");
        ev.set("outcome", "success");
        ev.set("auth_method", words[1]);
        ev.set("service", "sshd");
        ev.set("user", words[3]);
        if let Some(ip) = ip_after_from(words) {
            ev.set("source_ip", ip);
        }
        return true;
    }
    if words.len() >= 3 && words[0] == "Invalid" && words[1] == "user" {
        ev.set("event_type", "auth_failure");
        ev.set("outcome", "failure");
        ev.set("invalid_user", "true");
        ev.set("service", "sshd");
        ev.set("user", words[2]);
        if let Some(ip) = ip_after_from(words) {
            ev.set("source_ip", ip);
        }
        return true;
    }
    false
}

fn enrich_sudo(ev: &mut Event, msg: &str) -> bool {
    if msg.contains("authentication failure") || msg.contains("incorrect password") {
        ev.set("event_type", "sudo_auth_failure");
        ev.set("service", "sudo");
        if let Some(l) = value_after(msg, "logname=") {
            ev.set("actor", l.trim_end_matches(';').trim());
        }
        return true;
    }
    if let Some(cmd_idx) = msg.find("COMMAND=") {
        ev.set("event_type", "sudo_command");
        ev.set("service", "sudo");
        if let Some((actor, _)) = msg.split_once(" : ") {
            ev.set("actor", actor.trim());
        }
        if let Some(target) = value_after(msg, "USER=") {
            ev.set("target_user", target.trim_end_matches(';').trim());
        }
        let command = msg[cmd_idx + "COMMAND=".len()..].trim();
        ev.set("command", command);
        // The executable actually run (first token), so rules can match the
        // program without false-matching a shell path passed as an argument.
        if let Some(bin) = command.split_whitespace().next() {
            ev.set("command_bin", bin);
        }
        return true;
    }
    false
}

/// Return the whitespace-delimited token following `key` within `msg` (where
/// `key` ends with `=`), trimmed of a trailing comma/semicolon.
fn value_after<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    let i = msg.find(key)? + key.len();
    let rest = &msg[i..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .unwrap_or(rest.len());
    let v = &rest[..end];
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn ip_after_from<'a>(words: &[&'a str]) -> Option<&'a str> {
    let pos = words.iter().position(|w| *w == "from")?;
    let cand = words.get(pos + 1)?;
    if cand.contains('.') || cand.contains(':') {
        Some(*cand)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password() {
        let line = "Nov  4 10:18:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2";
        let ev = parse_line(line, 1, Some("auth.log")).unwrap();
        assert_eq!(ev.process.as_deref(), Some("sshd"));
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.get("user"), Some("admin"));
        assert_eq!(ev.get("source_ip"), Some("203.0.113.5"));
        assert_eq!(ev.get("event_type"), Some("auth_failure"));
        assert_eq!(ev.get("invalid_user"), Some("true"));
        assert!(ev.timestamp.is_some());
        assert_eq!(ev.host.as_deref(), Some("web01"));
    }

    #[test]
    fn parses_accepted_password() {
        let line = "Nov  4 10:20:11 web01 sshd[1250]: Accepted password for root from 203.0.113.5 port 54400 ssh2";
        let ev = parse_line(line, 2, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("auth_success"));
        assert_eq!(ev.get("user"), Some("root"));
        assert_eq!(ev.get("source_ip"), Some("203.0.113.5"));
        assert_eq!(ev.get("auth_method"), Some("password"));
    }

    #[test]
    fn parses_sudo_command() {
        let line = "Nov  4 11:02:03 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash";
        let ev = parse_line(line, 3, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("sudo_command"));
        assert_eq!(ev.get("actor"), Some("alice"));
        assert_eq!(ev.get("target_user"), Some("root"));
        assert_eq!(ev.get("command"), Some("/bin/bash"));
    }

    #[test]
    fn parses_useradd_uid0() {
        let line = "Nov  4 11:05:00 web01 useradd[2001]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash";
        let ev = parse_line(line, 4, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("user_add"));
        assert_eq!(ev.get("new_user"), Some("backdoor"));
        assert_eq!(ev.get("uid"), Some("0"));
    }

    #[test]
    fn new_group_is_group_not_user() {
        // Regression: useradd emits a "new group:" line that must NOT be
        // classified as a user account creation.
        let line = "Nov  4 11:05:00 web01 useradd[2001]: new group: name=backdoor, GID=1003";
        let ev = parse_line(line, 4, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("group_add"));
        assert_eq!(ev.get("new_group"), Some("backdoor"));
        assert_eq!(ev.get("new_user"), None);
    }

    #[test]
    fn sudo_command_bin_is_executable_not_arg() {
        // Regression: a shell path passed as an argument (useradd -s /bin/bash)
        // must not make command_bin look like a shell.
        let line = "Nov  4 07:15:08 kali sudo[11293]:     kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/sbin/useradd -g 0 -s /bin/bash butter";
        let ev = parse_line(line, 6, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("sudo_command"));
        assert_eq!(ev.get("command_bin"), Some("/usr/sbin/useradd"));

        let shell = "Nov  4 02:17:23 kali sudo[1]:     kali : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/sh -c 'id'";
        let ev = parse_line(shell, 7, None).unwrap();
        assert_eq!(ev.get("command_bin"), Some("/usr/bin/sh"));
    }

    #[test]
    fn useradd_enriches_gid_and_home() {
        let line = "2026-09-25T07:15:08-04:00 kali useradd[11296]: new user: name=butter, UID=1006, GID=0, home=/root, shell=/bin/bash, from=none";
        let ev = parse_line(line, 8, None).unwrap();
        assert_eq!(ev.get("event_type"), Some("user_add"));
        assert_eq!(ev.get("gid"), Some("0"));
        assert_eq!(ev.get("home"), Some("/root"));
        assert_eq!(ev.get("shell"), Some("/bin/bash"));
    }

    #[test]
    fn parses_iso_header() {
        let line = "2026-11-04T10:18:01+08:00 web01 sshd[9]: Failed password for root from 10.0.0.9 port 1 ssh2";
        let ev = parse_line(line, 5, None).unwrap();
        assert_eq!(ev.process.as_deref(), Some("sshd"));
        assert_eq!(ev.get("source_ip"), Some("10.0.0.9"));
        assert!(ev.timestamp.is_some());
    }
}
