//! Parser for web server access logs in Common / Combined Log Format
//! (nginx and Apache default). Standard library only.
//!
//! Example (combined):
//!   192.0.2.9 - - [04/Nov/2026:10:15:02 +0000] "GET /x.php?cmd=id HTTP/1.1" 200 12 "-" "curl/8.0"

use crate::event::Event;
use crate::util::{epoch_secs, month_num};

/// Quick heuristic: does this line look like a CLF/combined access log line?
pub fn looks_like(line: &str) -> bool {
    line.contains("] \"") && (line.contains("HTTP/1.") || line.contains("HTTP/2"))
}

pub fn parse_line(line: &str, line_no: usize, source: Option<&str>) -> Option<Event> {
    let mut ev = Event {
        parser: "web",
        raw: line.to_string(),
        message: line.to_string(),
        line_no,
        source: source.map(|s| s.to_string()),
        ..Default::default()
    };
    ev.set("event_type", "web_request");
    ev.set("service", "web");

    // Source IP: first whitespace token.
    if let Some(ip) = line.split_whitespace().next() {
        ev.set("source_ip", ip);
    }

    // Timestamp inside [ ... ].
    if let (Some(lb), Some(rb)) = (line.find('['), line.find(']')) {
        if rb > lb {
            let ts = &line[lb + 1..rb];
            ev.ts_raw = Some(ts.to_string());
            ev.timestamp = parse_clf_time(ts);
        }
    }

    // Request line: the first double-quoted field.
    if let Some(q1) = line.find('"') {
        if let Some(rel) = line[q1 + 1..].find('"') {
            let req = &line[q1 + 1..q1 + 1 + rel];
            let mut parts = req.split_whitespace();
            if let Some(method) = parts.next() {
                ev.set("http_method", method);
            }
            if let Some(url) = parts.next() {
                ev.set("url", url);
            }
            if let Some(proto) = parts.next() {
                ev.set("http_proto", proto);
            }
            // Status code: first token after the closing quote of the request.
            let after = &line[q1 + 1 + rel + 1..];
            if let Some(status) = after.split_whitespace().next() {
                if status.chars().all(|c| c.is_ascii_digit()) {
                    ev.set("http_status", status);
                }
            }
        }
    }

    // User-agent: the last double-quoted field (combined format).
    let quotes: Vec<usize> = line.match_indices('"').map(|(i, _)| i).collect();
    if quotes.len() >= 2 {
        let last_open = quotes[quotes.len() - 2];
        let last_close = quotes[quotes.len() - 1];
        if last_close > last_open + 1 {
            let ua = &line[last_open + 1..last_close];
            if ua != "-" {
                ev.set("user_agent", ua);
            }
        }
    }

    Some(ev)
}

/// Parse a CLF timestamp like `04/Nov/2026:10:15:02 +0000` to epoch seconds.
fn parse_clf_time(s: &str) -> Option<i64> {
    // date part before first ':'
    let (date, rest) = s.split_once(':')?;
    let mut dparts = date.split('/');
    let day: i64 = dparts.next()?.parse().ok()?;
    let mon = month_num(dparts.next()?)?;
    let year: i64 = dparts.next()?.parse().ok()?;
    let time = rest.split_whitespace().next().unwrap_or(rest);
    let mut tparts = time.split(':');
    let h: i64 = tparts.next()?.parse().ok()?;
    let mi: i64 = tparts.next()?.parse().ok()?;
    let sec: i64 = tparts.next()?.parse().ok()?;
    Some(epoch_secs(year, mon, day, h, mi, sec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_line() {
        let line = r#"192.0.2.9 - - [04/Nov/2026:10:15:02 +0000] "GET /uploads/x.php?cmd=id HTTP/1.1" 200 12 "-" "curl/8.0""#;
        let ev = parse_line(line, 1, Some("access.log")).unwrap();
        assert_eq!(ev.get("source_ip"), Some("192.0.2.9"));
        assert_eq!(ev.get("http_method"), Some("GET"));
        assert_eq!(ev.get("url"), Some("/uploads/x.php?cmd=id"));
        assert_eq!(ev.get("http_status"), Some("200"));
        assert_eq!(ev.get("user_agent"), Some("curl/8.0"));
        assert!(ev.timestamp.is_some());
    }

    #[test]
    fn detects_format() {
        assert!(looks_like(
            r#"10.0.0.1 - - [04/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5"#
        ));
        assert!(!looks_like(
            "Nov  4 10:18:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
        ));
    }
}
