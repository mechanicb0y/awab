//! Log parsers. Each turns raw text into normalized [`Event`]s.

pub mod auditd;
pub mod syslog;
pub mod web;

use crate::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserKind {
    Auto,
    Syslog,
    Web,
    Auditd,
}

impl ParserKind {
    pub fn from_name(name: &str) -> Option<ParserKind> {
        Some(match name.to_ascii_lowercase().as_str() {
            "auto" => ParserKind::Auto,
            "syslog" | "auth" | "authlog" => ParserKind::Syslog,
            "web" | "access" | "nginx" | "apache" => ParserKind::Web,
            "auditd" | "audit" => ParserKind::Auditd,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            ParserKind::Auto => "auto",
            ParserKind::Syslog => "syslog",
            ParserKind::Web => "web",
            ParserKind::Auditd => "auditd",
        }
    }
}

/// Detect which parser best fits a block of text by sampling its first lines.
pub fn detect(text: &str) -> ParserKind {
    for line in text.lines().filter(|l| !l.trim().is_empty()).take(10) {
        if auditd::looks_like(line) {
            return ParserKind::Auditd;
        }
        if web::looks_like(line) {
            return ParserKind::Web;
        }
    }
    ParserKind::Syslog
}

/// Parse a block of text into events using the chosen parser.
pub fn parse_text(text: &str, kind: ParserKind, source: Option<&str>) -> Vec<Event> {
    let chosen = match kind {
        ParserKind::Auto => detect(text),
        other => other,
    };
    let mut events = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let ev = match chosen {
            ParserKind::Web => web::parse_line(line, i + 1, source),
            ParserKind::Auditd => auditd::parse_line(line, i + 1, source),
            ParserKind::Syslog | ParserKind::Auto => syslog::parse_line(line, i + 1, source),
        };
        if let Some(ev) = ev {
            events.push(ev);
        }
    }
    events
}
