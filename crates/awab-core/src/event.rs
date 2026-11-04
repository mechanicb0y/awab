//! Normalized event model shared by all parsers.

use std::collections::BTreeMap;

/// A single normalized log event.
///
/// Parsers fill `raw` and `message` at minimum and enrich `fields` with any
/// structured values they can extract (e.g. `source_ip`, `user`,
/// `event_type`). Rules then match against these fields.
#[derive(Debug, Clone, Default)]
pub struct Event {
    /// Parsed timestamp as Unix epoch seconds (UTC), if determinable.
    pub timestamp: Option<i64>,
    /// The timestamp exactly as it appeared in the log, for display.
    pub ts_raw: Option<String>,
    /// Hostname from the log header, if present.
    pub host: Option<String>,
    /// Process / program name (e.g. `sshd`, `sudo`), if present.
    pub process: Option<String>,
    /// Process id, if present.
    pub pid: Option<u32>,
    /// The message body (everything after the syslog header).
    pub message: String,
    /// The original raw line, untouched.
    pub raw: String,
    /// Enriched structured fields extracted by the parser.
    pub fields: BTreeMap<String, String>,
    /// Which parser produced this event (`syslog`, ...).
    pub parser: &'static str,
    /// Source file name, if read from a file.
    pub source: Option<String>,
    /// 1-based line number within the source.
    pub line_no: usize,
}

impl Event {
    /// Look up a logical field by name. A few names are virtual and map onto
    /// the struct itself; everything else comes from `fields`.
    pub fn get(&self, field: &str) -> Option<&str> {
        match field {
            "message" | "msg" => Some(self.message.as_str()),
            "raw" => Some(self.raw.as_str()),
            "process" | "proc" => self.process.as_deref(),
            "host" => self.host.as_deref(),
            "parser" => Some(self.parser),
            other => self.fields.get(other).map(|s| s.as_str()),
        }
    }

    /// Convenience: insert an enriched field.
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.fields.insert(key.to_string(), value.into());
    }
}
