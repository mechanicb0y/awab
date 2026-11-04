//! Severity levels.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Level {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Level::Info,
            "low" => Level::Low,
            "medium" | "med" => Level::Medium,
            "high" => Level::High,
            "critical" | "crit" => Level::Critical,
            _ => return None,
        })
    }

    /// Bump the level up by `n` steps, saturating at `Critical`.
    pub fn escalate(self, n: u8) -> Level {
        let idx = (self as u8).saturating_add(n).min(Level::Critical as u8);
        match idx {
            0 => Level::Info,
            1 => Level::Low,
            2 => Level::Medium,
            3 => Level::High,
            _ => Level::Critical,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
