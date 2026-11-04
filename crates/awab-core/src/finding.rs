//! A detection result.

use crate::level::Level;
use crate::mitre::Mitre;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub level: Level,
    pub mitre: Option<Mitre>,
    pub description: String,
    /// The field events were grouped by (for correlated findings).
    pub group_field: Option<String>,
    /// The value of the group key, e.g. the offending source IP.
    pub group_key: Option<String>,
    /// Number of matching events in this finding.
    pub count: usize,
    /// Distinct count, when the rule used `count_distinct`.
    pub distinct_count: Option<usize>,
    /// First/last timestamps, as they appeared in the log (display form).
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// A few representative raw log lines.
    pub sample: Vec<String>,
    pub source: Option<String>,
}
