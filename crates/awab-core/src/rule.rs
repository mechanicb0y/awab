//! The rule format — awab's "plugin" system. Rules are small declarative
//! detections loaded from YAML; the engine stays generic.

use crate::level::Level;
use crate::mitre::Mitre;
use crate::regexlite::Regex;
use crate::yaml::Value;

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub author: String,
    pub references: Vec<String>,
    pub level: Level,
    pub mitre: Option<Mitre>,
    pub logsource: LogSource,
    pub detection: Detection,
}

#[derive(Debug, Clone, Default)]
pub struct LogSource {
    pub parser: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Detection {
    /// `field|op` -> value(s). All entries AND; values within one entry OR.
    pub selection: Vec<(String, MatchValue)>,
    pub group_by: Option<String>,
    pub timewindow: Option<String>,
    pub threshold: Option<u32>,
    pub count_distinct: Option<String>,
}

#[derive(Debug, Clone)]
pub enum MatchValue {
    One(String),
    Many(Vec<String>),
}

impl MatchValue {
    pub fn values(&self) -> Vec<&str> {
        match self {
            MatchValue::One(s) => vec![s.as_str()],
            MatchValue::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Equals,
    Contains,
    Regex,
    StartsWith,
    EndsWith,
    Gt,
    Lt,
}

impl Op {
    pub fn parse(suffix: &str) -> Option<Op> {
        Some(match suffix {
            "" | "equals" | "eq" => Op::Equals,
            "contains" => Op::Contains,
            "re" | "regex" => Op::Regex,
            "startswith" => Op::StartsWith,
            "endswith" => Op::EndsWith,
            "gt" => Op::Gt,
            "lt" => Op::Lt,
            _ => return None,
        })
    }
}

/// Split a selection key `field|op` into its field and operator suffix.
pub fn split_key(key: &str) -> (&str, &str) {
    match key.split_once('|') {
        Some((field, op)) => (field, op),
        None => (key, ""),
    }
}

impl Rule {
    pub fn is_aggregated(&self) -> bool {
        self.detection.threshold.is_some()
    }

    /// Build a rule from a parsed YAML value.
    pub fn from_value(v: &Value) -> Result<Rule, String> {
        let get_str = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());

        let id = get_str("id").ok_or("missing `id`")?;
        let title = get_str("title").ok_or("missing `title`")?;
        let description = get_str("description").unwrap_or_default();
        let author = get_str("author").unwrap_or_default();

        let references = v
            .get("references")
            .and_then(|x| x.as_list())
            .map(|l| {
                l.iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let level = match get_str("level") {
            Some(s) => Level::parse(&s).ok_or_else(|| format!("unknown level `{s}`"))?,
            None => Level::default(),
        };

        let mitre = match v.get("mitre") {
            Some(mv) => {
                let tactic = mv
                    .get("tactic")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let technique = mv
                    .get("technique")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(Mitre { tactic, technique })
            }
            None => None,
        };

        let logsource = match v.get("logsource") {
            Some(ls) => LogSource {
                parser: ls
                    .get("parser")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                service: ls
                    .get("service")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            },
            None => LogSource::default(),
        };

        let det_v = v.get("detection").ok_or("missing `detection`")?;
        let selection = match det_v.get("selection").and_then(|x| x.as_map()) {
            Some(entries) => entries
                .iter()
                .map(|(k, val)| (k.clone(), to_match_value(val)))
                .collect(),
            None => Vec::new(),
        };
        let threshold = det_v
            .get("threshold")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().parse::<u32>())
            .transpose()
            .map_err(|_| "`threshold` must be an integer")?;
        let detection = Detection {
            selection,
            group_by: det_v
                .get("group_by")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            timewindow: det_v
                .get("timewindow")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            threshold,
            count_distinct: det_v
                .get("count_distinct")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        };

        Ok(Rule {
            id,
            title,
            description,
            author,
            references,
            level,
            mitre,
            logsource,
            detection,
        })
    }

    /// Structural validation independent of any input logs.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.id.trim().is_empty() {
            errs.push("missing `id`".into());
        }
        if self.title.trim().is_empty() {
            errs.push("missing `title`".into());
        }
        if self.detection.selection.is_empty() {
            errs.push("`detection.selection` must have at least one condition".into());
        }
        for (key, val) in &self.detection.selection {
            let (field, op) = split_key(key);
            if field.is_empty() {
                errs.push(format!("selection key `{key}` has an empty field name"));
            }
            match Op::parse(op) {
                None => errs.push(format!(
                    "selection key `{key}` uses unknown operator `{op}`"
                )),
                Some(Op::Regex) => {
                    for pat in val.values() {
                        if let Err(e) = Regex::new(pat) {
                            errs.push(format!("selection `{key}` has invalid regex `{pat}`: {e}"));
                        }
                    }
                }
                _ => {}
            }
        }
        if self.detection.threshold.is_some() && self.detection.group_by.is_none() {
            errs.push("`threshold` requires `group_by`".into());
        }
        if self.detection.timewindow.is_some() && self.detection.threshold.is_none() {
            errs.push("`timewindow` has no effect without `threshold`".into());
        }
        if let Some(tw) = &self.detection.timewindow {
            if crate::util::parse_duration_secs(tw).is_none() {
                errs.push(format!(
                    "`timewindow` `{tw}` is invalid (use e.g. 60s, 5m, 1h)"
                ));
            }
        }
        errs
    }
}

fn to_match_value(v: &Value) -> MatchValue {
    match v {
        Value::Str(s) => MatchValue::One(s.clone()),
        Value::List(items) => MatchValue::Many(
            items
                .iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect(),
        ),
        Value::Map(_) => MatchValue::One(String::new()),
    }
}
