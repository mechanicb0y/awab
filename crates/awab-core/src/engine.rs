//! The detection engine: match events against rules and correlate bursts.

use crate::event::Event;
use crate::finding::Finding;
use crate::level::Level;
use crate::regexlite::Regex;
use crate::rule::{split_key, Op, Rule};
use crate::util::parse_duration_secs;
use std::collections::BTreeSet;

struct Cond {
    field: String,
    op: Op,
    values: Vec<String>,
    regexes: Vec<Regex>,
}

struct Compiled<'r> {
    rule: &'r Rule,
    conds: Vec<Cond>,
}

impl<'r> Compiled<'r> {
    fn new(rule: &'r Rule) -> Compiled<'r> {
        let mut conds = Vec::new();
        for (key, val) in &rule.detection.selection {
            let (field, opstr) = split_key(key);
            let op = Op::parse(opstr).unwrap_or(Op::Equals);
            let values: Vec<String> = val.values().iter().map(|s| s.to_string()).collect();
            let regexes = if op == Op::Regex {
                values.iter().filter_map(|v| Regex::new(v).ok()).collect()
            } else {
                Vec::new()
            };
            conds.push(Cond {
                field: field.to_string(),
                op,
                values,
                regexes,
            });
        }
        Compiled { rule, conds }
    }

    fn matches(&self, ev: &Event) -> bool {
        if let Some(p) = &self.rule.logsource.parser {
            if !ev.parser.eq_ignore_ascii_case(p) {
                return false;
            }
        }
        if let Some(svc) = &self.rule.logsource.service {
            let proc_ok = ev
                .process
                .as_deref()
                .map(|p| p.starts_with(svc.as_str()))
                .unwrap_or(false);
            let field_ok = ev.get("service").map(|s| s == svc).unwrap_or(false);
            if !proc_ok && !field_ok {
                return false;
            }
        }
        self.conds.iter().all(|c| cond_matches(c, ev))
    }
}

fn cond_matches(c: &Cond, ev: &Event) -> bool {
    let actual = match ev.get(&c.field) {
        Some(v) => v,
        None => return false,
    };
    match c.op {
        Op::Equals => c.values.iter().any(|v| actual == v),
        Op::Contains => c.values.iter().any(|v| actual.contains(v.as_str())),
        Op::StartsWith => c.values.iter().any(|v| actual.starts_with(v.as_str())),
        Op::EndsWith => c.values.iter().any(|v| actual.ends_with(v.as_str())),
        Op::Regex => c.regexes.iter().any(|re| re.is_match(actual)),
        Op::Gt | Op::Lt => {
            let a: f64 = match actual.parse() {
                Ok(n) => n,
                Err(_) => return false,
            };
            c.values.iter().any(|v| match v.parse::<f64>() {
                Ok(n) => {
                    if c.op == Op::Gt {
                        a > n
                    } else {
                        a < n
                    }
                }
                Err(_) => false,
            })
        }
    }
}

/// Run all rules over all events and return findings, most severe first.
pub fn scan(events: &[Event], rules: &[Rule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules {
        let compiled = Compiled::new(rule);
        if rule.is_aggregated() {
            findings.extend(run_aggregated(events, &compiled));
        } else {
            findings.extend(run_simple(events, &compiled));
        }
    }
    findings.sort_by(|a, b| b.level.cmp(&a.level).then(b.count.cmp(&a.count)));
    findings
}

fn run_simple(events: &[Event], c: &Compiled) -> Vec<Finding> {
    let mut out = Vec::new();
    for ev in events.iter().filter(|e| c.matches(e)) {
        out.push(Finding {
            rule_id: c.rule.id.clone(),
            title: c.rule.title.clone(),
            level: c.rule.level,
            mitre: c.rule.mitre.clone(),
            description: c.rule.description.clone(),
            group_field: None,
            group_key: None,
            count: 1,
            distinct_count: None,
            first_seen: ev.ts_raw.clone(),
            last_seen: ev.ts_raw.clone(),
            sample: vec![ev.raw.clone()],
            source: ev.source.clone(),
        });
    }
    out
}

fn run_aggregated(events: &[Event], c: &Compiled) -> Vec<Finding> {
    let det = &c.rule.detection;
    let group_field = match &det.group_by {
        Some(g) => g.as_str(),
        None => return Vec::new(),
    };
    let threshold = det.threshold.unwrap_or(1) as usize;
    let window = det.timewindow.as_deref().and_then(parse_duration_secs);

    // Group matching events by the group field value, preserving order.
    let mut keys: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<&Event>> =
        std::collections::HashMap::new();
    for ev in events.iter().filter(|e| c.matches(e)) {
        if let Some(key) = ev.get(group_field) {
            let k = key.to_string();
            groups.entry(k.clone()).or_insert_with(|| {
                keys.push(k.clone());
                Vec::new()
            });
            groups.get_mut(&k).unwrap().push(ev);
        }
    }

    let mut out = Vec::new();
    for key in keys {
        let mut evs = groups.remove(&key).unwrap();
        evs.sort_by_key(|e| e.timestamp.unwrap_or(i64::MIN));
        let all_have_ts = evs.iter().all(|e| e.timestamp.is_some());

        let burst = match (window, all_have_ts) {
            (Some(win), true) => best_window(&evs, win, det.count_distinct.as_deref(), threshold),
            _ => whole_group(&evs, det.count_distinct.as_deref(), threshold),
        };

        if let Some(b) = burst {
            let level = escalate_by_ratio(c.rule.level, b.metric, threshold);
            out.push(Finding {
                rule_id: c.rule.id.clone(),
                title: c.rule.title.clone(),
                level,
                mitre: c.rule.mitre.clone(),
                description: c.rule.description.clone(),
                group_field: Some(group_field.to_string()),
                group_key: Some(key),
                count: b.count,
                distinct_count: det.count_distinct.as_ref().map(|_| b.metric),
                first_seen: b.first,
                last_seen: b.last,
                sample: b.sample,
                source: evs.first().and_then(|e| e.source.clone()),
            });
        }
    }
    out
}

struct Burst {
    count: usize,
    metric: usize,
    first: Option<String>,
    last: Option<String>,
    sample: Vec<String>,
}

fn whole_group(evs: &[&Event], count_distinct: Option<&str>, threshold: usize) -> Option<Burst> {
    let metric = match count_distinct {
        Some(f) => distinct_count(evs, f),
        None => evs.len(),
    };
    if metric >= threshold {
        Some(Burst {
            count: evs.len(),
            metric,
            first: evs.first().and_then(|e| e.ts_raw.clone()),
            last: evs.last().and_then(|e| e.ts_raw.clone()),
            sample: sample_lines(evs),
        })
    } else {
        None
    }
}

fn best_window(
    evs: &[&Event],
    win_secs: i64,
    count_distinct: Option<&str>,
    threshold: usize,
) -> Option<Burst> {
    let n = evs.len();
    let mut left = 0usize;
    let mut best: Option<(usize, usize)> = None; // (metric, span)
    let mut best_bounds = (0usize, 0usize);

    for right in 0..n {
        let rt = evs[right].timestamp.unwrap();
        while rt - evs[left].timestamp.unwrap() > win_secs {
            left += 1;
        }
        let window = &evs[left..=right];
        let metric = match count_distinct {
            Some(f) => distinct_count(window, f),
            None => window.len(),
        };
        if metric >= threshold {
            let span = right - left + 1;
            let better = match best {
                None => true,
                Some((m, s)) => metric > m || (metric == m && span > s),
            };
            if better {
                best = Some((metric, span));
                best_bounds = (left, right);
            }
        }
    }

    best.map(|(metric, _)| {
        let (l, r) = best_bounds;
        let window = &evs[l..=r];
        Burst {
            count: window.len(),
            metric,
            first: window.first().and_then(|e| e.ts_raw.clone()),
            last: window.last().and_then(|e| e.ts_raw.clone()),
            sample: sample_lines(window),
        }
    })
}

fn distinct_count(evs: &[&Event], field: &str) -> usize {
    let mut set = BTreeSet::new();
    for e in evs {
        if let Some(v) = e.get(field) {
            set.insert(v.to_string());
        }
    }
    set.len()
}

fn sample_lines(evs: &[&Event]) -> Vec<String> {
    evs.iter().take(3).map(|e| e.raw.clone()).collect()
}

fn escalate_by_ratio(base: Level, metric: usize, threshold: usize) -> Level {
    if threshold == 0 {
        return base;
    }
    let ratio = metric / threshold;
    if ratio >= 10 {
        base.escalate(2)
    } else if ratio >= 3 {
        base.escalate(1)
    } else {
        base
    }
}
