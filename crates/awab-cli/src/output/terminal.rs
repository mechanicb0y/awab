//! Human-readable terminal output (hand-rolled table + ANSI, std-only).

use super::Stats;
use awab_core::finding::Finding;
use awab_core::level::Level;
use awab_core::rule::Rule;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const BRIGHT_RED: &str = "\x1b[91m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";

fn when(f: &Finding) -> String {
    match (&f.first_seen, &f.last_seen) {
        (Some(a), Some(b)) if a != b => format!("{a} → {b}"),
        (Some(a), _) => a.clone(),
        _ => "-".into(),
    }
}

fn attack(f: &Finding) -> String {
    f.mitre
        .as_ref()
        .map(|m| m.technique.clone())
        .unwrap_or_else(|| "-".into())
}

fn level_color(level: Level) -> &'static str {
    match level {
        Level::Critical => BRIGHT_RED,
        Level::High => RED,
        Level::Medium => YELLOW,
        Level::Low => BLUE,
        Level::Info => DIM,
    }
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Max detail blocks shown per rule before collapsing (unless --full).
const DETAIL_CAP: usize = 3;

pub fn render(findings: &[Finding], stats: &Stats, color: bool, full: bool) {
    println!(
        "[*] loaded {} rules, parsed {} log events",
        stats.rules, stats.events
    );

    if findings.is_empty() {
        println!(
            "{}",
            paint(
                "[+] no findings - nothing matched the loaded rules",
                GREEN,
                color
            )
        );
        return;
    }

    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.level as usize] += 1;
    }
    let bang = paint("[!]", BRIGHT_RED, color);
    println!(
        "{bang} {} finding(s): {} critical, {} high, {} medium, {} low, {} info\n",
        findings.len(),
        counts[Level::Critical as usize],
        counts[Level::High as usize],
        counts[Level::Medium as usize],
        counts[Level::Low as usize],
        counts[Level::Info as usize],
    );

    // Group findings by rule, preserving first-appearance order (findings arrive
    // severity-sorted), then order groups by severity then size.
    let mut order: Vec<&str> = Vec::new();
    let mut groups: std::collections::HashMap<&str, Vec<&Finding>> =
        std::collections::HashMap::new();
    for f in findings {
        let id = f.rule_id.as_str();
        if !groups.contains_key(id) {
            order.push(id);
        }
        groups.entry(id).or_default().push(f);
    }
    let gmax = |id: &str| {
        groups
            .get(id)
            .unwrap()
            .iter()
            .map(|f| f.level)
            .max()
            .unwrap()
    };
    order.sort_by(|a, b| {
        gmax(b).cmp(&gmax(a)).then(
            groups
                .get(*b)
                .unwrap()
                .len()
                .cmp(&groups.get(*a).unwrap().len()),
        )
    });

    // Summary: one row per rule.
    let headers = ["SEVERITY", "RULE", "KEY", "COUNT", "ATT&CK"];
    let rows: Vec<Vec<String>> = order
        .iter()
        .map(|id| {
            let g = groups.get(*id).unwrap();
            let rep = g[0];
            let key = if g.len() == 1 {
                rep.group_key.clone().unwrap_or_else(|| "-".into())
            } else {
                "-".into()
            };
            vec![
                gmax(id).as_str().to_uppercase(),
                truncate(&rep.title, 38),
                key,
                g.len().to_string(),
                attack(rep),
            ]
        })
        .collect();
    print_cols(&headers, &rows, color);
    println!();

    // Details: grouped by rule, capped per rule unless --full.
    let mut truncated = false;
    for id in &order {
        let g = groups.get(*id).unwrap();
        let show = if full {
            g.len()
        } else {
            g.len().min(DETAIL_CAP)
        };
        for f in &g[..show] {
            detail(f, color);
        }
        if g.len() > show {
            truncated = true;
            println!(
                "    {}\n",
                paint(
                    &format!("… and {} more '{}' finding(s)", g.len() - show, g[0].title),
                    DIM,
                    color
                )
            );
        }
    }
    if truncated {
        println!(
            "{}",
            paint(
                "[*] output capped per rule - use --full for every finding, or -f json",
                DIM,
                color
            )
        );
    }
}

/// Render one finding's detail block.
fn detail(f: &Finding, color: bool) {
    let lvl = paint(
        &f.level.as_str().to_uppercase(),
        level_color(f.level),
        color,
    );
    println!(
        "{lvl}  {}  {}",
        paint(&f.title, BOLD, color),
        paint(&format!("({})", f.rule_id), DIM, color)
    );
    if let Some(m) = &f.mitre {
        println!(
            "    ATT&CK : {} / {}  {}",
            m.tactic,
            m.technique,
            paint(&m.url(), DIM, color)
        );
    }
    if let (Some(field), Some(key)) = (&f.group_field, &f.group_key) {
        print!("    Target : {field} = {key}");
        if let Some(d) = f.distinct_count {
            print!("  ({d} distinct)");
        }
        println!();
    }
    println!("    Events : {}  ({})", f.count, when(f));
    if let Some(src) = &f.source {
        println!("    Source : {src}");
    }
    let desc = f.description.trim().replace('\n', " ");
    if !desc.is_empty() {
        println!("    Why    : {desc}");
    }
    if !f.sample.is_empty() {
        println!("    Sample :");
        for line in &f.sample {
            println!("      {}", paint(line, DIM, color));
        }
    }
    println!();
}

pub fn render_rule_list(rules: &[Rule]) {
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let headers = ["ID", "LEVEL", "TITLE", "ATT&CK"];
    let rows: Vec<Vec<String>> = sorted
        .iter()
        .map(|r| {
            vec![
                r.id.clone(),
                r.level.as_str().to_uppercase(),
                truncate(&r.title, 50),
                r.mitre
                    .as_ref()
                    .map(|m| m.technique.clone())
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    print_cols(&headers, &rows, false);
    println!("\n[*] {} rule(s) loaded.", rules.len());
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Print plain, left-aligned columns (nmap/hydra style) — no borders.
fn print_cols(headers: &[&str], rows: &[Vec<String>], color: bool) {
    let ncol = headers.len();
    let mut w = vec![0usize; ncol];
    for (i, h) in headers.iter().enumerate() {
        w[i] = h.chars().count();
    }
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < ncol {
                w[i] = w[i].max(c.chars().count());
            }
        }
    }

    let render_row = |cells: &[String]| {
        let mut line = String::new();
        for (i, width) in w.iter().enumerate() {
            let cell = cells.get(i).cloned().unwrap_or_default();
            if i + 1 == ncol {
                line.push_str(&cell); // last column: no trailing pad
            } else {
                line.push_str(&pad(&cell, *width));
                line.push_str("  ");
            }
        }
        line
    };

    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    println!("{}", paint(&render_row(&header_cells), DIM, color));
    for r in rows {
        println!("{}", render_row(r));
    }
}
