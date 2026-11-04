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

pub fn render(findings: &[Finding], stats: &Stats, color: bool) {
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

    let headers = ["SEVERITY", "RULE", "KEY", "HITS", "ATT&CK"];
    let rows: Vec<Vec<String>> = findings
        .iter()
        .map(|f| {
            vec![
                f.level.as_str().to_uppercase(),
                truncate(&f.title, 38),
                f.group_key.clone().unwrap_or_else(|| "-".into()),
                f.count.to_string(),
                attack(f),
            ]
        })
        .collect();
    print_cols(&headers, &rows, color);
    println!();

    for f in findings {
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
