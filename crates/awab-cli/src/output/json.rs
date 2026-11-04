//! Machine-readable JSON output (hand-written, std-only).

use super::Stats;
use awab_core::finding::Finding;

pub fn render(findings: &[Finding], stats: &Stats) -> Result<(), String> {
    print!("{}", to_json(findings, stats));
    println!();
    Ok(())
}

pub fn to_json(findings: &[Finding], stats: &Stats) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"tool\": \"awab\",\n");
    s.push_str(&format!(
        "  \"version\": {},\n",
        q(env!("CARGO_PKG_VERSION"))
    ));
    s.push_str(&format!(
        "  \"generated\": {},\n",
        q(&awab_core::util::format_utc(awab_core::util::now_epoch()))
    ));
    s.push_str(&format!(
        "  \"stats\": {{ \"rules\": {}, \"events\": {}, \"findings\": {} }},\n",
        stats.rules, stats.events, stats.findings
    ));
    s.push_str("  \"findings\": [");
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("\n    {\n");
        s.push_str(&format!("      \"rule_id\": {},\n", q(&f.rule_id)));
        s.push_str(&format!("      \"title\": {},\n", q(&f.title)));
        s.push_str(&format!("      \"level\": {},\n", q(f.level.as_str())));
        match &f.mitre {
            Some(m) => s.push_str(&format!(
                "      \"mitre\": {{ \"tactic\": {}, \"technique\": {}, \"url\": {} }},\n",
                q(&m.tactic),
                q(&m.technique),
                q(&m.url())
            )),
            None => s.push_str("      \"mitre\": null,\n"),
        }
        s.push_str(&format!(
            "      \"description\": {},\n",
            q(f.description.trim())
        ));
        s.push_str(&format!(
            "      \"group_field\": {},\n",
            opt(&f.group_field)
        ));
        s.push_str(&format!("      \"group_key\": {},\n", opt(&f.group_key)));
        s.push_str(&format!("      \"count\": {},\n", f.count));
        match f.distinct_count {
            Some(d) => s.push_str(&format!("      \"distinct_count\": {d},\n")),
            None => s.push_str("      \"distinct_count\": null,\n"),
        }
        s.push_str(&format!("      \"first_seen\": {},\n", opt(&f.first_seen)));
        s.push_str(&format!("      \"last_seen\": {},\n", opt(&f.last_seen)));
        s.push_str(&format!("      \"source\": {},\n", opt(&f.source)));
        s.push_str("      \"sample\": [");
        for (j, line) in f.sample.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            s.push_str(&q(line));
        }
        s.push_str("]\n    }");
    }
    if findings.is_empty() {
        s.push_str("]\n");
    } else {
        s.push_str("\n  ]\n");
    }
    s.push('}');
    s
}

fn opt(o: &Option<String>) -> String {
    match o {
        Some(v) => q(v),
        None => "null".to_string(),
    }
}

/// Quote and escape a string as a JSON value.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
