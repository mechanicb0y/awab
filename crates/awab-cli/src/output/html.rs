//! Standalone, self-contained HTML triage report.
//!
//! Design: a calm "field report" rather than a dashboard. Severity is the only
//! saturated color and it carries the information — each finding is a record
//! with a severity-colored spine, and raw log lines sit in an inset terminal
//! block. No external fonts or assets, so the file works fully offline.

use super::Stats;
use awab_core::finding::Finding;
use awab_core::level::Level;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn level_slug(l: Level) -> &'static str {
    match l {
        Level::Critical => "critical",
        Level::High => "high",
        Level::Medium => "medium",
        Level::Low => "low",
        Level::Info => "info",
    }
}

const STYLE: &str = r#"
*,*::before,*::after{box-sizing:border-box}
:root{
  --paper:#f5f6f8; --surface:#ffffff; --ink:#19202a; --muted:#5d6977;
  --hair:#e4e8ed; --inset:#111821; --inset-ink:#c9d4e0;
  --crit:#b4232a; --high:#c15a12; --med:#9a7406; --low:#2d6c97; --info:#64748b;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#0f141a; --surface:#161d26; --ink:#dde4ec; --muted:#8c99a8;
  --hair:#232d39; --inset:#0a0e13; --inset-ink:#9fb0c2;
  --crit:#f0585f; --high:#f0863a; --med:#e0b43a; --low:#5aa6d8; --info:#93a2b4;
}}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  font-size:16px;line-height:1.55;padding:40px 20px}
.wrap{max-width:860px;margin:0 auto}
.mast{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;
  padding-bottom:18px;border-bottom:2px solid var(--ink)}
.brand{display:flex;align-items:center;gap:11px}
.brand svg{width:30px;height:30px;display:block}
.brand b{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1}
.kicker{color:var(--muted);font-weight:500;letter-spacing:.01em}
.gen{margin-left:auto;color:var(--muted);font-size:13.5px;font-variant-numeric:tabular-nums}
.summary{margin:20px 0 8px;font-size:17px}
.summary strong{font-weight:700}
.signal{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:18px 0 6px;
  background:var(--hair)}
.signal span{display:block}
.legend{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-bottom:34px;
  font-variant-numeric:tabular-nums}
.legend i{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:6px;vertical-align:baseline}
.rec{background:var(--surface);border:1px solid var(--hair);border-top:3px solid var(--bar);
  border-radius:4px;padding:18px 20px;margin-bottom:16px}
.rec h2{margin:0;font-size:18px;font-weight:700;letter-spacing:-.01em}
.rtop{display:flex;align-items:center;gap:12px;margin-bottom:4px}
.sev{font-size:12px;font-weight:800;letter-spacing:.04em;color:#fff;background:var(--bar);
  padding:3px 9px;border-radius:4px;text-transform:uppercase;flex:none}
.rid{margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:12.5px}
.facts{display:flex;flex-wrap:wrap;gap:6px 22px;margin:12px 0;color:var(--muted);font-size:14px;
  font-variant-numeric:tabular-nums}
.facts b{color:var(--ink);font-weight:600}
.facts code{font-family:var(--mono);color:var(--ink)}
.facts a{color:var(--bar);text-decoration:none;font-weight:600;border-bottom:1px solid transparent}
.facts a:hover{border-bottom-color:var(--bar)}
.why{margin:10px 0 14px;color:var(--ink);max-width:68ch}
.lines{background:var(--inset);border-radius:5px;padding:12px 14px;overflow-x:auto}
.lines div{font-family:var(--mono);font-size:12.5px;line-height:1.7;color:var(--inset-ink);
  white-space:pre}
.rec.critical{--bar:var(--crit)} .rec.high{--bar:var(--high)}
.rec.medium{--bar:var(--med)} .rec.low{--bar:var(--low)} .rec.info{--bar:var(--info)}
.allclear{background:var(--surface);border:1px solid var(--hair);border-radius:6px;
  padding:42px 24px;text-align:center}
.allclear b{font-size:19px} .allclear p{color:var(--muted);margin:.4rem 0 0}
.foot{margin-top:34px;padding-top:16px;border-top:1px solid var(--hair);
  color:var(--muted);font-size:13px}
.foot code{font-family:var(--mono)}
@media (max-width:560px){body{padding:24px 14px}.brand b{font-size:25px}.gen{margin-left:0;width:100%}}
@media print{body{background:#fff;color:#000;padding:0}.rec{break-inside:avoid}}
"#;

const MARK: &str = r##"<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><circle cx="16" cy="16" r="13" stroke="var(--ink)" stroke-width="2"/><path d="M16 3v6M16 23v6M3 16h6M23 16h6" stroke="var(--ink)" stroke-width="2"/><circle cx="16" cy="16" r="4" fill="var(--high)"/></svg>"##;

pub fn render(findings: &[Finding], stats: &Stats) -> String {
    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.level as usize] += 1;
    }
    let order = [
        (Level::Critical, "crit"),
        (Level::High, "high"),
        (Level::Medium, "med"),
        (Level::Low, "low"),
        (Level::Info, "info"),
    ];

    // Severity signal bar + legend.
    let total = findings.len().max(1);
    let mut signal = String::new();
    let mut legend = String::new();
    for (lvl, var) in order {
        let c = counts[lvl as usize];
        if c > 0 {
            let pct = (c as f64 / total as f64) * 100.0;
            signal.push_str(&format!(
                "<span style=\"width:{pct:.3}%;background:var(--{var})\"></span>"
            ));
        }
        legend.push_str(&format!(
            "<span><i style=\"background:var(--{var})\"></i>{} {}</span>",
            c,
            lvl.as_str()
        ));
    }

    // Finding records.
    let mut records = String::new();
    for f in findings {
        let slug = level_slug(f.level);
        let attack = f
            .mitre
            .as_ref()
            .map(|m| {
                format!(
                    "<span>ATT&amp;CK <a href=\"{}\" target=\"_blank\" rel=\"noopener\">{}</a> {}</span>",
                    esc(&m.url()),
                    esc(&m.technique),
                    esc(&m.tactic)
                )
            })
            .unwrap_or_default();
        let target = match (&f.group_field, &f.group_key) {
            (Some(field), Some(key)) => {
                let d = f
                    .distinct_count
                    .map(|d| format!(" ({d} distinct)"))
                    .unwrap_or_default();
                format!(
                    "<span><b>{}</b> <code>{}</code>{}</span>",
                    esc(field),
                    esc(key),
                    d
                )
            }
            _ => String::new(),
        };
        let window = match (&f.first_seen, &f.last_seen) {
            (Some(a), Some(b)) if a != b => format!("<span>{} → {}</span>", esc(a), esc(b)),
            (Some(a), _) => format!("<span>{}</span>", esc(a)),
            _ => String::new(),
        };
        let lines: String = f
            .sample
            .iter()
            .map(|l| format!("<div>{}</div>", esc(l)))
            .collect();
        records.push_str(&format!(
            "<article class=\"rec {slug}\">\
               <div class=\"rtop\"><span class=\"sev\">{sev}</span>\
               <h2>{title}</h2><span class=\"rid\">{id}</span></div>\
               <div class=\"facts\">{target}<span><b>{count}</b> event(s)</span>{window}{attack}</div>\
               <p class=\"why\">{why}</p>\
               <div class=\"lines\">{lines}</div>\
             </article>",
            slug = slug,
            sev = f.level.as_str(),
            title = esc(&f.title),
            id = esc(&f.rule_id),
            target = target,
            count = f.count,
            window = window,
            attack = attack,
            why = esc(f.description.trim()),
            lines = lines,
        ));
    }

    let body = if findings.is_empty() {
        r#"<div class="allclear"><b>No findings.</b><p>Nothing in these logs matched the loaded detection rules.</p></div>"#.to_string()
    } else {
        format!("<div class=\"signal\">{signal}</div><div class=\"legend\">{legend}</div>{records}")
    };

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>awab triage report</title><style>{style}</style></head><body><div class=\"wrap\">\
         <div class=\"mast\"><span class=\"brand\">{mark}<b>awab</b></span>\
         <span class=\"kicker\">threat triage report</span>\
         <span class=\"gen\">{generated}</span></div>\
         <p class=\"summary\">Scanned <strong>{events}</strong> events against \
         <strong>{rules}</strong> rules — <strong>{total}</strong> finding{plural}.</p>\
         {body}\
         <div class=\"foot\">Generated by <code>awab v{version}</code>, a zero-dependency Linux \
         log triage engine. Findings are leads to investigate, not confirmed incidents.</div>\
         </div></body></html>",
        style = STYLE,
        mark = MARK,
        generated = esc(&awab_core::util::format_utc(awab_core::util::now_epoch())),
        events = stats.events,
        rules = stats.rules,
        total = stats.findings,
        plural = if stats.findings == 1 { "" } else { "s" },
        body = body,
        version = env!("CARGO_PKG_VERSION"),
    )
}
