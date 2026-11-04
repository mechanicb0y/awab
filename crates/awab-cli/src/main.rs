//! awab — fast, zero-dependency Linux log triage & threat-hunting engine.

mod input;
mod output;

use awab_core::level::Level;
use awab_core::loader::{self, Loaded};
use awab_core::parsers::ParserKind;
use std::path::PathBuf;
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(e) = run() {
        eprintln!("awab: error: {e}");
        exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = match args.first() {
        Some(a) => a.as_str(),
        None => {
            print_help();
            return Ok(());
        }
    };
    match first {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" | "version" => {
            println!("awab {VERSION}");
            Ok(())
        }
        "scan" => cmd_scan(&args[1..]),
        "rules" => cmd_rules(&args[1..]),
        "update" => cmd_update(),
        other => Err(format!("unknown command `{other}` (try `awab --help`)")),
    }
}

fn print_help() {
    println!(
        "awab {VERSION} — fast, zero-dependency Linux log triage & threat-hunting engine\n\n\
         USAGE:\n\
         \x20 awab scan [TARGET...] [OPTIONS]   Scan logs (files, dirs, or - for stdin)\n\
         \x20 awab rules list [OPTIONS]          List loaded detection rules\n\
         \x20 awab rules validate [PATH...]      Validate rule files\n\
         \x20 awab update                        How to update the rule set\n\n\
         SCAN OPTIONS:\n\
         \x20 --rules <DIR>       Load extra rules from a directory\n\
         \x20 --no-builtin        Ignore the rules embedded in the binary\n\
         \x20 --parser <P>        auto | syslog   (default: auto)\n\
         \x20 --format <F>        table | json    (default: table)\n\
         \x20 --min-level <L>     info|low|medium|high|critical (default: info)\n\
         \x20 --html <FILE>       Also write a standalone HTML report\n\
         \x20 --no-color          Disable colored output\n\n\
         EXAMPLES:\n\
         \x20 awab scan /var/log/auth.log\n\
         \x20 journalctl -o short-iso | awab scan -\n\
         \x20 awab scan /var/log --format json > findings.json\n\
         \x20 awab scan auth.log --html report.html\n\n\
         Exit codes: 0 = no high+ findings, 1 = high/critical findings, 2 = error."
    );
}

fn next_val(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("`{flag}` needs a value"))
}

fn gather_rules(external: Option<&PathBuf>, no_builtin: bool) -> Result<Loaded, String> {
    let mut loaded = if no_builtin {
        Loaded::default()
    } else {
        loader::load_builtin()
    };
    if let Some(dir) = external {
        let extra = loader::load_dir(dir)?;
        loaded.rules.extend(extra.rules);
        loaded.errors.extend(extra.errors);
    }
    Ok(loaded)
}

fn cmd_scan(args: &[String]) -> Result<(), String> {
    let mut targets: Vec<String> = Vec::new();
    let mut rules_dir: Option<PathBuf> = None;
    let mut no_builtin = false;
    let mut parser = ParserKind::Auto;
    let mut format = "table".to_string();
    let mut min_level = Level::Info;
    let mut html: Option<PathBuf> = None;
    let mut no_color = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rules" => rules_dir = Some(PathBuf::from(next_val(&mut it, "--rules")?)),
            "--no-builtin" => no_builtin = true,
            "--parser" => {
                let v = next_val(&mut it, "--parser")?;
                parser = ParserKind::from_name(&v)
                    .ok_or_else(|| format!("unknown parser `{v}` (use auto|syslog)"))?;
            }
            "--format" => {
                format = next_val(&mut it, "--format")?;
                if format != "table" && format != "json" {
                    return Err(format!("unknown format `{format}` (use table|json)"));
                }
            }
            "--min-level" => {
                let v = next_val(&mut it, "--min-level")?;
                min_level = Level::parse(&v).ok_or_else(|| format!("unknown level `{v}`"))?;
            }
            "--html" => html = Some(PathBuf::from(next_val(&mut it, "--html")?)),
            "--no-color" => no_color = true,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            s if s.starts_with("--") => return Err(format!("unknown option `{s}`")),
            s => targets.push(s.to_string()),
        }
    }

    let loaded = gather_rules(rules_dir.as_ref(), no_builtin)?;
    for e in &loaded.errors {
        eprintln!("awab: warning: skipped rule in {}: {}", e.source, e.error);
    }
    if loaded.rules.is_empty() {
        return Err("no rules loaded — nothing to scan with".into());
    }

    let sources = input::collect_sources(&targets)?;
    if sources.is_empty() {
        return Err("no input read (pass a file/directory, or pipe logs and use `-`)".into());
    }

    let mut events = Vec::new();
    for src in &sources {
        let mut evs = awab_core::parsers::parse_text(&src.text, parser, Some(&src.name));
        events.append(&mut evs);
    }

    let mut findings = awab_core::engine::scan(&events, &loaded.rules);
    findings.retain(|f| f.level >= min_level);

    let stats = output::Stats {
        rules: loaded.rules.len(),
        events: events.len(),
        findings: findings.len(),
    };

    if let Some(path) = &html {
        let page = output::html::render(&findings, &stats);
        std::fs::write(path, page).map_err(|e| format!("writing {}: {e}", path.display()))?;
        eprintln!("awab: wrote HTML report to {}", path.display());
    }

    if format == "json" {
        output::json::render(&findings, &stats)?;
    } else {
        let color = !no_color && std::env::var_os("NO_COLOR").is_none();
        output::terminal::render(&findings, &stats, color);
    }

    if findings.iter().any(|f| f.level >= Level::High) {
        exit(1);
    }
    Ok(())
}

fn cmd_rules(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    match sub {
        "list" => {
            let mut rules_dir: Option<PathBuf> = None;
            let mut no_builtin = false;
            let mut it = args[1.min(args.len())..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--rules" => rules_dir = Some(PathBuf::from(next_val(&mut it, "--rules")?)),
                    "--no-builtin" => no_builtin = true,
                    s => return Err(format!("unknown option `{s}`")),
                }
            }
            let loaded = gather_rules(rules_dir.as_ref(), no_builtin)?;
            output::terminal::render_rule_list(&loaded.rules);
            for e in &loaded.errors {
                eprintln!("awab: warning: {}: {}", e.source, e.error);
            }
            Ok(())
        }
        "validate" => {
            let paths: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();
            let loaded = if paths.is_empty() {
                loader::load_builtin()
            } else {
                let mut acc = Loaded::default();
                for p in &paths {
                    if p.is_dir() {
                        let l = loader::load_dir(p)?;
                        acc.rules.extend(l.rules);
                        acc.errors.extend(l.errors);
                    } else {
                        let text = std::fs::read_to_string(p)
                            .map_err(|e| format!("reading {}: {e}", p.display()))?;
                        loader::parse_str(&p.display().to_string(), &text, &mut acc);
                    }
                }
                acc
            };
            for e in &loaded.errors {
                eprintln!("✗ {}: {}", e.source, e.error);
            }
            println!(
                "{} rule(s) valid, {} problem(s) found.",
                loaded.rules.len(),
                loaded.errors.len()
            );
            if !loaded.errors.is_empty() {
                exit(1);
            }
            Ok(())
        }
        other => Err(format!(
            "unknown rules subcommand `{other}` (use list|validate)"
        )),
    }
}

fn cmd_update() -> Result<(), String> {
    println!(
        "awab ships its rule set embedded in the binary.\n\
         To get the latest community rules: update awab itself, or pass a local\n\
         rules directory with `awab scan --rules <DIR>`.\n\
         A live rule-feed fetcher is planned for a future release."
    );
    Ok(())
}
