//! awab-core — the engine behind awab.
//!
//! Pipeline: raw text -> [`parsers`] -> [`event::Event`]s -> [`engine::scan`]
//! against [`rule::Rule`]s -> [`finding::Finding`]s.
//!
//! The crate uses only the Rust standard library — no third-party crates — so
//! the supply chain is trivially auditable and it builds offline anywhere.

pub mod engine;
pub mod event;
pub mod finding;
pub mod level;
pub mod loader;
pub mod mitre;
pub mod parsers;
pub mod regexlite;
pub mod rule;
pub mod util;
pub mod yaml;

pub use engine::scan;
pub use event::Event;
pub use finding::Finding;
pub use level::Level;
pub use rule::Rule;

/// Convenience: parse text with a parser and immediately scan it with rules.
pub fn parse_and_scan(
    text: &str,
    kind: parsers::ParserKind,
    source: Option<&str>,
    rules: &[Rule],
) -> Vec<Finding> {
    let events = parsers::parse_text(text, kind, source);
    engine::scan(&events, rules)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use parsers::ParserKind;

    fn rule_from_yaml(src: &str) -> Rule {
        let v = yaml::parse_document(src).expect("yaml parses");
        Rule::from_value(&v).expect("rule builds")
    }

    fn bruteforce_rule() -> Rule {
        rule_from_yaml(
            r#"
id: awab-ssh-bruteforce
title: SSH Brute Force
description: Many failed SSH logins from one source IP.
level: high
mitre:
  tactic: credential-access
  technique: T1110.001
logsource:
  service: sshd
detection:
  selection:
    event_type: auth_failure
  group_by: source_ip
  timewindow: 60s
  threshold: 5
"#,
        )
    }

    #[test]
    fn detects_bruteforce_burst() {
        let mut lines = String::new();
        for i in 0..6 {
            lines.push_str(&format!(
                "Nov  4 10:18:0{i} web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 5432{i} ssh2\n"
            ));
        }
        let rules = vec![bruteforce_rule()];
        let findings = parse_and_scan(&lines, ParserKind::Syslog, Some("auth.log"), &rules);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "awab-ssh-bruteforce");
        assert_eq!(f.group_key.as_deref(), Some("203.0.113.5"));
        assert!(f.count >= 5);
    }

    #[test]
    fn quiet_traffic_does_not_fire() {
        let lines = "Nov  4 10:18:01 web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n";
        let rules = vec![bruteforce_rule()];
        let findings = parse_and_scan(lines, ParserKind::Syslog, None, &rules);
        assert!(findings.is_empty());
    }

    #[test]
    fn builtin_rules_load_cleanly() {
        let loaded = loader::load_builtin();
        assert!(loaded.rules.len() >= 5, "expected several bundled rules");
        assert!(
            loaded.errors.is_empty(),
            "bundled rules should all be valid: {:?}",
            loaded.errors
        );
    }
}
