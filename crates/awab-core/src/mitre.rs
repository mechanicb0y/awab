//! Minimal MITRE ATT&CK reference carried on rules and findings.

#[derive(Debug, Clone)]
pub struct Mitre {
    /// Tactic slug, e.g. `credential-access`.
    pub tactic: String,
    /// Technique id, e.g. `T1110.001`.
    pub technique: String,
}

impl Mitre {
    /// Build the canonical ATT&CK URL for this technique.
    pub fn url(&self) -> String {
        let t = self.technique.trim().trim_start_matches('T');
        if let Some((parent, sub)) = t.split_once('.') {
            format!("https://attack.mitre.org/techniques/T{parent}/{sub}/")
        } else {
            format!("https://attack.mitre.org/techniques/T{t}/")
        }
    }
}
