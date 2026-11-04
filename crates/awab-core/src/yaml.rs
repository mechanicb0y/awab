//! A small, dependency-free YAML *subset* parser — just enough for awab rule
//! files. It is intentionally not a full YAML implementation.
//!
//! Supported:
//!   * block mappings (`key: value`) with 2-or-more-space indentation
//!   * block sequences (`- item`) of scalars
//!   * nested mappings / sequences
//!   * plain, single-quoted, and double-quoted scalars
//!   * folded (`>`) and literal (`|`) block scalars
//!   * inline flow lists (`[a, b, c]`)
//!   * `#` comments on their own line, and `---` document separators
//!
//! Not supported (documented for rule authors): anchors/aliases, inline flow
//! maps, complex keys, and inline trailing comments. Put a `#` comment on its
//! own line, and prefer single quotes for regex values so backslashes are kept.

/// A parsed YAML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Map(v) => Some(v),
            _ => None,
        }
    }
    /// Look up a key in a mapping.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Content,
    Blank,
    Comment,
}

struct Line {
    indent: usize,
    text: String,
    kind: Kind,
}

struct Parser {
    lines: Vec<Line>,
}

/// Parse one or more `---`-separated documents.
pub fn parse_documents(input: &str) -> Result<Vec<Value>, String> {
    let mut docs = Vec::new();
    let mut current = String::new();
    for raw in input.lines() {
        if raw.trim_end() == "---" {
            if !current.trim().is_empty() {
                docs.push(parse_document(&current)?);
            }
            current.clear();
        } else {
            current.push_str(raw);
            current.push('\n');
        }
    }
    if !current.trim().is_empty() {
        docs.push(parse_document(&current)?);
    }
    Ok(docs)
}

/// Parse a single document.
pub fn parse_document(input: &str) -> Result<Value, String> {
    let mut lines = Vec::new();
    for raw in input.lines() {
        let no_cr = raw.strip_suffix('\r').unwrap_or(raw);
        let indent = no_cr.len() - no_cr.trim_start_matches(' ').len();
        if no_cr.contains('\t') && no_cr[..indent].contains('\t') {
            return Err("tabs are not allowed for indentation".into());
        }
        let text = no_cr[indent..].to_string();
        let kind = if text.trim().is_empty() {
            Kind::Blank
        } else if text.trim_start().starts_with('#') {
            Kind::Comment
        } else {
            Kind::Content
        };
        lines.push(Line { indent, text, kind });
    }
    let p = Parser { lines };
    let mut idx = 0;
    match p.next_content(idx) {
        Some(i) => {
            idx = i;
            let base = p.lines[idx].indent;
            p.parse_collection(&mut idx, base)
        }
        None => Ok(Value::Map(Vec::new())),
    }
}

impl Parser {
    fn next_content(&self, mut idx: usize) -> Option<usize> {
        while idx < self.lines.len() {
            if self.lines[idx].kind == Kind::Content {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }

    fn parse_collection(&self, idx: &mut usize, indent: usize) -> Result<Value, String> {
        let text = &self.lines[*idx].text;
        if text == "-" || text.starts_with("- ") {
            self.parse_sequence(idx, indent)
        } else {
            self.parse_mapping(idx, indent)
        }
    }

    fn parse_mapping(&self, idx: &mut usize, indent: usize) -> Result<Value, String> {
        let mut entries = Vec::new();
        while let Some(li) = self.next_content(*idx) {
            *idx = li;
            let line = &self.lines[*idx];
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                return Err(format!("unexpected indentation at: {}", line.text));
            }
            if line.text == "-" || line.text.starts_with("- ") {
                return Err(format!(
                    "unexpected sequence item in mapping: {}",
                    line.text
                ));
            }
            let (key, rest) = split_kv(&line.text)?;
            *idx += 1;
            let value = self.parse_value(&rest, indent, idx)?;
            entries.push((key, value));
        }
        Ok(Value::Map(entries))
    }

    fn parse_sequence(&self, idx: &mut usize, indent: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some(li) = self.next_content(*idx) {
            *idx = li;
            let line = &self.lines[*idx];
            if line.indent != indent || !(line.text == "-" || line.text.starts_with("- ")) {
                break;
            }
            let rest = if line.text == "-" {
                ""
            } else {
                line.text[2..].trim()
            };
            *idx += 1;
            if rest.is_empty() {
                // Nested block as the item.
                if let Some(ni) = self.next_content(*idx) {
                    let child = self.lines[ni].indent;
                    if child > indent {
                        *idx = ni;
                        items.push(self.parse_collection(idx, child)?);
                        continue;
                    }
                }
                items.push(Value::Str(String::new()));
            } else {
                items.push(Value::Str(unquote(rest)));
            }
        }
        Ok(Value::List(items))
    }

    fn parse_value(
        &self,
        rest: &str,
        parent_indent: usize,
        idx: &mut usize,
    ) -> Result<Value, String> {
        let rest = rest.trim();
        if rest.is_empty() {
            if let Some(ni) = self.next_content(*idx) {
                let child = self.lines[ni].indent;
                if child > parent_indent {
                    *idx = ni;
                    return self.parse_collection(idx, child);
                }
            }
            return Ok(Value::Str(String::new()));
        }
        if rest == ">" || rest == ">-" || rest == "|" || rest == "|-" {
            let folded = rest.starts_with('>');
            return Ok(Value::Str(self.collect_block_scalar(
                parent_indent,
                idx,
                folded,
            )));
        }
        if rest.starts_with('[') && rest.ends_with(']') {
            return Ok(parse_flow_list(rest));
        }
        Ok(Value::Str(unquote(rest)))
    }

    fn collect_block_scalar(&self, parent_indent: usize, idx: &mut usize, folded: bool) -> String {
        let mut base: Option<usize> = None;
        let mut collected: Vec<String> = Vec::new();
        while *idx < self.lines.len() {
            let l = &self.lines[*idx];
            match l.kind {
                Kind::Blank => {
                    collected.push(String::new());
                    *idx += 1;
                }
                Kind::Content | Kind::Comment => {
                    if l.indent > parent_indent {
                        let b = *base.get_or_insert(l.indent);
                        let extra = l.indent.saturating_sub(b);
                        collected.push(format!("{}{}", " ".repeat(extra), l.text));
                        *idx += 1;
                    } else {
                        break;
                    }
                }
            }
        }
        if folded {
            let mut out = String::new();
            let mut para = String::new();
            for line in &collected {
                if line.trim().is_empty() {
                    if !para.is_empty() {
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(para.trim());
                        para.clear();
                    }
                } else {
                    if !para.is_empty() {
                        para.push(' ');
                    }
                    para.push_str(line.trim());
                }
            }
            if !para.is_empty() {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(para.trim());
            }
            out.trim().to_string()
        } else {
            while collected
                .last()
                .map(|s| s.trim().is_empty())
                .unwrap_or(false)
            {
                collected.pop();
            }
            collected.join("\n")
        }
    }
}

/// Split `key: value` at the first `:` that is followed by a space or EOL.
fn split_kv(text: &str) -> Result<(String, String), String> {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' {
            match bytes.get(i + 1) {
                None => return Ok((unquote(text[..i].trim()), String::new())),
                Some(&b' ') => return Ok((unquote(text[..i].trim()), text[i + 1..].to_string())),
                _ => continue,
            }
        }
    }
    Err(format!("expected `key: value`, found: {text}"))
}

fn parse_flow_list(s: &str) -> Value {
    let inner = &s[1..s.len() - 1];
    let items = inner
        .split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| Value::Str(unquote(x)))
        .collect();
    Value::List(items)
}

/// Strip quotes and process escapes for a scalar.
fn unquote(s: &str) -> String {
    let s = s.trim();
    let bytes = s.as_bytes();
    if s.len() >= 2 && bytes[0] == b'"' && bytes[s.len() - 1] == b'"' {
        unescape_double(&s[1..s.len() - 1])
    } else if s.len() >= 2 && bytes[0] == b'\'' && bytes[s.len() - 1] == b'\'' {
        s[1..s.len() - 1].replace("''", "'")
    } else {
        s.to_string()
    }
}

fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                // Unknown escape: keep both chars so regex escapes survive.
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_rule() {
        let yaml = r#"
id: awab-ssh-bruteforce
title: SSH brute-force attempt
description: >
  A single source IP produced many failed SSH logins
  in a short window.
level: high
references:
  - https://attack.mitre.org/techniques/T1110/001/
mitre:
  tactic: credential-access
  technique: T1110.001
logsource:
  parser: syslog
  service: sshd
detection:
  selection:
    event_type: auth_failure
  group_by: source_ip
  timewindow: 60s
  threshold: 5
"#;
        let v = parse_document(yaml).unwrap();
        assert_eq!(v.get("id").unwrap().as_str(), Some("awab-ssh-bruteforce"));
        assert_eq!(v.get("level").unwrap().as_str(), Some("high"));
        let refs = v.get("references").unwrap().as_list().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            v.get("mitre").unwrap().get("technique").unwrap().as_str(),
            Some("T1110.001")
        );
        let det = v.get("detection").unwrap();
        assert_eq!(det.get("threshold").unwrap().as_str(), Some("5"));
        let sel = det.get("selection").unwrap();
        assert_eq!(
            sel.get("event_type").unwrap().as_str(),
            Some("auth_failure")
        );
        let desc = v.get("description").unwrap().as_str().unwrap();
        assert!(desc.contains("single source IP"));
        assert!(!desc.contains('\n')); // folded to one line
    }

    #[test]
    fn keeps_regex_in_single_quotes() {
        let yaml = "detection:\n  selection:\n    command|re: '(^|/)(bash|sh)($| )'\n";
        let v = parse_document(yaml).unwrap();
        let re = v
            .get("detection")
            .unwrap()
            .get("selection")
            .unwrap()
            .get("command|re")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(re, "(^|/)(bash|sh)($| )");
    }

    #[test]
    fn quoted_number_stays_string() {
        let yaml = "uid: \"0\"\n";
        let v = parse_document(yaml).unwrap();
        assert_eq!(v.get("uid").unwrap().as_str(), Some("0"));
    }
}
