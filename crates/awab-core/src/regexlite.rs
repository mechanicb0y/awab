//! A compact, dependency-free regular-expression engine (recursive
//! backtracking) supporting a practical subset:
//!
//!   literals, `.`, `*` `+` `?` (greedy), `(` `)` groups, `|` alternation,
//!   anchors `^` `$`, character classes `[...]` / `[^...]` with ranges, and the
//!   escapes `\d \D \w \W \s \S \n \t \r` plus escaped metacharacters.
//!
//! Not supported: backreferences, lookaround, non-greedy quantifiers, `{m,n}`
//! counts, and word boundaries (`\b`). Inputs are single log lines, so `.`
//! does not match `\n`. This is enough for detection rules; authors who need
//! more can keep using `contains` / `startswith` ops.

#[derive(Debug)]
enum Node {
    Empty,
    Char(char),
    Any,
    Class { neg: bool, items: Vec<ClassItem> },
    Start,
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    Quest(Box<Node>),
}

#[derive(Debug)]
enum ClassItem {
    Range(char, char),
    Single(char),
    Digit,
    NotDigit,
    Word,
    NotWord,
    Space,
    NotSpace,
}

pub struct Regex {
    root: Node,
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, String> {
        let mut p = P {
            c: pattern.chars().collect(),
            i: 0,
        };
        let root = p.parse_alt()?;
        if p.i != p.c.len() {
            return Err(format!("unexpected `{}` in regex", p.c[p.i]));
        }
        Ok(Regex { root })
    }

    /// True if the pattern matches anywhere in `text`.
    pub fn is_match(&self, text: &str) -> bool {
        let s: Vec<char> = text.chars().collect();
        for start in 0..=s.len() {
            if m(&self.root, &s, start, &|_| true) {
                return true;
            }
        }
        false
    }
}

// ---- matcher ----

fn m(node: &Node, s: &[char], pos: usize, k: &dyn Fn(usize) -> bool) -> bool {
    match node {
        Node::Empty => k(pos),
        Node::Char(c) => pos < s.len() && s[pos] == *c && k(pos + 1),
        Node::Any => pos < s.len() && s[pos] != '\n' && k(pos + 1),
        Node::Class { neg, items } => {
            pos < s.len() && class_match(items, *neg, s[pos]) && k(pos + 1)
        }
        Node::Start => pos == 0 && k(pos),
        Node::End => pos == s.len() && k(pos),
        Node::Concat(v) => concat(v, 0, s, pos, k),
        Node::Alt(v) => v.iter().any(|n| m(n, s, pos, k)),
        Node::Star(n) => star(n, s, pos, k),
        Node::Plus(n) => m(n, s, pos, &|p| star(n, s, p, k)),
        Node::Quest(n) => m(n, s, pos, k) || k(pos),
    }
}

fn concat(v: &[Node], i: usize, s: &[char], pos: usize, k: &dyn Fn(usize) -> bool) -> bool {
    if i == v.len() {
        k(pos)
    } else {
        m(&v[i], s, pos, &|p| concat(v, i + 1, s, p, k))
    }
}

fn star(n: &Node, s: &[char], pos: usize, k: &dyn Fn(usize) -> bool) -> bool {
    m(n, s, pos, &|p| p > pos && star(n, s, p, k)) || k(pos)
}

fn class_match(items: &[ClassItem], neg: bool, c: char) -> bool {
    let matched = items.iter().any(|it| match it {
        ClassItem::Range(a, b) => c >= *a && c <= *b,
        ClassItem::Single(x) => c == *x,
        ClassItem::Digit => c.is_ascii_digit(),
        ClassItem::NotDigit => !c.is_ascii_digit(),
        ClassItem::Word => c.is_alphanumeric() || c == '_',
        ClassItem::NotWord => !(c.is_alphanumeric() || c == '_'),
        ClassItem::Space => c.is_whitespace(),
        ClassItem::NotSpace => !c.is_whitespace(),
    });
    if neg {
        !matched
    } else {
        matched
    }
}

// ---- parser ----

struct P {
    c: Vec<char>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn next(&mut self) -> Option<char> {
        let r = self.peek();
        if r.is_some() {
            self.i += 1;
        }
        r
    }

    fn parse_alt(&mut self) -> Result<Node, String> {
        let mut alts = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.next();
            alts.push(self.parse_concat()?);
        }
        if alts.len() == 1 {
            Ok(alts.pop().unwrap())
        } else {
            Ok(Node::Alt(alts))
        }
    }

    fn parse_concat(&mut self) -> Result<Node, String> {
        let mut seq = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == '|' || ch == ')' {
                break;
            }
            let atom = self.parse_atom()?;
            seq.push(self.parse_repeat(atom)?);
        }
        match seq.len() {
            0 => Ok(Node::Empty),
            1 => Ok(seq.pop().unwrap()),
            _ => Ok(Node::Concat(seq)),
        }
    }

    fn parse_repeat(&mut self, atom: Node) -> Result<Node, String> {
        match self.peek() {
            Some('*') => {
                self.next();
                Ok(Node::Star(Box::new(atom)))
            }
            Some('+') => {
                self.next();
                Ok(Node::Plus(Box::new(atom)))
            }
            Some('?') => {
                self.next();
                Ok(Node::Quest(Box::new(atom)))
            }
            _ => Ok(atom),
        }
    }

    fn parse_atom(&mut self) -> Result<Node, String> {
        match self.next() {
            Some('(') => {
                let inner = self.parse_alt()?;
                if self.next() != Some(')') {
                    return Err("unclosed `(`".into());
                }
                Ok(inner)
            }
            Some('[') => self.parse_class(),
            Some('.') => Ok(Node::Any),
            Some('^') => Ok(Node::Start),
            Some('$') => Ok(Node::End),
            Some('\\') => self.parse_escape(),
            Some(c) => Ok(Node::Char(c)),
            None => Ok(Node::Empty),
        }
    }

    fn parse_escape(&mut self) -> Result<Node, String> {
        match self.next() {
            Some('d') => Ok(class1(ClassItem::Digit)),
            Some('D') => Ok(class1(ClassItem::NotDigit)),
            Some('w') => Ok(class1(ClassItem::Word)),
            Some('W') => Ok(class1(ClassItem::NotWord)),
            Some('s') => Ok(class1(ClassItem::Space)),
            Some('S') => Ok(class1(ClassItem::NotSpace)),
            Some('n') => Ok(Node::Char('\n')),
            Some('t') => Ok(Node::Char('\t')),
            Some('r') => Ok(Node::Char('\r')),
            Some(c) => Ok(Node::Char(c)),
            None => Err("trailing backslash".into()),
        }
    }

    fn parse_class(&mut self) -> Result<Node, String> {
        let neg = if self.peek() == Some('^') {
            self.next();
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None => return Err("unclosed `[`".into()),
                Some(']') => {
                    self.next();
                    break;
                }
                Some('\\') => {
                    self.next();
                    let e = self.next().ok_or("trailing backslash in class")?;
                    match e {
                        'd' => items.push(ClassItem::Digit),
                        'D' => items.push(ClassItem::NotDigit),
                        'w' => items.push(ClassItem::Word),
                        'W' => items.push(ClassItem::NotWord),
                        's' => items.push(ClassItem::Space),
                        'S' => items.push(ClassItem::NotSpace),
                        'n' => items.push(ClassItem::Single('\n')),
                        't' => items.push(ClassItem::Single('\t')),
                        'r' => items.push(ClassItem::Single('\r')),
                        other => items.push(ClassItem::Single(other)),
                    }
                }
                Some(c) => {
                    self.next();
                    if self.peek() == Some('-')
                        && self.c.get(self.i + 1).map(|&n| n != ']').unwrap_or(false)
                    {
                        self.next(); // consume '-'
                        let end = self.next().unwrap();
                        let end = if end == '\\' {
                            match self.next() {
                                Some('n') => '\n',
                                Some('t') => '\t',
                                Some('r') => '\r',
                                Some(x) => x,
                                None => '\\',
                            }
                        } else {
                            end
                        };
                        items.push(ClassItem::Range(c, end));
                    } else {
                        items.push(ClassItem::Single(c));
                    }
                }
            }
        }
        Ok(Node::Class { neg, items })
    }
}

fn class1(item: ClassItem) -> Node {
    Node::Class {
        neg: false,
        items: vec![item],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Regex::new(p).unwrap().is_match(t)
    }

    #[test]
    fn literals_and_anchors() {
        assert!(m("abc", "xxabcyy"));
        assert!(m("^abc$", "abc"));
        assert!(!m("^abc$", "abcd"));
    }

    #[test]
    fn digits_and_quantifiers() {
        assert!(m(r"\d+", "abc123"));
        assert!(m(r"^\d+$", "4567"));
        assert!(!m(r"^\d+$", "12a"));
        assert!(m("ab?c", "ac"));
        assert!(m("ab?c", "abc"));
        assert!(m("a.*z", "a___z"));
    }

    #[test]
    fn classes() {
        assert!(m("[a-z]+", "hello"));
        assert!(!m("^[a-z]+$", "Hello"));
        assert!(m("[^0-9]", "a"));
        assert!(!m("^[^0-9]$", "5"));
    }

    #[test]
    fn alternation_and_groups() {
        let shell = r"(^|/)(bash|sh|zsh|dash|ksh|csh|fish)($| )";
        assert!(m(shell, "/bin/bash"));
        assert!(m(shell, "/usr/bin/zsh"));
        assert!(m(shell, "/bin/bash -c whoami"));
        assert!(!m(shell, "/usr/bin/vim"));
        assert!(!m(shell, "/bin/false"));
    }

    #[test]
    fn webshell_pattern() {
        let p = r"\.(php|jsp|asp|aspx)\?";
        assert!(m(p, "GET /uploads/x.php?cmd=id"));
        assert!(!m(p, "GET /index.html"));
    }
}
