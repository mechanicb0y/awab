# Writing awab rules

A rule is a small YAML file describing one detection. The engine is generic;
all detection logic lives here, so **adding a rule needs no Rust and no
rebuild** — just drop a `.yml` file in a directory and point `awab` at it:

```sh
awab rules validate ./my-rules
awab scan /var/log/auth.log --rules ./my-rules
```

Rules in this repo's `rules/` directory are compiled into the binary, so a
merged PR ships your detection to everyone.

## Anatomy of a rule

```yaml
id: awab-ssh-bruteforce            # unique, stable, kebab-case
title: SSH brute-force attempt     # short human title
description: >                     # folded text; shown in reports
  A single source IP produced many failed SSH logins in a short window.
author: awab                       # your handle (optional)
level: high                        # info | low | medium | high | critical
references:                        # optional links
  - https://attack.mitre.org/techniques/T1110/001/
mitre:
  tactic: credential-access        # ATT&CK tactic slug
  technique: T1110.001             # ATT&CK technique id
logsource:
  parser: syslog                   # optional: syslog | web
  service: sshd                    # optional: restrict by process/service
detection:
  selection:                       # field conditions (all must match)
    event_type: auth_failure
  group_by: source_ip              # optional correlation key
  timewindow: 60s                  # optional sliding window
  threshold: 5                     # optional: fire at N matches
  count_distinct: user             # optional: count distinct values instead
```

Only `id`, `title`, and `detection.selection` are strictly required.

## The `selection` block

Each entry is `field|operator: value`. **All entries must match** (AND); a list
of values for one entry matches if **any** matches (OR).

```yaml
detection:
  selection:
    event_type: auth_failure          # equals (default operator)
    message|contains: "Failed password"
    user|re: '^(root|admin)$'         # regex (use single quotes!)
    http_status|equals: ["401", "403"]
```

### Operators

| Operator | Meaning |
|----------|---------|
| *(none)* / `equals` | exact string match |
| `contains` | substring match |
| `startswith` / `endswith` | prefix / suffix match |
| `re` / `regex` | regular expression (subset — see below) |
| `gt` / `lt` | numeric greater-than / less-than |

### Fields you can match on

Virtual fields always available: `message`, `raw`, `process`, `host`, `parser`.

Enriched fields depend on the parser:

- **syslog / auth.log:** `event_type` (`auth_failure`, `auth_success`,
  `sudo_command`, `sudo_auth_failure`, `user_add`, `group_add`), `source_ip`,
  `user`, `auth_method`, `invalid_user`, `actor`, `target_user`, `command`,
  `command_bin`, `new_user`, `uid`, `gid`, `home`, `shell`, `new_group`,
  `service`
- **web access logs:** `event_type` (`web_request`), `source_ip`, `http_method`,
  `url`, `http_status`, `http_proto`, `user_agent`
- **auditd (`audit.log`):** `audit_type` (EXECVE, SYSCALL, …), `event_type`
  (`exec`, `syscall`, `auth`), `command`, `command_bin`, `exe`, `comm`,
  `audit_key`, `uid`, `auid`, `success`, `user`, `outcome`

**Tip:** `command` is populated by both sudo commands *and* auditd EXECVE
records, so a rule that matches `command` works across both without caring which
log it came from — that's how the SUID / log-wipe / persistence rules are
written.

## Correlation (catching bursts)

Add `group_by` + `threshold` to fire only when something happens repeatedly:

```yaml
detection:
  selection:
    event_type: auth_failure
  group_by: source_ip     # bucket events by this field
  timewindow: 60s         # (optional) only within a sliding window: s/m/h/d
  threshold: 5            # fire when a bucket reaches this many matches
```

Use `count_distinct` to count *distinct values* instead of raw events — ideal
for password spraying (many distinct users from one IP):

```yaml
  group_by: source_ip
  timewindow: 300s
  threshold: 5
  count_distinct: user
```

Severity automatically escalates one level at ≥3× the threshold and two levels
at ≥10×.

## The regex subset

`awab`'s built-in regex engine (no third-party crates) supports:

> literals, `.`, `*` `+` `?`, groups `( )`, alternation `|`, anchors `^` `$`,
> character classes `[...]` / `[^...]` with ranges, and `\d \D \w \W \s \S`.

It does **not** support backreferences, lookaround, `{m,n}` counts, non-greedy
quantifiers, or `\b`. These cover the vast majority of detections; if you need
more, combine `contains`/`startswith` conditions instead.

**Always single-quote regex values** so backslashes are preserved:

```yaml
url|re: '/(c99|r57|wso)\.php|eval\(|base64_decode'
```

## Checklist before you open a PR

- [ ] `id` is unique and kebab-case (`awab-<area>-<name>`)
- [ ] `level` reflects real-world severity (don't cry wolf)
- [ ] a `mitre` tactic + technique is set
- [ ] `awab rules validate path/to/rule.yml` passes
- [ ] you tested it against a sample log (add one under `tests/data/` if you can)

Thank you — a good rule helps every awab user at once.
