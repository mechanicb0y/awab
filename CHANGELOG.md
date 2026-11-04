# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-04

### Added
- **auditd parser** for `/var/log/audit/audit.log` (EXECVE / SYSCALL / USER_*),
  auto-detected. EXECVE records are reconstructed into full command lines
  (hex-encoded args decoded), so behavioral rules work on everything a host
  runs, not just what goes through sudo.
- Five behavioral detections, matching both sudo and auditd command lines:
  - `awab-clear-logs` — deletion/truncation of /var/log or the journal (high)
  - `awab-clear-history` — shell history tampering (medium)
  - `awab-suid-set` — setting the SUID/SGID bit (high)
  - `awab-cron-persistence` — crontab / cron directory changes (medium)
  - `awab-systemd-persistence` — enabling or installing a systemd unit (medium)
- A helpful hint when a classic log path (e.g. `/var/log/auth.log`) doesn't
  exist, pointing at the `journalctl` pipe.

## [0.1.3] - 2026-11-04

### Changed
- Terminal output is now organized by rule: the summary shows one row per rule
  with an occurrence count, and detail blocks are grouped by rule and capped at
  3 each (with a "… and N more" note) so a flood of one detection no longer
  buries the rest. Use `-a`/`--full` for every finding, or `-f json`.

## [0.1.2] - 2026-11-04

### Added
- Three detections for backdoor-account and sudo-policy tampering, surfaced by
  real-world testing:
  - `awab-useradd-rootgroup` — new account with primary group GID 0 (high)
  - `awab-useradd-roothome` — new account homed in /root (high)
  - `awab-sudoers-modified` — a sudo command touching /etc/sudoers(.d) (high)
- The syslog parser now enriches user-creation events with `gid`, `home`, and
  `shell`, so rules can reason about them.

## [0.1.1] - 2026-11-04

### Fixed
- useradd `new group:` lines were misclassified as user-account creation,
  doubling the noise from account provisioning. Groups are now `group_add`.
- "Interactive shell launched via sudo" false-fired when a shell path was passed
  as an argument (e.g. `useradd -s /bin/bash`). Detection now matches the
  executable actually run via a new `command_bin` field.

## [0.1.0] - 2026-11-04

First public release.

### Added
- Zero-dependency (std-only) Rust engine: syslog/`auth.log` and web
  access-log parsers, a YAML rule format, and a correlation engine with
  sliding-window and distinct-count thresholds.
- `awab scan` with table, JSON, and standalone HTML output; reads files,
  directories, or stdin.
- `awab rules list` / `awab rules validate`.
- 10 bundled detections across SSH, privilege escalation, persistence, web, and
  execution, all mapped to MITRE ATT&CK.
- Built-in regex engine (practical subset) for rule authors.
- CI and cross-platform release workflows.

[Unreleased]: https://github.com/mechanicb0y/awab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mechanicb0y/awab/releases/tag/v0.1.0
