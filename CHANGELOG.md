# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
