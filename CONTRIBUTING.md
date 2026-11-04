# Contributing to awab

Thanks for helping make Linux triage better for everyone. Rules, parsers, bug
fixes, and docs are all welcome.

## The golden rule: zero dependencies

`awab` is built with **only the Rust standard library**. This is a deliberate,
load-bearing design choice — it's what makes awab trivially auditable and
buildable offline on locked-down hosts. **Pull requests that add a third-party
crate to `awab-core` or `awab-cli` will not be merged** unless they come with a
strong, discussed justification. When in doubt, open an issue first.

## Good first contribution: a detection rule

The highest-value thing you can add is a **detection rule**. No Rust required —
see [rules/README.md](rules/README.md). Browse the
[`good first issue`](https://github.com/awab-alshandawi/awab/labels/good%20first%20issue)
label for rule requests.

## Development

```sh
cargo build                 # debug build
cargo test                  # run all tests (unit + integration)
cargo fmt --all             # format
cargo clippy --all-targets  # lint
./target/debug/awab scan tests/data/sample_auth.log
```

The workspace:

- `crates/awab-core` — parsers, the rule engine, the YAML/regex mini-parsers,
  and output models. No I/O, no presentation.
- `crates/awab-cli` — argument parsing, input reading, and rendering.
- `rules/` — the bundled detection rules, embedded at build time by `build.rs`.
- `tests/data/` — synthetic logs used by tests and for manual checks.

### Adding a parser

Implement a module under `crates/awab-core/src/parsers/`, emit normalized
`Event`s (fill `fields` with useful keys), add a `ParserKind` variant, wire it
into `parse_text` and `detect`, and add unit tests. Keep it std-only.

### Tests

Every parser and detector should have tests. Add a sample log under
`tests/data/` when it helps. CI runs `fmt`, `clippy`, `build`, and `test` on
Linux, macOS, and Windows.

## Commit & PR

- Keep PRs focused; one logical change each.
- Describe *what an attacker does* that a new rule catches, and include a sample
  log line in the PR description.
- Be kind. This is a community project.

## Supply-chain hardening

Because awab is a security tool, releases aim to follow OpenSSF best practices
(pinned CI actions, provenance, signed releases). If you're improving the
release/CI pipeline, that work is appreciated and tracked under the
`infrastructure` label.

## License

By contributing, you agree your contributions are dual-licensed under MIT and
Apache-2.0, matching the project.
