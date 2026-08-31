# Changelog

The installable release is whatever [get.purge.cc](https://get.purge.cc)
prints at `/stable`. This tree's crate version is in `Cargo.toml`.

## [0.38.0]

Current public source. Single binary, one TOML config, systemd unit, TUI.
No Docker.

- Per-device profiles, schedules, and per-device exceptions
- Multi-format lists (domain-only, AdGuard `||domain^`, hosts)
- Encrypted upstreams: DNS-over-HTTPS and DNS-over-TLS. DNS-over-QUIC and
  DNSSEC validation are optional compile features (`--features doq`,
  `--features dnssec`) and are off in a default build
- CNAME inspection, response rate limiting, RFC 8482 ANY refusal,
  operator-authored anti-bypass, SSRF-hardened list downloads
- `warden dashboard` TUI, CLI, Unix-socket IPC, optional REST API
- Config is the source of truth; CLI mutations write TOML and reload

## [0.23.0-beta] — 2026-07-18

First GitHub beta of an earlier snapshot.
