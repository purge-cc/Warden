# Changelog

The installable release is whatever [get.purge.cc](https://get.purge.cc)
prints at `/stable`. This tree's crate version is in `Cargo.toml`.

## [0.40.1]

Current public source.

- The corpus ceiling now sits above the catalog it has to hold. A default
  install was landing at roughly 88% of its own limit and growing; crossing it
  froze the blocklists — they stopped updating — with nothing said. `warden
  status`, the API and the metrics now report a frozen corpus, and a source
  that outgrows its per-source cap freezes at its last good copy instead of
  disappearing from the corpus entirely
- An upgrade that takes its time is no longer reported as a failure. The
  installer waited 30s for the DNS listener, but the daemon binds only after
  loading the whole corpus, which is minutes on a large one. It now waits
  (`PURGE_LISTENER_TIMEOUT`, default 300s), tells you it is still starting, and
  fails fast if the service actually dies
- A failed lookup is no longer read as a successful one. The verification step
  merged `dig`'s stderr into its answer, so a connection timeout sat where an
  address belongs and passed a non-empty check
- The rollback copy taken before a config migration is visible again.
  `warden config restore --list` skipped it by name and could not read it
  either, so it reported no backups over a directory that held one. It is now
  listed, and a backup that cannot be read says so instead of being reported
  as absent

## [0.38.0] Single binary, one TOML config, systemd unit, TUI.
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
