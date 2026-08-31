# Contributing to purge-warden

Thanks for your interest. purge-warden is a DNS filtering server written in
Rust — a Pi-hole / AdGuard Home alternative.

## Getting started

See [BUILDING.md](BUILDING.md) for system dependencies, then:

```bash
git clone https://github.com/purge-cc/Warden.git
cd Warden
cargo build --release
```

The binary lands at `target/release/warden`. For local DNS testing without
root, run on a high port and query it:

```bash
dig @127.0.0.1 -p 15353 example.com
```

## Before you open a pull request

These gates must pass — CI runs them on every PR:

```bash
./scripts/check_no_raw_fs_write.sh
cargo fmt --check
cargo clippy --all-targets
cargo test
```

`clippy` must succeed. Warnings are reported but do not fail CI yet.

If you touch config-writing code, also run `./scripts/check_no_raw_fs_write.sh`
(CI runs it too — it forbids raw `fs::write` on config paths).

## Guidelines

- **One logical change per PR.** Keep diffs focused and reviewable.
- **Add tests** for new behavior and every bug fix.
- **The DNS query hot path must stay zero-allocation and lock-free** — use
  `ArcSwap` / atomics, never `Mutex` / `RwLock` on the query path.
- **External blocklists are sandboxed** — never add code that lets an
  external list use `@@` allow rules, `$important`, or regex. Those powers
  belong only to operator-authored profile rules.
- Match the surrounding code's style and idioms.

## Commit messages

Use a `type: summary` subject line, where type is one of `feat`, `fix`,
`docs`, `refactor`, `test`, `perf`, `security`. Explain the *why* in the body.

## Reporting issues

- Regular bugs → open an issue using the bug-report template.
- **Security vulnerabilities → do NOT open a public issue.** Follow
  [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [AGPL-3.0-or-later license](LICENSE).
