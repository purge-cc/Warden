# Security Policy

## Supported versions

purge-warden is in **public beta**. Security fixes land on the latest
released tag and `main`. There is no long-term-support branch yet; run a
recent release.

| Version | Supported |
|---------|-----------|
| latest release and `main` | ✅ |
| older pre-release tags | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately, in this order:

1. GitHub **[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)** — repository **Security** tab → **Report a vulnerability**. That form is the preferred path once this repository is public.
2. If the Security tab has no report form, [purge.cc/contact](https://purge.cc/contact).

Please include a description, affected version, and a reproduction (a
`dig` transcript or config snippet is ideal). We aim to acknowledge within
a few days and to coordinate a fix and disclosure timeline with you. As a
self-hosted project run by a small team, we appreciate good-faith,
responsible disclosure and will credit reporters who want it.

## Security design

purge-warden is built to be safe by default. Highlights:

- **Restrictive default.** Leave `[server].default_profile` unset and
  any source the resolver chain does not map gets `REFUSED`. Point it at
  a profile if you want unknown devices filtered rather than refused.
- **External lists are sandboxed.** Downloaded blocklists cannot use `@@`
  allow rules, `$important`, or regex — those powers belong only to
  operator-authored profile rules. This closes the supply-chain vector
  where a compromised list unblocks a domain.
- **CNAME deep inspection.** CNAME targets are checked against the
  blocklist, defeating cloaking bypass.
- **Anti-amplification.** Response Rate Limiting per /24 and RFC 8482
  ANY-query refusal (synthetic `HINFO`) blunt reflection/amplification;
  per-device token-bucket rate limiting is lock-free.
- **Anti-bypass is operator-authored.** Warden ships no resolver list of
  its own. Name DoH/DoT domains in `[anti_bypass].extra_domains` or
  subscribe to a list; see [`docs/CONFIG_GUIDE.md`](docs/CONFIG_GUIDE.md).
- **SSRF-hardened list downloads.** HTTPS-only, private-IP rejection,
  bounded response body.
- **Hardened local trust boundary.** The Unix control socket is
  `0o600` and enforces a peer-UID check; API tokens are generated with a
  CSPRNG (`OsRng`); config writes are atomic (temp-file + `fsync` +
  rename) with no world-readable race window.
- **MAC + IP device identification.** IP-only identity is trivially
  spoofable; device binding uses both.
- **No system OpenSSL.** TLS for DoH/DoT and list fetching is rustls +
  ring with embedded webpki roots — nothing links system OpenSSL.

Set `server.allow_from` when binding a non-loopback address so the
process is not an open resolver.

## Dependency advisory policy

`cargo audit` runs in CI when a push or a pull request changes
`Cargo.lock` or `Cargo.toml`, on a weekly schedule, and on demand (see
`.github/workflows/audit.yml`).

- **Vulnerability advisories fail the `audit` workflow.** The release
  workflow does not run it: before tagging, check that the last `audit`
  run passed and resolve any advisory.
- **Unmaintained / yanked / notice** warnings do not fail CI but are
  triaged: patch-bump, swap to a maintained alternative, or document a
  deferral with rationale.

Currently deferred. `.github/workflows/audit.yml` ignores the four rustls
advisories below; the other entries are warnings, which do not fail CI:

- `rustls 0.23.45` — `RUSTSEC-2026-0346`, `RUSTSEC-2026-0347`,
  `RUSTSEC-2026-0348` and `RUSTSEC-2026-0349`, published on 2026-10-14 and
  fixed in `rustls 0.23.46`, which the next release ships. Not reachable in
  warden: it uses the ring crypto provider, which offers no post-quantum key
  exchange to downgrade (`-0349`); rustls is built without its `brotli`
  feature (`-0348`); warden configures no Encrypted Client Hello (`-0347`);
  and warden never formats rustls session values or forwards rustls log
  records (`-0346`).
- `lru 0.12.5` — `RUSTSEC-2026-0002` (unsound `IterMut`) and
  `RUSTSEC-2026-0253` (panic safety of `LruCache::pop`). Transitive through
  `ratatui 0.29.0`. Not reachable: warden uses no `lru` API, and ratatui
  0.29.0 calls only `resize` and `get_or_insert`. A ratatui upgrade removes
  it.
- `paste 1.0.15` — `RUSTSEC-2024-0436` (unmaintained, no fixed release).
  Transitive through `ratatui 0.29.0`, compile-time macros only. The same
  ratatui upgrade removes it.
