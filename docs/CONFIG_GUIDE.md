# Configuration

The operator contract for this tree. If a sentence here disagrees with
`warden <cmd> --help` or `config/default.toml`, those two win.

## Where it lives

One TOML tree. After `scripts/install.sh` / `warden init` that is
`/etc/purge-warden/` (v1 layout). A git checkout used with `--config`
can point at a file anywhere.

Every mutating CLI command writes that tree and asks the daemon to
reload. There is no second live database.

Commented option list, same schema the daemon loads:

- [`config/default.toml`](../config/default.toml)

Validate before a reload:

```bash
warden config lint
```

## First boot

```bash
curl -fsSL https://get.purge.cc | sudo sh
```

or, from this repo, `cargo build --release` then
`sudo ./scripts/install.sh --build-from-source`.

`warden init` does **not** pick an upstream for you. Pass `--upstream`,
or let it adopt the resolvers already in this machine's `resolv.conf`.
There is no compiled-in public resolver.

Unknown clients: if `[server].default_profile` is unset, they get
`REFUSED`. Point it at a profile if you want them filtered instead.

A non-loopback bind needs a non-empty `server.allow_from` or the
validator refuses an open resolver.

## Day-to-day

```bash
sudo warden dashboard          # terminal UI (SSH-friendly)
warden --help                  # verbs that exist in *this* binary
warden <verb> --help           # flags for that verb
```

The dashboard is the operator UI. There is no web panel in this repo.

Lists come from [lists.purge.cc](https://lists.purge.cc) or any URL/file
you add. Direction (`allow` vs `deny`) is a property of *your* import,
not of the downloaded file. External list *bodies* cannot use `@@`,
`$important`, or regex — those stay in operator-authored rules.

DoH and DoT are configured in `[upstream]`. DNSSEC validation and
DNS-over-QUIC exist as **optional compile features** (`--features dnssec`,
`--features doq`); a default `cargo build` does not turn them on.

Anti-bypass is also operator-authored: name DoH/DoT hosts in
`[anti_bypass].extra_domains` or subscribe to a list. Warden ships no
resolver blocklist of its own.

## What this file is not

It is not a full flag-by-flag manual. Those rot. `config/default.toml`
and `warden --help` are generated from the same code the daemon runs.
