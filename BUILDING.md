# Building purge-warden

System dependencies required to build and run purge-warden. A pre-built
binary from [get.purge.cc](https://get.purge.cc) needs none of the
compile-time packages.

Minimum Rust version is **1.94** (see `rust-version` in `Cargo.toml`).

## Build dependencies (dev only)

| Package | Fedora (`dnf`) | Debian/Ubuntu (`apt`) | Purpose |
|---------|---------------|----------------------|---------|
| gcc | `gcc` | `build-essential` | C compiler (linker, jemalloc, native deps) |
| g++ | `gcc-c++` | (in `build-essential`) | C++ compiler — jemalloc and zstd need it alongside cc |
| make | `make` | `make` | Build automation |
| pkg-config | `pkgconf-pkg-config` | `pkg-config` | Locate system libraries |
| git | `git` | `git` | Version control |
| curl | `curl` | `curl` | Fetch rustup |
| Rust toolchain | via `rustup` | via `rustup` | Compiler + cargo (stable channel) |
| ripgrep | `ripgrep` | `ripgrep` | `scripts/check_no_raw_fs_write.sh` (the `make test` lint) |

> **No OpenSSL.** The TLS stack is rustls + ring end-to-end (DoH/DoT,
> list fetcher) with embedded webpki roots — nothing in the dependency
> tree links system OpenSSL, so `libssl-dev` / `openssl-devel` and perl
> are not needed.

> **`cmake` is optional, and worth installing anyway.** x86_64 builds
> without it. Some native crates fall back to a CMake builder on other
> targets; a missing `cmake` then surfaces as a panic mid-build rather
> than a readable error. `scripts/install.sh --build-from-source`
> installs it for that reason.

### Rust installation

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
```

### Build

```bash
cargo build --release
```

The binary lands at `target/release/warden`. For local DNS testing
without root, run on a high port:

```bash
dig @127.0.0.1 -p 15353 example.com
```

## Runtime dependencies (production)

The binary itself has no TLS runtime dependency (rustls + ring,
statically linked). `ca-certificates` is only needed if you still use
system tools (`curl`, `rustup`) on the host.

A musl aarch64 build is fully static and has zero runtime library
dependencies.

## Cross-compile for aarch64 (Raspberry Pi and other ARM boxes)

```bash
rustup target add aarch64-unknown-linux-musl
# needs aarch64-linux-gnu-gcc on PATH (Debian: gcc-aarch64-linux-gnu)
cargo build --release --target aarch64-unknown-linux-musl
```

## Tests

```bash
make test
# or:
./scripts/check_no_raw_fs_write.sh
cargo fmt --check
cargo clippy --all-targets
cargo test
```

`dig` (`bind-utils` on Fedora, `dnsutils` on Debian) is useful for
manual checks after install.
