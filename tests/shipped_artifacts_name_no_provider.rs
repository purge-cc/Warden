//! neutrality-09 — the shipped installer and config templates name no DNS provider.
//!
//! **Why this exists as a test and not only as a sweep.** `CLAUDE.md` §Neutrality
//! documents Sweep C, which greps these same files. A documented sweep is a thing a
//! human has to remember to run; `neutrality-03` was declared closed on a sweep that
//! structurally could not see `scripts/install.sh`, and the installer kept routing every
//! default household install to one named provider for weeks afterwards.
//!
//! The pre-existing guard, `neutrality03_scaffold_ships_no_vendor_upstream`, greps
//! `default_config()` — a Rust function. It cannot see a shell script or a `.toml`
//! template by construction. This closes that gap.
//!
//! Scope is deliberately narrow: the two artifacts a fresh install actually consumes.
//! Widening it to the whole tree would drag in `fuzz/Cargo.toml`'s `fuzz_adguard_parser`
//! target name — the `adguard`-as-parser-format benign class — and a test with a
//! documented exceptions list is the shape that has already bitten this project.

use std::path::PathBuf;

/// Same needles as Sweep C in `CLAUDE.md` §Neutrality. Keep the two in sync: a needle
/// added there and not here leaves the sweep ahead of the gate, which is how the
/// installer default survived in the first place.
const PROVIDER_NEEDLES: &[&str] = &[
    // Addresses
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "208.67.",
    "94.140.",
    "185.228.",
    "194.242.",
    "45.90.",
    // Names. `dns.google` rather than bare `google` — the precise token returns the one
    // survivor, the company name returns seven, six of them `google.com` used as a
    // generic example domain.
    "cloudflare",
    "cloudfront",
    "fastly",
    "akamai",
    "quad9",
    "nextdns",
    "opendns",
    "mullvad",
    "cleanbrowsing",
    "dns.google",
];

/// Every needle present in `body`, lowercased before matching so a capitalised
/// `Cloudflare` in a comment cannot slip past.
fn provider_hits(body: &str) -> Vec<&'static str> {
    let lower = body.to_ascii_lowercase();
    PROVIDER_NEEDLES
        .iter()
        .copied()
        .filter(|needle| lower.contains(*needle))
        .collect()
}

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("shipped artifact {} must be readable: {e}", path.display()))
}

/// **The control arm.** Without it, the two assertions below would pass just as happily
/// for a `provider_hits` that always returns an empty vec — a detector that sees nothing
/// and a tree that contains nothing are indistinguishable from the outside.
///
/// The fixture is the literal line `scripts/install.sh:32` carried until 2026-07-31.
#[test]
fn the_detector_fires_on_the_line_that_actually_shipped() {
    let pre_fix = r#"DEFAULT_UPSTREAM="1.1.1.1:53,1.0.0.1:53""#;
    let hits = provider_hits(pre_fix);
    assert!(
        hits.contains(&"1.1.1.1") && hits.contains(&"1.0.0.1"),
        "the detector must catch the pair that shipped for weeks; got {hits:?}"
    );
}

/// Second control arm, for the name half of the alternation: a hostname hides in a shell
/// script exactly as easily as an address, and Sweep B missed `dns.google:853` in
/// `upstream/dot.rs` for precisely that reason.
#[test]
fn the_detector_fires_on_a_provider_hostname() {
    assert_eq!(
        provider_hits(r#"servers = ["dns.google:853"]"#),
        vec!["dns.google"]
    );
    assert_eq!(
        provider_hits("# e.g. dns.cloudflare.com:853"),
        vec!["cloudflare"]
    );
}

/// A documentation-range example must NOT trip the detector, or the test becomes noise
/// and gets suppressed.
#[test]
fn rfc_5737_and_example_net_are_clean() {
    assert!(provider_hits(r#"servers = ["192.0.2.53:53", "192.0.2.54:53"]"#).is_empty());
    assert!(
        provider_hits("#   doh:   URL  (e.g. \"https://dns.example.net/dns-query\")").is_empty()
    );
}

/// The installer runs as root on a fresh machine and, until 2026-07-31, always forwarded
/// a hardcoded provider pair to `warden init`. Rule 10 read green the whole time because
/// it is scoped to `src/`.
#[test]
fn install_sh_names_no_provider() {
    let hits = provider_hits(&repo_file("scripts/install.sh"));
    assert!(
        hits.is_empty(),
        "scripts/install.sh names a DNS provider: {hits:?}. \
         Every default install consumes this file — see CLAUDE.md §Neutrality."
    );
}

/// The shipped config template is what an operator copies and edits. Its commented
/// examples are as much a recommendation as an uncommented value.
#[test]
fn default_toml_names_no_provider() {
    let hits = provider_hits(&repo_file("config/default.toml"));
    assert!(
        hits.is_empty(),
        "config/default.toml names a DNS provider: {hits:?}. \
         Use RFC 5737 (192.0.2.0/24) and example.net, as src/ already does."
    );
}

/// Nothing under `config/` may ship a live third-party resolver, uncommented or not.
/// A shipped config must not name a third-party resolver. This catches
/// a default upstream returning under any filename.
#[test]
fn no_shipped_config_template_names_a_provider() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("config/ must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("readable config template");
        let hits = provider_hits(&body);
        if !hits.is_empty() {
            offenders.push(format!("{}: {hits:?}", path.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "shipped config templates name a DNS provider: {offenders:?}"
    );
}

/// The scan above is only meaningful if `config/` actually holds templates. An empty or
/// moved directory would make `no_shipped_config_template_names_a_provider` vacuously
/// true — the same two-empty-arms failure the control arms above exist to prevent.
#[test]
fn the_config_scan_examines_a_non_empty_set() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let count = std::fs::read_dir(&dir)
        .expect("config/ must exist")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("toml"))
        .count();
    assert!(
        count > 0,
        "config/ holds no .toml templates — the provider scan would pass vacuously"
    );
}
