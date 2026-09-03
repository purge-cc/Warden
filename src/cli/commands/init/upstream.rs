//! Upstream resolver detection and the `warden init` menu.
//!
//! Everything provider-adjacent lives in this one file so
//! a reader asking "where could a provider name hide?" has one place to
//! look. There are none: entry 1 is read from the machine, entries 2..N
//! are read from an operator-editable data file.

use anyhow::Context;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;

/// One selectable menu entry, read from `upstreams.toml`.
///
/// `deny_unknown_fields` is load-bearing, not tidiness — see
/// [`CatalogFile`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamChoice {
    pub name: String,
    pub servers: Vec<String>,
}

/// **`deny_unknown_fields` is what makes this file's
/// promise true.** Without it, `[[upstreams]]` — the plural, the single
/// likeliest typo for this schema — is simply a different top-level key:
/// serde discards it, `#[serde(default)]` supplies an empty `upstream`,
/// and a ten-entry catalog renders as a menu with no catalog in it. That
/// is indistinguishable from the supported file-is-absent state, so the
/// operator gets silence where the doc-comment below promises an error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    #[serde(default)]
    upstream: Vec<UpstreamChoice>,
}

/// Parse an `upstreams.toml` body into menu entries, sorted by `name`.
///
/// **Alphabetical, not file order.** Ordering is influence: position 1
/// takes most installs, so no ranking warden could apply would be
/// neutral. Sorting removes the question.
///
/// A malformed body is an error, never a silent skip — the operator gets
/// told which file to fix.
pub(crate) fn parse_catalog(body: &str) -> anyhow::Result<Vec<UpstreamChoice>> {
    let parsed: CatalogFile = toml::from_str(body).context(
        "upstreams.toml is not valid TOML (expected [[upstream]] entries with `name` and `servers`)",
    )?;
    for choice in &parsed.upstream {
        for server in &choice.servers {
            server.parse::<SocketAddr>().with_context(|| {
                format!(
                    "upstreams.toml entry \"{}\": server \"{}\" is not addr:port (e.g. 192.0.2.53:53)",
                    choice.name, server
                )
            })?;
        }
    }
    let mut out = parsed.upstream;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Load the menu catalog from disk.
///
/// **An absent file is a supported state**, not an error: the menu then
/// offers only the detected resolver and the free-typed entry. That is
/// what keeps this feature out of the installer's way — nothing has to
/// place the file for `warden init` to work.
pub(crate) fn load_catalog(path: &Path) -> anyhow::Result<Vec<UpstreamChoice>> {
    match std::fs::read_to_string(path) {
        Ok(body) => parse_catalog(&body),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

/// Port a detected bare address is offered on. `resolv.conf` carries no
/// port, and `validated_upstreams` demands `addr:port`.
const DETECTED_PORT: u16 = 53;

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4
/// form, leaving everything else untouched.
///
/// Without this, `[::ffff:0.0.0.0]:53` — a spelling clap
/// accepts, `validated_listen` blesses, and the **kernel binds as a
/// wildcard over every IPv4 address** — is not `is_unspecified()`,
/// because its octets are not all zero. The self-loop rule therefore
/// fell through to an exact `l == ip` comparison that an IPv4 candidate
/// can never satisfy, warden's own address survived, and `--yes` wrote a
/// config pointing warden at itself.
///
/// Compare canonical forms and both halves work: the mapped wildcard
/// becomes `0.0.0.0` and reads as unspecified, and a mapped specific
/// address matches the plain-form candidate it denotes.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Reduce raw detected addresses to `addr:port` strings safe to propose.
///
/// `is_local` is injected rather than calling [`is_local_address`]
/// directly so the self-listen rule is testable without depending on the
/// test runner's interfaces.
///
/// Order of rules matters only for readability — they are independent —
/// but de-duplication runs last so an address dropped by an earlier rule
/// cannot consume a slot.
pub(crate) fn filter_candidates(
    candidates: Vec<IpAddr>,
    listen: &str,
    is_local: &dyn Fn(IpAddr) -> bool,
) -> Vec<String> {
    // An unparseable `listen` still has to yield a usable rule. Falling
    // back to the default port is the conservative choice: it keeps the
    // self-loop check active rather than disabling it on a typo.
    let listen_addr = listen.parse::<SocketAddr>().ok();
    let listen_port = listen_addr.map(|a| a.port()).unwrap_or(DETECTED_PORT);
    // Canonicalised: `[::ffff:0.0.0.0]:53` is a wildcard the kernel
    // honours but `is_unspecified()` denies — see `canonical`.
    let listen_ip = listen_addr.map(|a| canonical(a.ip()));

    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<IpAddr> = Vec::new();

    for ip in candidates {
        let ip = canonical(ip);
        if ip.is_loopback() {
            continue;
        }
        // Self-loop. Two shapes: warden binds this exact address, or it
        // binds every address and this one is ours.
        let self_loop = match listen_ip {
            Some(l) if l.is_unspecified() => is_local(ip),
            Some(l) => l == ip,
            None => is_local(ip),
        };
        if self_loop && listen_port == DETECTED_PORT {
            continue;
        }
        if seen.contains(&ip) {
            continue;
        }
        seen.push(ip);
        out.push(SocketAddr::new(ip, DETECTED_PORT).to_string());
    }
    out
}

/// Is `ip` an address this host actually holds?
///
/// Answered by binding an ephemeral UDP port to it. The kernel refuses
/// with `EADDRNOTAVAIL` for any address not on a local interface, which
/// makes this a complete answer with **no dependency and no `unsafe`**.
/// The tree has no interface-enumeration crate, and reaching
/// `getifaddrs` through `libc` would mean `unsafe` in a codebase that
/// avoids it.
///
/// Port 0 is ephemeral, so this cannot collide with a listener — and the
/// socket is dropped immediately.
///
/// Measured across four arms: a host's own address and loopback bind;
/// the LAN gateway and an off-network address return "Cannot assign
/// requested address". The standing check is
/// `a_public_address_is_not_local` below, which uses an RFC 5737
/// address — this module names no resolver, including in its comments.
pub(crate) fn is_local_address(ip: IpAddr) -> bool {
    UdpSocket::bind((ip, 0)).is_ok()
}

/// Extract `nameserver` addresses from a `resolv.conf` body, in file order.
///
/// Takes the body rather than a path: the caller reads the file, so this
/// is testable without `/etc`. An unparseable address is skipped, not an
/// error — a single malformed line must not blind detection to the rest.
pub(crate) fn parse_resolv_conf(body: &str) -> Vec<IpAddr> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("nameserver")?;
            // Require whitespace after the keyword so `nameserverfoo`
            // does not match.
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            rest.split_whitespace().next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

/// What detection found, and what survived filtering.
///
/// An empty `usable` is **two** states, and collapsing
/// them to one produced the worst kind of error message — one that
/// contradicts what the operator can see in `/etc/resolv.conf`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Detection {
    /// Addresses safe to propose, rendered `addr:port`.
    pub usable: Vec<String>,
    /// Everything read from the machine BEFORE filtering. Non-empty with
    /// an empty `usable` means every resolver this host uses is warden
    /// itself — the steady state of a working install, not an edge case.
    pub seen: Vec<IpAddr>,
}

/// Refusal text for the case where the machine *has* resolvers and every
/// one of them is us. Distinct from [`super::UPSTREAM_MISSING`] on
/// purpose: telling an operator "no upstream resolver configured" when
/// their `resolv.conf` visibly lists one sends them to debug the wrong
/// thing.
fn format_only_ourselves(seen: &[IpAddr]) -> String {
    let names: Vec<String> = seen.iter().map(|ip| ip.to_string()).collect();
    format!(
        "the only resolver(s) this machine uses are warden itself ({}) \u{2014} \
         adopting one would make warden query itself. Pass --upstream <addr:port> \
         with a resolver outside this host, e.g. --upstream 192.0.2.53:53",
        names.join(", ")
    )
}

/// Non-interactive resolution: adopt what the machine already uses, or
/// refuse — saying *which* kind of nothing it found.
///
/// Split out from [`resolve_upstreams`] so the `--yes` contract is
/// testable without a terminal or a real `/etc/resolv.conf`.
///
/// Adoption is the operator-friendly half; the refusal is the honest
/// half. Warden never invents a value.
pub(crate) fn choose_non_interactive(detection: Detection) -> anyhow::Result<Vec<String>> {
    if !detection.usable.is_empty() {
        return Ok(detection.usable);
    }
    if detection.seen.is_empty() {
        anyhow::bail!(super::UPSTREAM_MISSING);
    }
    anyhow::bail!(format_only_ourselves(&detection.seen));
}

/// Resolve the upstream list for `warden init`.
///
/// Precedence: `--upstream` wins outright; then `--yes` adopts what was
/// detected (printed, never silent); otherwise the operator picks from
/// the menu.
pub(crate) fn resolve_upstreams(
    explicit: Option<&str>,
    yes: bool,
    listen: &str,
    catalog_path: &Path,
) -> anyhow::Result<Vec<String>> {
    if let Some(csv) = explicit {
        return super::validated_upstreams(csv);
    }

    let detection = detect_upstreams(listen);

    if yes {
        let chosen = choose_non_interactive(detection)?;
        // Printed, not silent: the operator must be able to see what was
        // chosen for them in the install transcript.
        println!(
            "upstream: adopting {} ({DETECTED_LABEL})",
            chosen.join(", ")
        );
        return Ok(chosen);
    }

    let catalog = load_catalog(catalog_path)?;
    let menu = build_menu(detection.usable, catalog);
    prompt_upstream(&menu)
}

/// Render the numbered menu and read one choice.
fn prompt_upstream(menu: &[UpstreamChoice]) -> anyhow::Result<Vec<String>> {
    use std::io::Write;

    println!("upstream resolver:");
    for (i, choice) in menu.iter().enumerate() {
        println!(
            "  {}) {}  ({})",
            i + 1,
            choice.servers.join(", "),
            choice.name
        );
    }
    println!("  0) other — type addr:port, comma-separated for several");

    let default_hint = if menu.is_empty() { "0" } else { "1" };
    print!("choice [{default_hint}]: ");
    std::io::stdout().flush().ok();

    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let answer = buf.trim();
    let answer = if answer.is_empty() {
        default_hint
    } else {
        answer
    };

    if answer == "0" {
        print!("upstream (addr:port): ");
        std::io::stdout().flush().ok();
        let mut typed = String::new();
        std::io::stdin().read_line(&mut typed)?;
        let typed = typed.trim();
        if typed.is_empty() {
            anyhow::bail!(super::UPSTREAM_MISSING);
        }
        return super::validated_upstreams(typed);
    }

    let idx: usize = answer
        .parse()
        .map_err(|_| anyhow::anyhow!("\"{answer}\" is not one of the offered numbers"))?;
    let choice = menu
        .get(idx.wrapping_sub(1))
        .ok_or_else(|| anyhow::anyhow!("\"{answer}\" is not one of the offered numbers"))?;
    super::validated_upstreams(&choice.servers.join(","))
}

/// Label given to the detected entry. Names no provider — it names where
/// the value came from, which is the whole point: this machine's network
/// chose it, warden did not.
const DETECTED_LABEL: &str = "detected on this machine";

/// Compose the numbered menu: detected first, then the catalog.
///
/// A catalog entry whose server set is **exactly** the detected one is
/// suppressed — one address must not occupy two slots. Comparison is on
/// parsed `SocketAddr`s, not strings, so `192.0.2.1:53` written two ways
/// still collapses. An entry that merely overlaps survives, because
/// picking it yields a genuinely different result.
pub(crate) fn build_menu(
    detected: Vec<String>,
    catalog: Vec<UpstreamChoice>,
) -> Vec<UpstreamChoice> {
    let mut out = Vec::new();

    let detected_set: Option<Vec<SocketAddr>> = if detected.is_empty() {
        None
    } else {
        detected
            .iter()
            .map(|s| s.parse::<SocketAddr>().ok())
            .collect()
    };

    if !detected.is_empty() {
        out.push(UpstreamChoice {
            name: DETECTED_LABEL.to_string(),
            servers: detected,
        });
    }

    for choice in catalog {
        let parsed: Option<Vec<SocketAddr>> = choice
            .servers
            .iter()
            .map(|s| s.parse::<SocketAddr>().ok())
            .collect();
        if let (Some(a), Some(b)) = (&detected_set, &parsed) {
            if a == b {
                continue;
            }
        }
        out.push(choice);
    }
    out
}

/// Extract addresses from `resolvectl status` output.
///
/// Reads both shapes systemd prints: `DNS Servers: a b` (per link and
/// global) and `Current DNS Server: x`. Non-address tokens are skipped,
/// so a format change degrades to "no candidates" rather than to garbage.
pub(crate) fn parse_resolvectl(body: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let rest = line
            .strip_prefix("DNS Servers:")
            .or_else(|| line.strip_prefix("Current DNS Server:"));
        let Some(rest) = rest else { continue };
        for token in rest.split_whitespace() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Detect resolvers this machine already uses, filtered and ready to
/// propose.
///
/// Source order is deliberate: `/etc/resolv.conf` first because it is
/// the universal answer, `resolvectl` only as a fallback for hosts where
/// the file holds nothing but the `systemd-resolved` stub.
///
/// **`resolvectl` being absent is an empty result, never an error** —
/// it is not installed on every host, and detection must not fail there.
pub(crate) fn detect_upstreams(listen: &str) -> Detection {
    let mut candidates = std::fs::read_to_string("/etc/resolv.conf")
        .map(|body| parse_resolv_conf(&body))
        .unwrap_or_default();

    if filter_candidates(candidates.clone(), listen, &is_local_address).is_empty() {
        if let Ok(out) = std::process::Command::new("resolvectl")
            .arg("status")
            .output()
        {
            let body = String::from_utf8_lossy(&out.stdout);
            candidates.extend(parse_resolvectl(&body));
        }
    }

    // `seen` keeps the pre-filter list so the caller can distinguish
    // "this machine names no resolver" from "every resolver it names is
    // us" — see `Detection`.
    Detection {
        usable: filter_candidates(candidates.clone(), listen, &is_local_address),
        seen: candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped on a real `/etc/resolv.conf` whose FIRST nameserver is
    /// warden's own address.
    #[test]
    fn parses_nameserver_lines_in_order() {
        let body = "domain home.local\nsearch home.local\nnameserver 10.10.1.94\nnameserver 149.112.112.112\n";
        assert_eq!(
            parse_resolv_conf(body),
            vec![
                "10.10.1.94".parse::<IpAddr>().unwrap(),
                "149.112.112.112".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn ignores_comments_blanks_and_other_directives() {
        let body = "# a comment\n\noptions edns0\nnameserver 192.0.2.1\n; another comment\nsearch example.net\n";
        assert_eq!(
            parse_resolv_conf(body),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn skips_unparseable_addresses_without_failing() {
        let body = "nameserver not-an-address\nnameserver 192.0.2.2\n";
        assert_eq!(
            parse_resolv_conf(body),
            vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn empty_body_yields_no_candidates() {
        assert!(parse_resolv_conf("").is_empty());
    }

    /// Verified with an equivalent python probe: the host's own address
    /// and loopback bind; a public resolver and the LAN gateway return
    /// EADDRNOTAVAIL.
    ///
    /// Loopback is the arm that works on every machine, including CI.
    #[test]
    fn loopback_is_local() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
    }

    /// The discriminating arm. Without it the test would pass for a
    /// function that returns `true` unconditionally.
    #[test]
    fn a_public_address_is_not_local() {
        assert!(!is_local_address("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_loopback_is_local() {
        assert!(is_local_address("::1".parse().unwrap()));
    }

    /// Every candidate is a genuine address; the discriminator is the
    /// rule, not the parseability.
    #[test]
    fn drops_loopback_candidates() {
        let got = filter_candidates(
            vec!["127.0.0.53".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            "0.0.0.0:53",
            &|_| false,
        );
        assert_eq!(got, vec!["192.0.2.1:53".to_string()]);
    }

    /// The rule that matters when a host's first nameserver is
    /// its own address. `0.0.0.0:53` means warden answers on every local
    /// address, so a candidate on port 53 that IS one of ours self-loops.
    #[test]
    fn drops_our_own_address_under_unspecified_bind() {
        let ours: IpAddr = "10.10.1.94".parse().unwrap();
        let got = filter_candidates(
            vec![ours, "192.0.2.1".parse().unwrap()],
            "0.0.0.0:53",
            &|ip| ip == ours,
        );
        assert_eq!(got, vec!["192.0.2.1:53".to_string()]);
    }

    /// Control arm for the rule above: same local address, but warden
    /// will listen on a DIFFERENT port, so there is no loop and the
    /// candidate must survive.
    #[test]
    fn keeps_a_local_address_when_the_listen_port_differs() {
        let ours: IpAddr = "10.10.1.94".parse().unwrap();
        let got = filter_candidates(vec![ours], "0.0.0.0:15353", &|ip| ip == ours);
        assert_eq!(got, vec!["10.10.1.94:53".to_string()]);
    }

    /// A specific bind drops only that exact address, not every local one.
    #[test]
    fn specific_bind_drops_only_that_address() {
        let got = filter_candidates(
            vec!["10.10.1.94".parse().unwrap(), "10.10.1.95".parse().unwrap()],
            "10.10.1.94:53",
            &|_| true,
        );
        assert_eq!(got, vec!["10.10.1.95:53".to_string()]);
    }

    #[test]
    fn de_duplicates_preserving_order() {
        let got = filter_candidates(
            vec![
                "192.0.2.2".parse().unwrap(),
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
            ],
            "0.0.0.0:53",
            &|_| false,
        );
        assert_eq!(
            got,
            vec!["192.0.2.2:53".to_string(), "192.0.2.1:53".to_string()]
        );
    }

    #[test]
    fn ipv6_candidates_render_bracketed() {
        let got = filter_candidates(vec!["2001:db8::1".parse().unwrap()], "0.0.0.0:53", &|_| {
            false
        });
        assert_eq!(got, vec!["[2001:db8::1]:53".to_string()]);
    }

    #[test]
    fn an_unparseable_listen_falls_back_to_port_53() {
        let got = filter_candidates(vec!["192.0.2.1".parse().unwrap()], "nonsense", &|_| false);
        assert_eq!(got, vec!["192.0.2.1:53".to_string()]);
    }

    /// `::ffff:0.0.0.0`
    /// is the IPv4-mapped spelling of the wildcard: clap accepts it,
    /// `validated_listen` blesses it, and the kernel binds **every IPv4
    /// address** — the reviewer proved that by binding it and then
    /// receiving a datagram sent to a specific host address.
    ///
    /// But `Ipv6Addr::is_unspecified()` is false for it (its octets are
    /// not all zero), so the unspecified-bind branch never fired, the
    /// `l == ip` comparison could not match an IPv4 candidate, and the
    /// host's own address survived. `--yes` then adopted it and wrote a
    /// config telling warden to forward every query to itself: silent,
    /// total loss of DNS, shaped like "warden is broken".
    #[test]
    fn an_ipv4_mapped_wildcard_listen_still_drops_our_own_address() {
        let ours: IpAddr = "10.10.1.94".parse().unwrap();
        let got = filter_candidates(
            vec![ours, "192.0.2.1".parse().unwrap()],
            "[::ffff:0.0.0.0]:53",
            &|ip| ip == ours,
        );
        assert_eq!(
            got,
            vec!["192.0.2.1:53".to_string()],
            "a mapped-form wildcard binds every IPv4 address, so our own \
             address must be dropped exactly as it is for 0.0.0.0"
        );
    }

    /// The specific-address half of the same normalisation: a listen
    /// value written in mapped form must still match the plain-form
    /// candidate it denotes.
    #[test]
    fn an_ipv4_mapped_specific_listen_matches_its_plain_form() {
        let got = filter_candidates(
            vec!["10.10.1.94".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            "[::ffff:10.10.1.94]:53",
            &|_| false,
        );
        assert_eq!(
            got,
            vec!["192.0.2.1:53".to_string()],
            "[::ffff:10.10.1.94] and 10.10.1.94 are the same address"
        );
    }

    /// `resolvectl status` prints "DNS Servers: a b" per link, and
    /// "Current DNS Server: x" globally. Both shapes must be read.
    #[test]
    fn parses_resolvectl_dns_server_lines() {
        let body = "Global\n       Protocols: -LLMNR\nCurrent DNS Server: 192.0.2.1\n       DNS Servers: 192.0.2.1 192.0.2.2\n\nLink 2 (eth0)\n    DNS Servers: 192.0.2.3\n";
        assert_eq!(
            parse_resolvectl(body),
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap(),
                "192.0.2.3".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn resolvectl_empty_output_yields_no_candidates() {
        assert!(parse_resolvectl("").is_empty());
    }

    /// `resolvectl` is not installed on every host. A missing binary
    /// must read as "no candidates", never as an error:
    /// `resolvectl: command not found`.
    #[test]
    fn detect_never_panics_and_returns_a_vec() {
        let got = detect_upstreams("0.0.0.0:53");
        for entry in &got.usable {
            assert!(
                entry.parse::<std::net::SocketAddr>().is_ok(),
                "detect must only emit parseable addr:port, got {entry:?}"
            );
        }
        // `usable` is a subset of what was `seen`: a survivor that was
        // never a candidate would mean the filter invented an address.
        assert!(
            got.usable.len() <= got.seen.len(),
            "usable {:?} cannot exceed seen {:?}",
            got.usable,
            got.seen
        );
    }

    #[test]
    fn catalog_entries_come_back_alphabetical() {
        let body = r#"
[[upstream]]
name = "Zulu Resolver"
servers = ["192.0.2.9:53"]

[[upstream]]
name = "Alpha Resolver"
servers = ["192.0.2.1:53", "192.0.2.2:53"]
"#;
        let got = parse_catalog(body).unwrap();
        assert_eq!(
            got.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["Alpha Resolver", "Zulu Resolver"]
        );
        assert_eq!(got[0].servers, vec!["192.0.2.1:53", "192.0.2.2:53"]);
    }

    /// Ordering is influence — position 1 takes most installs. Sorting
    /// must not depend on the file's order, so this fixture is already
    /// sorted and must stay sorted.
    #[test]
    fn already_sorted_input_stays_sorted() {
        let body = "[[upstream]]\nname = \"Alpha\"\nservers = [\"192.0.2.1:53\"]\n\n[[upstream]]\nname = \"Beta\"\nservers = [\"192.0.2.2:53\"]\n";
        let got = parse_catalog(body).unwrap();
        assert_eq!(
            got.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["Alpha", "Beta"]
        );
    }

    #[test]
    fn empty_catalog_body_is_ok_and_empty() {
        assert!(parse_catalog("").unwrap().is_empty());
    }

    /// A malformed file is a hard error, never a silent skip. A menu
    /// that quietly shrinks because a key was mistyped is exactly the
    /// failure mode this workstream exists to remove.
    #[test]
    fn a_malformed_catalog_is_an_error() {
        let err = parse_catalog("[[upstream]]\nnmae = \"typo\"\n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("upstreams.toml"),
            "the error must name the file the operator has to fix: {msg}"
        );
    }

    /// The test above passes for the WRONG REASON: `nmae`
    /// errors because the required field `name` is then missing, not
    /// because `nmae` is unknown. It would pass identically against a
    /// deserializer that silently ignores unknown keys — which is what
    /// was in use. So it never discriminated the failure this module's
    /// own doc-comment promises to prevent.
    ///
    /// `[[upstreams]]` — the plural, the single likeliest typo for this
    /// schema — is a DIFFERENT top-level TOML key. Verified:
    /// `tomllib.loads("[[upstreams]]…")` yields `{'upstreams': …}`. With
    /// `#[serde(default)]` and no `deny_unknown_fields` it parsed to an
    /// empty list, so a ten-entry catalog rendered as a menu with no
    /// catalog in it — indistinguishable from the supported
    /// file-is-absent state.
    #[test]
    fn a_plural_section_header_is_an_error_not_a_silently_empty_menu() {
        let body = "[[upstreams]]\nname = \"Typo\"\nservers = [\"192.0.2.1:53\"]\n";
        let err = parse_catalog(body).unwrap_err();
        assert!(
            err.to_string().contains("upstreams.toml"),
            "a plural section header must be refused, not read as an empty \
             catalog: {err}"
        );
    }

    /// The same hole one level down: an unknown key INSIDE an entry.
    /// `server` (singular) next to a valid `name` would have been
    /// discarded, leaving `servers` to fail as missing — the right
    /// outcome by accident. A misspelling next to a complete entry is
    /// the case that was silent.
    #[test]
    fn an_unknown_key_inside_an_entry_is_an_error() {
        let body = "[[upstream]]\nname = \"X\"\nservers = [\"192.0.2.1:53\"]\ncoment = \"typo\"\n";
        let err = parse_catalog(body).unwrap_err();
        assert!(
            err.to_string().contains("upstreams.toml"),
            "an unknown key inside an entry must be refused: {err}"
        );
    }

    /// An entry whose server is not addr:port fails here rather than
    /// three prompts later.
    #[test]
    fn a_catalog_server_that_is_not_addr_port_is_an_error() {
        let err = parse_catalog("[[upstream]]\nname = \"Bad\"\nservers = [\"example.net\"]\n")
            .unwrap_err();
        assert!(err.to_string().contains("example.net"));
    }

    #[test]
    fn an_absent_catalog_file_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let got = load_catalog(&dir.path().join("upstreams.toml")).unwrap();
        assert!(got.is_empty());
    }

    fn choice(name: &str, servers: &[&str]) -> UpstreamChoice {
        UpstreamChoice {
            name: name.to_string(),
            servers: servers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn detected_leads_the_menu() {
        let got = build_menu(
            vec!["192.0.2.1:53".to_string()],
            vec![choice("Alpha", &["192.0.2.9:53"])],
        );
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].servers, vec!["192.0.2.1:53"]);
        assert!(got[0].name.contains("detected"));
        assert_eq!(got[1].name, "Alpha");
    }

    /// Suppression, on the parsed SocketAddr set rather than the string:
    /// one address must not occupy two numbered slots, or picking "2"
    /// and getting the same result as "1" makes the menu look broken.
    #[test]
    fn a_catalog_entry_matching_the_detected_one_is_suppressed() {
        let got = build_menu(
            vec!["192.0.2.1:53".to_string()],
            vec![
                choice("Same", &["192.0.2.1:53"]),
                choice("Other", &["192.0.2.9:53"]),
            ],
        );
        assert_eq!(got.len(), 2);
        assert!(got[0].name.contains("detected"));
        assert_eq!(got[1].name, "Other");
    }

    /// Control arm for suppression: an entry that merely OVERLAPS must
    /// survive, because choosing it gives a genuinely different result.
    #[test]
    fn a_catalog_entry_that_only_overlaps_survives() {
        let got = build_menu(
            vec!["192.0.2.1:53".to_string()],
            vec![choice("Pair", &["192.0.2.1:53", "192.0.2.2:53"])],
        );
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].name, "Pair");
    }

    #[test]
    fn with_nothing_detected_the_menu_is_just_the_catalog() {
        let got = build_menu(vec![], vec![choice("Alpha", &["192.0.2.9:53"])]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "Alpha");
    }

    #[test]
    fn with_nothing_detected_and_no_catalog_the_menu_is_empty() {
        assert!(build_menu(vec![], vec![]).is_empty());
    }

    /// `--upstream` wins over everything and never consults the machine
    /// or the catalog.
    #[test]
    fn an_explicit_upstream_short_circuits() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_upstreams(
            Some("192.0.2.7:53"),
            true,
            "0.0.0.0:53",
            &dir.path().join("upstreams.toml"),
        )
        .unwrap();
        assert_eq!(got, vec!["192.0.2.7:53".to_string()]);
    }

    /// The `--yes` decision: adopt what was detected. Pinned with an
    /// injected detection result so the test does not depend on the
    /// runner's /etc/resolv.conf.
    #[test]
    fn yes_adopts_the_detected_resolver() {
        let detection = Detection {
            usable: vec!["192.0.2.1:53".to_string()],
            seen: vec!["192.0.2.1".parse().unwrap()],
        };
        let got = choose_non_interactive(detection).unwrap();
        assert_eq!(got, vec!["192.0.2.1:53".to_string()]);
    }

    /// The other half of that decision: with nothing detected at all,
    /// `--yes` refuses with the frozen message rather than inventing a
    /// value.
    #[test]
    fn yes_with_nothing_detected_refuses_with_the_frozen_message() {
        let err = choose_non_interactive(Detection::default()).unwrap_err();
        assert_eq!(err.to_string(), super::super::UPSTREAM_MISSING);
    }

    /// "Empty" is TWO states and they were conflated:
    /// nothing was read from the machine, versus everything read was
    /// dropped as loopback or as us.
    ///
    /// The second is not an edge case — it is the steady state of a
    /// working install. Once the operator points a host at warden and
    /// removes the old entry, `resolv.conf` is one line: warden's own
    /// address. Re-running `init --yes --force` then failed with "no
    /// upstream resolver configured" on a machine whose `resolv.conf`
    /// visibly contains a nameserver.
    #[test]
    fn yes_says_so_when_every_resolver_this_host_uses_is_warden_itself() {
        let detection = Detection {
            usable: vec![],
            seen: vec!["10.10.1.94".parse().unwrap()],
        };
        let err = choose_non_interactive(detection).unwrap_err();
        let msg = err.to_string();
        assert_ne!(
            msg,
            super::super::UPSTREAM_MISSING,
            "the two empty states must not share one message"
        );
        assert!(
            msg.contains("10.10.1.94"),
            "the message must name what it found and rejected, or the \
             operator cannot tell which state they are in: {msg}"
        );
        assert!(
            msg.contains("--upstream"),
            "it must still say how to recover: {msg}"
        );
    }

    /// Control arm: a host with a usable resolver alongside itself is
    /// NOT in that state and must succeed silently.
    #[test]
    fn a_host_with_one_usable_resolver_besides_itself_still_adopts() {
        let detection = Detection {
            usable: vec!["149.112.112.112:53".to_string()],
            seen: vec![
                "10.10.1.94".parse().unwrap(),
                "149.112.112.112".parse().unwrap(),
            ],
        };
        assert_eq!(
            choose_non_interactive(detection).unwrap(),
            vec!["149.112.112.112:53".to_string()]
        );
    }
}
