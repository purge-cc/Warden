//! Generate iptables/nftables rules for DNS filtering enforcement.
//!
//! Two layers of enforcement:
//! 1. Redirect all outgoing DNS (port 53) through purge-warden
//! 2. Block direct HTTPS/DoT connections to resolver IPs **the operator
//!    supplies** — see below
//!
//! These rules complement the DNS-level anti-bypass blocking — even if
//! a client knows a resolver IP, the firewall blocks direct access.
//!
//! # `neutrality-02`: layer 2 no longer ships an address list
//!
//! A `RESOLVER_IPS` const used to carry 22 addresses belonging to eight
//! named providers, and every one of them was written into the
//! iptables/nftables file warden tells the operator to install with
//! `sudo sh`. That is Key Design Rule 10 broken at the packet-filter
//! layer — warden shipping an opinion about named companies, in a form
//! the operator had to run as root, and correctable only by a new build.
//! It was also stale by construction: the module's own note admitted the
//! list was hand-maintained and would drift.
//!
//! The list is gone and **nothing replaced it with a default**. No
//! non-empty value is neutral — project rules records that exact mistake
//! being made twice (`neutrality-03` shipped a provider as the default
//! upstream; `neutrality-07` put the same address in the safe-mode
//! config) and a third time in a shipped artifact rather than in `src/`
//! (`neutrality-09`, the installer's `DEFAULT_UPSTREAM`), which is why
//! the sweep grew a section for files outside `src/`. Layer 1 — the DNS
//! redirect, which is what actually forces traffic through warden — is
//! unchanged and still emitted.
//!
//! What layer 2 emits instead is a commented block explaining that no
//! addresses are configured, the two rule templates to copy per address,
//! and the one trap that makes this feature bite: **the addresses must
//! be resolved somewhere other than this machine.** If warden is the
//! network's resolver and the operator has listed the same names under
//! `anti_bypass.extra_domains`, warden refuses them, a lookup made here
//! returns nothing, and a naive "resolve the hostnames at generation
//! time" implementation would emit an empty ruleset that looks like
//! success. Silent under-protection is the worst direction to fail in,
//! so the artifact says so in the operator's own file.
//!
//! Wiring this to the operator's config properly — deriving candidate
//! addresses from `[[upstreams]]` or an imported list — needs the
//! command's caller (`main.rs`), which is outside this change. See
//! `NOTES-e.md`.

use std::net::SocketAddr;

/// Render the iptables/nftables rules for DNS enforcement as text.
/// Separated from [`run_firewall_rules`] so the generated artifact can be
/// asserted in tests (rev-2606 firewall_rules-01).
fn render_firewall_rules(listen: SocketAddr) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let port = listen.port();
    let ip = listen.ip();

    let _ = writeln!(out, "# purge-warden firewall rules");
    let _ = writeln!(out, "# Generated for listen address: {listen}");
    let _ = writeln!(
        out,
        "# Apply by reviewing the rules below, then running this file as a"
    );
    let _ = writeln!(out, "# shell script: sudo sh <file>");
    let _ = writeln!(
        out,
        "# (These are executable iptables/ip6tables commands, NOT iptables-save"
    );
    let _ = writeln!(out, "# format, so `iptables-restore` cannot read them.)");
    let _ = writeln!(
        out,
        "# Or copy individual rules. The nftables section is commented out —"
    );
    let _ = writeln!(out, "# uncomment the lines you want before running them.");
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "# ── iptables (IPv4) ────────────────────────────────────"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "# 1. Redirect all DNS (port 53) to purge-warden");
    let _ = writeln!(
        out,
        "# Skip traffic from purge-warden itself to avoid loops"
    );
    if ip.is_loopback() {
        let _ = writeln!(
            out,
            "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port {port}"
        );
        let _ = writeln!(
            out,
            "iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port {port}"
        );
    } else {
        let _ = writeln!(
            out,
            "iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination {listen}"
        );
        let _ = writeln!(
            out,
            "iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination {listen}"
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "# 2. Block direct DoH/DoT to resolver IPs — NONE CONFIGURED"
    );
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# warden ships no list of resolver addresses, in either direction. Any"
    );
    let _ = writeln!(
        out,
        "# list compiled into the binary is one operator's guess, goes stale the"
    );
    let _ = writeln!(
        out,
        "# moment an operator of a resolver adds an endpoint, and cannot be"
    );
    let _ = writeln!(
        out,
        "# corrected without a new build. So the addresses have to come from you."
    );
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Add two rules per address you want refused — 443 for DoH, 853 for DoT."
    );
    let _ = writeln!(out, "# IPv4:");
    let _ = writeln!(
        out,
        "#   iptables -A FORWARD -d <addr> -p tcp --dport 443 -j REJECT --reject-with tcp-reset"
    );
    let _ = writeln!(
        out,
        "#   iptables -A FORWARD -d <addr> -p tcp --dport 853 -j REJECT --reject-with tcp-reset"
    );
    let _ = writeln!(out, "# IPv6:");
    let _ = writeln!(
        out,
        "#   ip6tables -A FORWARD -d <addr> -p tcp --dport 443 -j REJECT --reject-with tcp-reset"
    );
    let _ = writeln!(
        out,
        "#   ip6tables -A FORWARD -d <addr> -p tcp --dport 853 -j REJECT --reject-with tcp-reset"
    );
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# IMPORTANT — resolve those addresses somewhere OTHER than this machine."
    );
    let _ = writeln!(
        out,
        "# If warden is this network's resolver and you have also listed the same"
    );
    let _ = writeln!(
        out,
        "# names under `anti_bypass.extra_domains`, warden refuses them: a lookup"
    );
    let _ = writeln!(
        out,
        "# made here returns nothing and you would install an empty ruleset that"
    );
    let _ = writeln!(
        out,
        "# looks like it worked. Ask a resolver that is not warden, and re-check"
    );
    let _ = writeln!(
        out,
        "# periodically — whatever you install here is a snapshot."
    );

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "# ── nftables equivalent ─────────────────────────────────"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "# nft add table inet purge-warden");
    if ip.is_loopback() {
        // Loopback listener: redirect locally-originated DNS via the nat
        // OUTPUT chain — the nft mirror of the iptables REDIRECT above.
        // Without it an nft-only operator with a loopback listen got the
        // DoH-block rules but NO DNS redirect at all (rev-2606
        // firewall_rules-01).
        let _ = writeln!(
            out,
            "# nft add chain inet purge-warden output {{ type nat hook output priority -100 \\; }}"
        );
        let _ = writeln!(
            out,
            "# nft add rule inet purge-warden output udp dport 53 redirect to :{port}"
        );
        let _ = writeln!(
            out,
            "# nft add rule inet purge-warden output tcp dport 53 redirect to :{port}"
        );
    } else {
        let _ = writeln!(
            out,
            "# nft add chain inet purge-warden prerouting {{ type nat hook prerouting priority -100 \\; }}"
        );
        let _ = writeln!(
            out,
            "# nft add rule inet purge-warden prerouting udp dport 53 dnat to {listen}"
        );
        let _ = writeln!(
            out,
            "# nft add rule inet purge-warden prerouting tcp dport 53 dnat to {listen}"
        );
    }
    let _ = writeln!(
        out,
        "# nft add chain inet purge-warden forward {{ type filter hook forward priority 0 \\; }}"
    );

    // The resolver-address set, as a template. Same reasoning as the
    // iptables section: the shape is warden's to describe, the contents
    // are the operator's to choose.
    let _ = writeln!(
        out,
        "# nft add set inet purge-warden doh_resolvers {{ type ipv4_addr \\; elements = {{ <addr>, <addr> }} \\; }}"
    );
    let _ = writeln!(out, "# nft add rule inet purge-warden forward ip daddr @doh_resolvers tcp dport {{ 443, 853 }} reject with tcp reset");

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "# Note: rule 1 above is what actually forces this network's DNS through"
    );
    let _ = writeln!(
        out,
        "# warden, and it is complete as generated. Rule 2 is an address blocklist"
    );
    let _ = writeln!(
        out,
        "# you populate; until you do, a client that hardcodes a DoH endpoint can"
    );
    let _ = writeln!(
        out,
        "# still reach it over 443. Blocking named endpoints is a game of catch-up"
    );
    let _ = writeln!(
        out,
        "# either way — for enforcement that does not depend on knowing every"
    );
    let _ = writeln!(
        out,
        "# address, block ALL outgoing 443/853 and allowlist the destinations you"
    );
    let _ = writeln!(out, "# want reachable.");

    out
}

/// Print iptables/nftables rules for DNS enforcement.
pub fn run_firewall_rules(listen: SocketAddr) {
    print!("{}", render_firewall_rules(listen));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 22 addresses `RESOLVER_IPS` used to emit, named here and only
    /// here. Per project rules §Neutrality a provider value belongs in
    /// `#[cfg(test)]` when it proves warden does **not** touch it.
    const RETIRED_RESOLVER_IPS: &[&str] = &[
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
        "208.67.222.222",
        "208.67.220.220",
        "45.90.28.0",
        "45.90.30.0",
        "94.140.14.14",
        "94.140.15.15",
        "194.242.2.2",
        "194.242.2.3",
        "185.228.168.168",
        "185.228.169.168",
    ];

    /// neutrality-02, inverted from `resolver_ips_not_empty` (which
    /// asserted `len() >= 15` — the violation, pinned by a test).
    #[test]
    fn neutrality02_no_retired_provider_address_is_emitted() {
        // Both listen shapes: the loopback and non-loopback branches
        // emit different rule 1 blocks, and a regression could
        // reintroduce the address list under either.
        for listen in ["10.0.0.1:53", "127.0.0.1:5300"] {
            let out = render_firewall_rules(listen.parse().unwrap());
            for ip in RETIRED_RESOLVER_IPS {
                assert!(
                    !out.contains(ip),
                    "generated firewall artifact carries provider address {ip} \
                     (listen {listen}) — see project rules §Neutrality"
                );
            }
        }
    }

    /// Stronger than the needle list above, which only catches the 22
    /// addresses we happen to know about: this pins the **entire**
    /// executable content of the artifact, so a future provider table
    /// with addresses nobody listed in `RETIRED_RESOLVER_IPS` still
    /// fails here.
    ///
    /// Written as an exact set rather than "no line contains ` -d `":
    /// that weaker form is also satisfied by an artifact that emits
    /// nothing at all, and by every line the generator has ever
    /// produced except the deleted FORWARD rules. An assertion that
    /// cannot tell "correct" from "empty" is not a check. Any new
    /// executable rule — with or without a destination — has to be
    /// added here deliberately.
    #[test]
    fn neutrality02_executable_rules_are_exactly_the_dns_redirect() {
        let executable = |listen: &str| -> Vec<String> {
            render_firewall_rules(listen.parse().unwrap())
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        };

        assert_eq!(
            executable("10.0.0.1:53"),
            vec![
                "iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.0.0.1:53",
                "iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination 10.0.0.1:53",
            ]
        );
        assert_eq!(
            executable("127.0.0.1:5300"),
            vec![
                "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300",
                "iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5300",
            ]
        );
    }

    /// An empty section that says nothing reads as a bug or as "handled".
    /// The artifact has to explain that the operator owns this list, and
    /// carry the trap that makes the obvious implementation self-defeat.
    #[test]
    fn neutrality02_empty_section_explains_itself() {
        let out = render_firewall_rules("10.0.0.1:53".parse().unwrap());
        assert!(out.contains("NONE CONFIGURED"), "{out}");
        assert!(
            out.contains("warden ships no list of resolver addresses"),
            "{out}"
        );
        // The templates an operator copies, both families.
        assert!(out.contains("iptables -A FORWARD -d <addr>"), "{out}");
        assert!(out.contains("ip6tables -A FORWARD -d <addr>"), "{out}");
        // The self-defeat trap: resolving the names through warden
        // returns nothing precisely when the operator has configured
        // things correctly, producing an empty ruleset that looks like
        // success.
        assert!(
            out.contains("resolve those addresses somewhere OTHER than this machine")
                || out.contains("OTHER than this machine"),
            "{out}"
        );
        assert!(out.contains("anti_bypass.extra_domains"), "{out}");
    }

    #[test]
    fn apply_hint_matches_the_format_actually_emitted() {
        // cli-help-lies: the body is a list of executable `iptables …`
        // commands, so the header must not send the operator to
        // `iptables-restore` — that consumes `iptables-save` table dumps
        // and fails on line 1 of this artifact.
        let out = render_firewall_rules("10.0.0.1:53".parse().unwrap());

        // Every non-comment line really is a shell command, which is what
        // makes "run it as a shell script" the honest instruction. An
        // `iptables-save` dump would carry `*nat` / `:PREROUTING ACCEPT` /
        // `COMMIT` lines instead, and none of those are shell.
        for line in out.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                line.starts_with("iptables ") || line.starts_with("ip6tables "),
                "non-comment line is not a runnable shell command: {line}"
            );
        }

        assert!(out.contains("sudo sh <file>"), "{out}");
        // The needle is the whole instruction, not the bare word
        // `iptables-restore`: the header now names that tool on purpose,
        // to explain why it does *not* work. A needle that matched the
        // bare word would go red on the correct text.
        assert!(!out.contains("Apply with: sudo iptables-restore"), "{out}");
    }

    #[test]
    fn nft_loopback_emits_output_redirect() {
        // firewall_rules-01: a loopback listener must still get a DNS
        // redirect in the nftables section (nat OUTPUT redirect), mirroring
        // the iptables REDIRECT — not silently drop to DoH-block-only.
        let out = render_firewall_rules("127.0.0.1:5300".parse().unwrap());
        assert!(
            out.contains("nft add chain inet purge-warden output"),
            "{out}"
        );
        assert!(
            out.contains("nft add rule inet purge-warden output udp dport 53 redirect to :5300"),
            "{out}"
        );
        assert!(
            out.contains("nft add rule inet purge-warden output tcp dport 53 redirect to :5300"),
            "{out}"
        );
        // No prerouting DNAT for a loopback listener.
        assert!(!out.contains("prerouting udp dport 53 dnat"), "{out}");
    }

    #[test]
    fn nft_non_loopback_emits_prerouting_dnat() {
        let out = render_firewall_rules("10.0.0.1:53".parse().unwrap());
        assert!(
            out.contains(
                "nft add rule inet purge-warden prerouting udp dport 53 dnat to 10.0.0.1:53"
            ),
            "{out}"
        );
        // No output-chain redirect for a non-loopback listener.
        assert!(
            !out.contains("purge-warden output udp dport 53 redirect"),
            "{out}"
        );
    }
}
