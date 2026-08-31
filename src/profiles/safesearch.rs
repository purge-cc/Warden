//! §4.53: per-profile SafeSearch toggle — **no longer carries an engine
//! set of its own** (`neutrality-04`, 2026-08-16).
//!
//! # What this module used to do, and why it stopped
//!
//! Until this change a `SAFE_SEARCH_PRESETS` const compiled eight CNAME
//! rewrites into the binary — four search vendors, chosen here — and
//! [`populate`] injected them into every profile carrying
//! [`crate::config::schema::profile::Profile::safe_search`]`= true`.
//!
//! That is the project rules §Neutrality test failed in every clause at
//! once. It changed what warden did to **named** domains; the operator
//! never asked for those particular names; the rows were invisible in
//! their TOML (`profile show`, `rewrite list` and the TUI all read the
//! raw authored slice, deliberately); and correcting one needed a new
//! build. That last clause was not hypothetical — this doc used to
//! carry four vendor documentation URLs and an instruction to
//! "re-verify against current vendor documentation at every release",
//! which is a maintenance burden warden took on in exchange for
//! deciding something that was never its to decide.
//!
//! Being opt-in did not save it. The operator opted in to *SafeSearch*,
//! not to warden's roster of engines or to its choice of enforcement
//! tier.
//!
//! # What replaces it: nothing, because the mechanism already existed
//!
//! `[[rewrites]]` on the profile is now the only source of rewrite
//! rules. It was already the **sovereign** one — an explicit operator
//! rule always beat a preset — so this is a removal, not a new
//! mechanism to learn. An operator adds an engine, retargets one, or
//! picks a different enforcement tier by editing config and reloading:
//! no rebuild, and the result is visible on every surface that shows
//! rewrites, which the injected rows never were.
//!
//! # Consequence, stated because it is a defect and not a feature
//!
//! `profile.safe_search` now selects nothing: a profile serves the same
//! rewrites with the flag on and off. A boolean in operator config that
//! does nothing is its own problem, and retiring it needs
//! `config/schema/profile.rs` — out of this change's scope. Until then
//! [`crate::config::schema::validator`] WARNs on every load for every
//! profile that sets it (`SAFE_SEARCH_FLAG_SELECTS_NOTHING`), so a
//! config still claiming the old protection says so out loud instead of
//! quietly enforcing nothing. That is the same treatment
//! `neutrality-01` gave `[anti_bypass]` when its built-in domain list
//! was deleted, for the same reason: the silence was the defect, not
//! the drop.
//!
//! [`populate`] is kept rather than deleted. It is the seam both the
//! resolver ([`crate::profiles::profile::ResolvedProfile::build_v1`])
//! and the load-time audit
//! (`crate::config::validator::audit_safesearch_effective_rewrites`)
//! call, and keeping one function that both go through is what makes
//! "the audited set is the served set" true by construction. If a
//! future design gives warden an operator-supplied engine table, this
//! is where it plugs in — and it must arrive as data the operator
//! writes, never as a table shipped with the build.

use crate::config::settings::RewriteRule;

/// Contribute SafeSearch rewrite rules to `existing`.
///
/// **Contributes none.** warden holds no list of search engines and no
/// opinion about which hostname should redirect where; `existing` — the
/// operator's own `[[rewrites]]` — comes back untouched, in order.
///
/// Kept as the single seam the resolver and the load-time audit share,
/// so neither can drift onto a different effective set. See the module
/// doc for why the built-in table was removed and what an operator
/// writes instead.
///
/// Trivially idempotent, which the resolver relies on: it runs at
/// startup, at every SIGHUP, and on every 60s schedule re-evaluation.
pub fn populate(existing: &mut Vec<RewriteRule>) {
    // Deliberately empty. An `existing.retain(…)` or a "sensible
    // default" here would be warden deciding again by a different
    // route — see the module doc.
    let _ = existing;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The eight hostnames `SAFE_SEARCH_PRESETS` used to compile into the
    /// binary, paired with the CNAME target it used to send them to.
    ///
    /// Naming them **here** is the point, and it is the one place where
    /// naming them is correct: project rules §Neutrality says a vendor name
    /// in `#[cfg(test)]` is desirable when it proves *absence* of
    /// behaviour. If anyone reintroduces the table — in any shape, under
    /// any name — `populate` starts producing these rows again and every
    /// test below goes red.
    const RETIRED_PRESETS: &[(&str, &str)] = &[
        ("google.com", "forcesafesearch.google.com"),
        ("www.google.com", "forcesafesearch.google.com"),
        ("www.youtube.com", "restrict.youtube.com"),
        ("m.youtube.com", "restrict.youtube.com"),
        ("www.youtube-nocookie.com", "restrict.youtube.com"),
        ("www.bing.com", "strict.bing.com"),
        ("edgeservices.bing.com", "strict.bing.com"),
        ("duckduckgo.com", "safe.duckduckgo.com"),
    ];

    fn rule(from: &str, to: &str, match_subdomains: bool) -> RewriteRule {
        RewriteRule {
            from: from.into(),
            to: to.into(),
            match_subdomains,
        }
    }

    #[test]
    fn neutrality04_populate_injects_nothing_for_empty_input() {
        // The whole of neutrality-04 in one assertion: a profile with
        // `safe_search = true` and no `[[rewrites]]` rewrites NOTHING.
        // Before this change the same call produced eight rows the
        // operator never wrote and could not change without a new build.
        let mut v: Vec<RewriteRule> = Vec::new();
        populate(&mut v);
        assert!(
            v.is_empty(),
            "populate must inject no rule of its own; got {v:?}"
        );
    }

    #[test]
    fn neutrality04_no_retired_vendor_target_is_reachable() {
        // Discriminating needle: assert on the (from, to) PAIR, not on
        // the hostname alone. An operator is free to write a rewrite for
        // any of these names — that is the whole point of moving the set
        // into their config — so a test that failed on the mere presence
        // of `www.google.com` would go red on correct operator config.
        // What must never come back is warden *choosing* the target.
        let mut v: Vec<RewriteRule> = Vec::new();
        populate(&mut v);
        for (from, to) in RETIRED_PRESETS {
            assert!(
                !v.iter().any(|r| r.from == *from && r.to == *to),
                "populate re-injected the retired preset {from} -> {to}"
            );
        }
    }

    #[test]
    fn neutrality04_operator_rules_survive_byte_identical() {
        // Replaces the four `..._skips_existing_collision` tests. There is
        // no longer anything to skip, so the property that carries their
        // intent forward is stronger and simpler: the operator's slice
        // comes back out unchanged — same rules, same order, same flags,
        // nothing appended after it.
        let before = vec![
            rule("www.google.com", "my.intranet.local", false),
            rule("ads.lan", "safe.lan", true),
            rule("duckduckgo.com", "safe.duckduckgo.com", false),
        ];
        let mut after = before.clone();
        populate(&mut after);
        assert_eq!(after.len(), before.len(), "populate appended: {after:?}");
        for (i, (a, b)) in after.iter().zip(before.iter()).enumerate() {
            assert_eq!(a.from, b.from, "rule {i} from");
            assert_eq!(a.to, b.to, "rule {i} to");
            assert_eq!(a.match_subdomains, b.match_subdomains, "rule {i} flag");
        }
    }

    #[test]
    fn neutrality04_operator_may_target_a_retired_hostname_freely() {
        // The migration path: an operator who WANTS the old behaviour
        // writes it themselves, and populate must neither duplicate it
        // nor second-guess the target they chose. `moderate` here is
        // s4-53-disc-1's YouTube tier — a config edit now, not a schema
        // enum and not a new build.
        let mut v = vec![rule(
            "www.youtube.com",
            "restrictmoderate.youtube.com",
            false,
        )];
        populate(&mut v);
        assert_eq!(v.len(), 1, "no second row for the same name: {v:?}");
        assert_eq!(v[0].to, "restrictmoderate.youtube.com");
    }

    #[test]
    fn neutrality04_populate_is_idempotent() {
        // Was true of the injecting version and stays true: the resolver
        // calls this on every 60s schedule re-evaluation, and the
        // validator calls it again on the same slice.
        let mut v = vec![rule("ads.lan", "safe.lan", false)];
        populate(&mut v);
        populate(&mut v);
        populate(&mut v);
        assert_eq!(v.len(), 1, "{v:?}");
    }
}
