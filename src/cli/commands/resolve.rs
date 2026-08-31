//! `warden resolve <ip>` — offline 5-level resolver attribution.
//!
//! Loads the v1 config from disk, builds a fresh [`ProfileResolver`],
//! evaluates the source IP, and prints the match level + device +
//! profile in a human-friendly format that matches the design doc §9.2.
//!
//! **Offline mode only for now.** The command does NOT consult the
//! running daemon via IPC — it simply re-runs the resolver against the
//! on-disk config. That means the output reflects the config as it
//! would be loaded on the next SIGHUP, not necessarily what the daemon
//! has active right now (if the operator edited the file without
//! reloading). S31+ can add an IPC path if the divergence becomes a
//! real operator pain point.
//!
//! # Exit codes
//!
//! - [`SUCCESS`] — resolution succeeded (any level 1-5 matched).
//! - [`FAILURE`](crate::cli::exit_codes::FAILURE) — the resolver could not be built (e.g. the list bitmap
//!   failed to assemble). No verdict was reached.
//! - [`CONFIG`] — config load failed (syntax / validation error).
//! - [`NEGATIVE`] — the source IP is REFUSED: level 5 reached with
//!   `server.default_profile` unset.
//!
//! REFUSED used to be `1`, which collided with this command's own
//! "something went wrong" code — a script could not tell "this IP would
//! be refused" (a real, useful answer) from "I could not compute an
//! answer". Under the contract those are [`NEGATIVE`] and [`FAILURE`](crate::cli::exit_codes::FAILURE),
//! and they are now distinct.

use std::net::IpAddr;
use std::path::Path;

use crate::cli::exit_codes::{CONFIG, NEGATIVE, SUCCESS};
use crate::config::loader;
use crate::lists::manager::merge_sources_with_blocklists;
use crate::lists::source_key::SourceBitMap;
use crate::profiles::ProfileResolver;

/// Run the offline resolver query. Returns a `Result<i32, anyhow::Error>`
/// where the inner integer is the intended process exit code. The caller
/// (main.rs) translates this into `std::process::exit(...)` at dispatch
/// time.
pub fn run_resolve(config_path: &Path, ip: IpAddr) -> anyhow::Result<i32> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = match loader::load_config(config_path, now) {
        Ok(l) => l,
        Err(errs) => {
            eprintln!(
                "cannot load config {} ({} error(s)):",
                config_path.display(),
                errs.len()
            );
            for err in &errs {
                eprintln!("  - {err}");
            }
            return Ok(CONFIG);
        }
    };

    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
    let source_bits = SourceBitMap::build(&merged_sources, &loaded.config.blocklists)
        .map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;
    let resolver = ProfileResolver::build(&loaded.config, &source_bits, &loaded.custom_lists);
    let resolution = resolver.resolve(&ip);

    println!("Source IP:      {ip}");
    match resolution.device_id.as_ref() {
        Some(id) => {
            let display = resolution.device_name.as_deref().unwrap_or(id.as_str());
            println!("Matched device: {} ({display})", id.as_str());
        }
        None => {
            println!("Matched device: <none>");
        }
    }

    match resolution.level {
        Some(level) => {
            let description = match level {
                crate::profiles::resolver::ResolveLevel::DeviceDirect => {
                    "1 (direct device profile)"
                }
                crate::profiles::resolver::ResolveLevel::Schedule => "2 (active schedule override)",
                crate::profiles::resolver::ResolveLevel::Group => "3 (group membership)",
                crate::profiles::resolver::ResolveLevel::Subnet => "4 (subnet longest-prefix)",
                crate::profiles::resolver::ResolveLevel::GlobalDefault => {
                    "5 (global default_profile)"
                }
            };
            println!("Match level:    {description}");
            if let Some(sched) = resolution.matched_schedule.as_ref() {
                println!("Active schedule: {}", sched.as_str());
            }
            if let Some(group) = resolution.matched_group.as_ref() {
                println!("Via group:       {}", group.as_str());
            }
            if let Some(subnet) = resolution.matched_subnet.as_ref() {
                println!("Via subnet:      {}", subnet.as_str());
            }
        }
        None => {
            println!("Match level:    <REFUSED — no level 1-5 matched>");
            println!("\nThis source would be REFUSED by the daemon.");
            println!(
                "To resolve it, either map the IP to a `[[devices]]` row, \
                 wire a `[[subnets]]` that covers it, or set \
                 `server.default_profile` to a fallback profile."
            );
            // NEGATIVE, not FAILURE: this is a correct answer to the
            // question asked, and it must be distinguishable from the
            // bitmap-build failure above, which also used to be `1`.
            return Ok(NEGATIVE);
        }
    }

    match resolution.profile.as_ref() {
        Some(p) => println!("Active profile: {}", p.name),
        None => println!("Active profile: <none — REFUSED>"),
    }
    print_tag_provenance(&loaded.config, &resolution);
    Ok(SUCCESS)
}

/// Print the list policy this resolution actually filters under.
///
/// # What this used to print, and why it changed (`plp-s3`)
///
/// It printed every *effective tag* with the entity that contributed it,
/// then the blocklists that tag set resolved to. The reason was sound and is
/// worth keeping in view: group tags widened what a device blocked, and a
/// block the operator could not trace to its cause was indistinguishable
/// from a bug — the only symptom being "why doesn't this site open?".
///
/// `_docs/features/profile_list_policy.md` removes the indirection instead
/// of tracing it. Direction is now a property of the `(profile, list)` pair,
/// so there is nothing to attribute: the profile the resolver landed on IS
/// the answer, and each list's direction under it is one lookup. The
/// traceability the tag-origin block bought is now free.
///
/// Uses [`effective_direction`](crate::config::schema::effective_direction) —
/// the same predicate the publish-time projection and `blocklist show`'s
/// enforcement report call. Never a re-derivation; that is the mistake D11
/// recorded and P5 forbids.
///
/// `unfiltered` is printed on its own line because it is the one thing that
/// still varies per *device* rather than per profile, and a reader who sees
/// a deny-list listed here needs to know it is not being applied to them.
///
/// Disabled lists are excluded: a disabled row never reaches the merged
/// sources vector, so it holds no bit and provably cannot be part of what
/// resolves.
///
/// Returns every line printed (in order), so tests can assert on the
/// exact output without capturing process stdout.
fn print_tag_provenance(
    config: &crate::config::schema::ConfigV1,
    resolution: &crate::profiles::Resolution,
) -> Vec<String> {
    use crate::config::schema::{effective_direction, ListPolicy};

    let mut lines = Vec::new();

    let Some(resolved) = resolution.profile.as_ref() else {
        return lines;
    };
    let Some(profile) = config.profiles.get(resolved.name.as_str()) else {
        return lines;
    };

    let device = resolution
        .device_id
        .as_ref()
        .and_then(|id| config.devices.iter().find(|d| &d.id == id));

    if device.is_some_and(|d| d.unfiltered) {
        lines.push("Effective tags: <none — device is unfiltered>".to_string());
        lines.push(String::new());
        lines.push("Resolved blocklists: none".to_string());
        for line in &lines {
            println!("{line}");
        }
        return lines;
    }

    let mut matched: Vec<(crate::config::schema::Id, ListPolicy)> = config
        .blocklists
        .iter()
        .filter(|b| b.enabled)
        .filter_map(|b| match effective_direction(profile, b) {
            ListPolicy::Ignore => None,
            dir => Some((b.id.clone(), dir)),
        })
        .collect();
    matched.sort_by(|a, b| a.0.cmp(&b.0));

    if matched.is_empty() {
        lines.push("Resolved blocklists: none".to_string());
    } else {
        let annotated: Vec<String> = matched
            .iter()
            .map(|(id, dir)| format!("{} [{}]", id.as_str(), dir.wire_str()))
            .collect();
        lines.push(format!(
            "Resolved blocklists ({}): {}",
            matched.len(),
            annotated.join(", ")
        ));
    }

    for line in &lines {
        println!("{line}");
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cfg(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let p = dir.path().join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    /// Mirrors `run_resolve`'s own setup glue so tests can reach a
    /// [`crate::profiles::Resolution`] and call `print_tag_provenance`
    /// directly, asserting on its returned lines instead of capturing
    /// process stdout (this crate has no stdout-capture dev-dependency).
    fn resolve_for_test(
        path: &Path,
        ip: IpAddr,
    ) -> (crate::config::schema::ConfigV1, crate::profiles::Resolution) {
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(path, now).expect("test config should load");
        let (merged_sources, _trust) =
            merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
        let source_bits = SourceBitMap::build(&merged_sources, &loaded.config.blocklists)
            .expect("test source bitmap should build");
        let resolver = ProfileResolver::build(&loaded.config, &source_bits, &loaded.custom_lists);
        let resolution = resolver.resolve(&ip);
        (loaded.config, resolution)
    }

    #[test]
    fn resolve_exit_config_on_unloadable_config() {
        // stats-01: a config that fails to load → CONFIG.
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(&dir, "this = is = not = valid = toml\n");
        let code = run_resolve(&p, "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(code, CONFIG);
    }

    /// REFUSED moved from 1 to NEGATIVE (3).
    ///
    /// At 1 it shared a code with this command's own "something went
    /// wrong" path — the bitmap-build failure a few lines above the
    /// resolution — so a script could not tell "this IP would be refused"
    /// (a real, useful answer) from "I could not compute an answer".
    #[test]
    fn resolve_exit_negative_when_refused() {
        // No default_profile + no device/subnet match → level 5 unreachable
        // → REFUSED.
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let code = run_resolve(&p, "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(code, NEGATIVE);
    }

    #[test]
    fn resolve_exit_success_on_match() {
        // default_profile set → unmapped IP falls to level 5 → success.
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let code = run_resolve(&p, "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(code, SUCCESS);
    }

    /// The three outcomes must stay mutually distinguishable. Asserting
    /// each code in isolation would still pass if two of them were
    /// accidentally unified; this pins the separation itself, which is the
    /// property a script depends on.
    #[test]
    fn the_three_resolve_outcomes_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let refused = write_cfg(
            &dir,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let refused_code = run_resolve(&refused, "10.0.0.1".parse().unwrap()).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let broken = write_cfg(&dir2, "this = is = not = valid = toml\n");
        let broken_code = run_resolve(&broken, "10.0.0.1".parse().unwrap()).unwrap();

        assert_ne!(
            refused_code, broken_code,
            "REFUSED and could-not-load must not share a code"
        );
        assert_ne!(refused_code, SUCCESS);
        assert_ne!(broken_code, SUCCESS);
        // ...and neither may collide with FAILURE, which this command
        // reserves for a resolver it could not build.
        assert_ne!(refused_code, crate::cli::exit_codes::FAILURE);
    }

    /// A device's tag resolves to every blocklist that shares the tag,
    /// listed sorted by id — not TOML declaration order (`zzz-list` is
    /// declared before `ads-block`) — and never a list tagged only
    /// `tracking`, which is disjoint from this device's tags.
    #[test]
    fn resolve_lists_matching_blocklists_sorted_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\nenforce_device_mac = false\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             ip = \"10.0.0.5\"\nprofile = \"default\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"zzz-list\"\ndisplay_name = \"Zzz\"\n\
             url = \"https://example.invalid/zzz.txt\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"ads-block\"\ndisplay_name = \"Ads Block\"\n\
             url = \"https://example.invalid/ads.txt\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"unrelated\"\ndisplay_name = \"Unrelated\"\n\
             url = \"https://example.invalid/unrelated.txt\"\ntags = [\"tracking\"]\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let (config, resolution) = resolve_for_test(&p, "10.0.0.5".parse().unwrap());
        assert!(
            resolution.profile.is_some(),
            "expected a profile match, got {resolution:?}"
        );

        let lines = print_tag_provenance(&config, &resolution);
        // `plp-s3`: `unrelated` used to be excluded because its tag did not
        // intersect the device's. Tags decide nothing now, so every enabled
        // list this profile does not `ignore` resolves — sorted by id, which
        // is what this test actually pins.
        assert!(
            lines.contains(
                &"Resolved blocklists (3): ads-block [deny], unrelated [deny], zzz-list [deny]"
                    .to_string()
            ),
            "lines: {lines:?}"
        );
    }

    /// A tag-matching but `enabled = false` list must NOT appear:
    /// `list_applies` only checks tag intersection, not `enabled` (by
    /// design — `blocklist show`'s enforcement report needs the disabled
    /// case too), and a disabled list never gets a source bit
    /// (`merge_sources_with_blocklists` skips it), so it provably cannot
    /// be part of what "actually resolves".
    #[test]
    fn resolve_excludes_disabled_lists_even_when_tags_match() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\nenforce_device_mac = false\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             ip = \"10.0.0.5\"\nprofile = \"default\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"ads-block\"\ndisplay_name = \"Ads Block\"\n\
             url = \"https://example.invalid/ads.txt\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"dead-list\"\ndisplay_name = \"Dead\"\n\
             url = \"https://example.invalid/dead.txt\"\ntags = [\"ads\"]\nenabled = false\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let (config, resolution) = resolve_for_test(&p, "10.0.0.5".parse().unwrap());
        assert!(
            resolution.profile.is_some(),
            "expected a profile match, got {resolution:?}"
        );

        let lines = print_tag_provenance(&config, &resolution);
        assert!(
            lines.contains(&"Resolved blocklists (1): ads-block [deny]".to_string()),
            "dead-list must not appear — lines: {lines:?}"
        );
    }

    /// Each resolved id is annotated with its direction so an
    /// allow-direction list never reads as "this blocks you" — it does
    /// the opposite. `base = "allow"` here pairs with `trust = "local"`
    /// so the config needs no `accept_unsigned_allow` consent (project rules
    /// §Neutrality's consent table: allow + local trust needs none).
    #[test]
    fn resolve_annotates_resolved_blocklists_with_kind() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\nenforce_device_mac = false\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             ip = \"10.0.0.5\"\nprofile = \"default\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"deny-list\"\ndisplay_name = \"Deny List\"\n\
             url = \"https://example.invalid/deny.txt\"\ntags = [\"ads\"]\n\n\
             [[blocklists]]\nid = \"allow-list\"\ndisplay_name = \"Allow List\"\n\
             url = \"https://example.invalid/allow.txt\"\ntags = [\"ads\"]\n\
             base = \"allow\"\ntrust = \"local\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let (config, resolution) = resolve_for_test(&p, "10.0.0.5".parse().unwrap());
        assert!(
            resolution.profile.is_some(),
            "expected a profile match, got {resolution:?}"
        );

        let lines = print_tag_provenance(&config, &resolution);
        assert!(
            lines.contains(
                &"Resolved blocklists (2): allow-list [allow], deny-list [deny]".to_string()
            ),
            "lines: {lines:?}"
        );
    }

    /// `Resolved blocklists: none` — a real line, not a blank one.
    ///
    /// **`plp-s3` changed how a profile gets there.** It used to be tag
    /// disjunction (device tagged `ads`, the only list tagged `tracking`).
    /// Tags reach nothing now, so the only way a profile resolves to no list
    /// is by overriding every one of them to `ignore` — which is what the
    /// fixture says, and which is the same state the validator's
    /// `PROFILE_FILTERS_NO_LISTS` WARN names.
    #[test]
    fn resolve_reports_no_resolved_blocklists_when_every_list_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\nenforce_device_mac = false\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\
             lists = { tracking-block = \"ignore\" }\n\n\
             [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             ip = \"10.0.0.5\"\nprofile = \"default\"\n\n\
             [[blocklists]]\nid = \"tracking-block\"\ndisplay_name = \"Tracking\"\n\
             url = \"https://example.invalid/tracking.txt\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let (config, resolution) = resolve_for_test(&p, "10.0.0.5".parse().unwrap());
        assert!(
            resolution.profile.is_some(),
            "expected a profile match, got {resolution:?}"
        );

        let lines = print_tag_provenance(&config, &resolution);
        assert!(
            lines.contains(&"Resolved blocklists: none".to_string()),
            "lines: {lines:?}"
        );
    }

    /// An unfiltered device has no effective tags at all (D14
    /// short-circuit) — must still print an explicit
    /// `Resolved blocklists: none`, not skip the line.
    #[test]
    fn resolve_reports_no_resolved_blocklists_when_device_unfiltered() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_cfg(
            &dir,
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\nenforce_device_mac = false\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [[devices]]\nid = \"guest\"\ndisplay_name = \"Guest\"\n\
             ip = \"10.0.0.6\"\nprofile = \"default\"\nunfiltered = true\n\n\
             [[blocklists]]\nid = \"ads-block\"\ndisplay_name = \"Ads Block\"\n\
             url = \"https://example.invalid/ads.txt\"\ntags = [\"ads\"]\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let (config, resolution) = resolve_for_test(&p, "10.0.0.6".parse().unwrap());
        assert!(
            resolution.profile.is_some(),
            "expected a profile match, got {resolution:?}"
        );

        let lines = print_tag_provenance(&config, &resolution);
        assert!(
            lines.contains(&"Effective tags: <none — device is unfiltered>".to_string()),
            "lines: {lines:?}"
        );
        assert!(
            lines.contains(&"Resolved blocklists: none".to_string()),
            "lines: {lines:?}"
        );
    }
}
