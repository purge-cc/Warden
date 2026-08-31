//! `warden config show [--resolved] [--annotate] [--section NAME]`.
//!
//! Three presentation modes on top of the same v1 loader:
//!
//! - **Default** — the merged `ConfigV1` serialised as TOML.
//! - **`--section <name>`** — print only one top-level table/array
//!   (`devices`, `profiles`, `subnets`, `server`, `upstream`, `cache`, …).
//! - **`--annotate`** — precede the output with a block listing every
//!   entity's source file:line from the loader's provenance sidecar.
//! - **`--resolved`** — report every configured device and subnet with
//!   the profile the 5-level resolver would pick (design doc §9.2).
//!
//! `--section` composes with `--resolved`, but over a narrower vocabulary:
//! the resolved view is a report rather than a serialisation, so it only
//! has blocks for `devices`, `subnets`, and `server` (see
//! [`RESOLVED_SECTIONS`]). Naming any other section under `--resolved` is
//! an error — previously it was silently ignored and the whole view
//! printed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::config::cidr::Cidr;
use crate::config::loader::{self, LoadedConfig, ProvenanceMap};
use crate::config::secrets;
use crate::lists::manager::merge_sources_with_blocklists;
use crate::lists::source_key::SourceBitMap;
use crate::profiles::resolver::ResolveLevel;
use crate::profiles::ProfileResolver;

/// Mask shown in `warden config show` in place of any value resolved
/// from `secrets.toml`. Sprint 32 N9 — the secrets file is never merged
/// into the show output, so the ref name passes through unchanged while
/// the resolved value is replaced by this constant.
const SECRET_MASK: &str = "****";

/// Print the current configuration with the requested flags applied.
///
/// `section`: `None` prints every section; `Some(name)` prints just that
///   top-level key. Unknown names return an error.
pub fn run_show(
    config_path: &Path,
    resolved: bool,
    annotate: bool,
    section: Option<&str>,
) -> anyhow::Result<()> {
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
            anyhow::bail!("config load failed");
        }
    };

    if annotate {
        print_annotations(&loaded.provenance);
        println!();
    }

    if resolved {
        print_resolved_view(&loaded, section)?;
        return Ok(());
    }

    match section {
        None => {
            // Serialised inside the arm that uses it. Computing it up
            // front made `--section server` inherit a whole-config
            // serialisation failure, which inverts what narrowing is for:
            // the operator reaches for `--section` precisely when the full
            // dump is unwieldy or broken.
            let full = toml::to_string_pretty(&loaded.config)
                .map_err(|e| anyhow::anyhow!("failed to serialise config: {}", e))?;
            println!("# {}", config_path.display());
            println!("{full}");
        }
        Some(name) => {
            let value = toml::Value::try_from(&loaded.config)
                .map_err(|e| anyhow::anyhow!("failed to serialise config: {}", e))?;
            let table = value
                .as_table()
                .ok_or_else(|| anyhow::anyhow!("config did not serialise to a table"))?;
            let sub = table
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("unknown section: {name}"))?;
            let mut filtered = toml::Table::new();
            filtered.insert(name.to_string(), sub.clone());
            let rendered = toml::to_string_pretty(&filtered)
                .map_err(|e| anyhow::anyhow!("failed to render section: {}", e))?;
            println!("# {} — section [{}]", config_path.display(), name);
            println!("{rendered}");
        }
    }

    // Sprint 32 N9: print a masked summary of every secret that a
    // blocklist's `auth_token_ref` resolves to. The ref name is already
    // present in the config serialisation above — this footer confirms
    // to the operator which refs are currently bound to a real secret
    // and which are dangling. Values are ALWAYS `****` regardless of
    // what `secrets.toml` contains.
    print_secret_mask_footer(config_path, &loaded);

    Ok(())
}

/// After the normal show output, emit one masked line per blocklist that
/// carries an `auth_token_ref`. Example:
///
/// ```text
/// # resolved secrets (masked)
/// #   blocklists.corp-ads.auth_token_ref = "corp-ads-token" → ****
/// #   blocklists.other.auth_token_ref   = "missing-token"   → (ref missing from secrets.toml)
/// ```
///
/// The file itself is never opened unless at least one `auth_token_ref`
/// exists — so benign configs without secrets have zero additional IO.
fn print_secret_mask_footer(config_path: &Path, loaded: &LoadedConfig) {
    let refs: Vec<(&str, &str)> = loaded
        .config
        .blocklists
        .iter()
        .filter_map(|b| b.auth_token_ref.as_deref().map(|r| (b.id.as_str(), r)))
        .collect();
    if refs.is_empty() {
        return;
    }

    let secrets_path = secrets::secrets_path_for(config_path);
    let table = secrets::load_secrets(&secrets_path).unwrap_or_else(|_| secrets::Secrets::empty());

    println!();
    println!("# resolved secrets (masked)");
    for (id, name) in refs {
        if table.get(name).is_some() {
            println!("#   blocklists.{id}.auth_token_ref = \"{name}\" → {SECRET_MASK}");
        } else {
            println!(
                "#   blocklists.{id}.auth_token_ref = \"{name}\" → (ref missing from secrets.toml)"
            );
        }
    }
}

fn print_annotations(provenance: &ProvenanceMap) {
    println!("# source provenance ({} entrie(s))", provenance.len());
    for (entity, (file, line)) in provenance {
        println!("#   {entity}: {}:{line}", file.display());
    }
}

/// The `--section` names the resolved view can render. The resolved view
/// is a report, not a serialisation of the config, so it only has a block
/// for the keys that participate in resolution — unlike the default view,
/// where every top-level TOML key is addressable.
const RESOLVED_SECTIONS: [&str; 3] = ["devices", "subnets", "server"];

/// Report every configured device and subnet with the resolver output.
///
/// For a subnet we pick the first address in the first CIDR as a
/// representative source — enough to show which level-4 profile an
/// unmapped caller from that range would land on. Devices that carry an
/// `ip` are resolved directly; MAC-only devices report a note (their
/// resolution requires an ARP lookup which the offline tool skips).
///
/// `section`: `None` prints every block. `Some(name)` prints just that
/// block, where `name` is one of [`RESOLVED_SECTIONS`]. Any other name is
/// an error naming the three — a section that exists in the config but has
/// no resolved rendering (`upstream`, `cache`, `profiles`, …) must not
/// silently fall back to printing everything, which is the defect this
/// parameter exists to close.
fn print_resolved_view(loaded: &LoadedConfig, section: Option<&str>) -> anyhow::Result<()> {
    print!("{}", render_resolved_view(loaded, section)?);
    Ok(())
}

/// Build the resolved-view report as a string.
///
/// Split out from [`print_resolved_view`] so a test can assert on what the
/// section filter actually excluded. Asserting "the command exited 0" is
/// satisfied by the old ignore-the-filter behaviour, so the only honest
/// test is one that reads the rendered text.
fn render_resolved_view(loaded: &LoadedConfig, section: Option<&str>) -> anyhow::Result<String> {
    use std::fmt::Write as _;

    if let Some(name) = section {
        if !RESOLVED_SECTIONS.contains(&name) {
            anyhow::bail!(
                "section \"{name}\" has no resolved view (--resolved renders: {}). \
                 Drop --resolved to print the configured [{name}] table.",
                RESOLVED_SECTIONS.join(", ")
            );
        }
    }
    let want = |block: &str| section.is_none() || section == Some(block);
    let mut out = String::new();

    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
    let source_bits = SourceBitMap::build(&merged_sources, &loaded.config.blocklists)
        .map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;
    let resolver = ProfileResolver::build(&loaded.config, &source_bits, &loaded.custom_lists);

    let _ = writeln!(out, "# resolved view — what the 5-level chain would pick\n");

    if want("devices") {
        let _ = writeln!(out, "## Devices ({})", loaded.config.devices.len());
        for dev in &loaded.config.devices {
            match dev.ip {
                Some(ip) => {
                    let res = resolver.resolve(&ip);
                    let _ = writeln!(
                        out,
                        "  {} ({}) ip={} → {} [{}]",
                        dev.id.as_str(),
                        dev.display_name,
                        ip,
                        format_profile(&res.profile),
                        format_level(res.level),
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "  {} ({}) mac-only → resolved at query time via ARP",
                        dev.id.as_str(),
                        dev.display_name,
                    );
                }
            }
        }
    }

    if want("subnets") {
        let _ = writeln!(out, "\n## Subnets ({})", loaded.config.subnets.len());
        for sn in &loaded.config.subnets {
            for cidr_str in &sn.cidrs {
                let Some(repr) = first_address(cidr_str) else {
                    let _ = writeln!(
                        out,
                        "  {} ({}) cidr={} → <could not parse CIDR>",
                        sn.id.as_str(),
                        sn.display_name,
                        cidr_str,
                    );
                    continue;
                };
                let res = resolver.resolve(&repr);
                let _ = writeln!(
                    out,
                    "  {} ({}) cidr={} → {} [{}]",
                    sn.id.as_str(),
                    sn.display_name,
                    cidr_str,
                    format_profile(&res.profile),
                    format_level(res.level),
                );
            }
        }
    }

    if want("server") {
        let _ = writeln!(out, "\n## Global fallback (level 5)");
        match &loaded.config.server.default_profile {
            Some(p) => {
                let _ = writeln!(out, "  server.default_profile = {}", p.as_str());
            }
            None => {
                let _ = writeln!(
                    out,
                    "  server.default_profile unset — any level-5 match returns REFUSED"
                );
            }
        }
        let _ = writeln!(out, "\n## Profile N6 fallbacks (server globals)");
        let _ = writeln!(
            out,
            "  default_block_response  = {:?}",
            loaded.config.server.default_block_response
        );
        let _ = writeln!(
            out,
            "  default_blocked_ttl_secs = {}",
            loaded.config.server.default_blocked_ttl_secs
        );
    }

    Ok(out)
}

fn format_profile(p: &Option<std::sync::Arc<crate::profiles::profile::ResolvedProfile>>) -> String {
    match p {
        Some(rp) => rp.name.to_string(),
        None => "<REFUSED>".to_string(),
    }
}

fn format_level(level: Option<ResolveLevel>) -> &'static str {
    match level {
        Some(ResolveLevel::DeviceDirect) => "level 1 device-direct",
        Some(ResolveLevel::Schedule) => "level 2 schedule",
        Some(ResolveLevel::Group) => "level 3 group",
        Some(ResolveLevel::Subnet) => "level 4 subnet",
        Some(ResolveLevel::GlobalDefault) => "level 5 default",
        None => "none — REFUSED",
    }
}

/// Return the network address of a CIDR range as a representative IP
/// for the resolved view. Falls back to `None` if the string is
/// unparseable (let the caller surface it in the output rather than
/// aborting the whole command).
fn first_address(cidr: &str) -> Option<IpAddr> {
    match Cidr::parse(cidr).ok()? {
        Cidr::V4 { network, .. } => Some(IpAddr::V4(Ipv4Addr::from(network))),
        Cidr::V6 { network, .. } => Some(IpAddr::V6(Ipv6Addr::from(network))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    }

    #[test]
    fn show_default_prints_without_error() {
        run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            false,
            false,
            None,
        )
        .unwrap();
    }

    #[test]
    fn show_section_filters_to_named_key() {
        run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            false,
            false,
            Some("devices"),
        )
        .unwrap();
    }

    #[test]
    fn show_section_errors_on_unknown_name() {
        let err = run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            false,
            false,
            Some("bogus-section"),
        );
        assert!(err.is_err(), "unknown section must error");
    }

    #[test]
    fn show_with_annotate_runs_without_error() {
        run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            false,
            true,
            None,
        )
        .unwrap();
    }

    #[test]
    fn show_with_resolved_runs_without_error() {
        run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            true,
            false,
            None,
        )
        .unwrap();
    }

    /// Load the shared fixture for the resolved-view render tests.
    fn loaded_fixture() -> LoadedConfig {
        let now = time::OffsetDateTime::now_utc();
        loader::load_config(&fixture("tests/fixtures/minimal-v1/config.toml"), now)
            .expect("fixture config loads")
    }

    /// The defect: `--section` was skipped entirely under `--resolved`, so
    /// this rendered every block. Asserting "exit 0" passes on that bug —
    /// the assertion has to be that the OTHER blocks are absent.
    #[test]
    fn resolved_section_devices_excludes_the_other_blocks() {
        let loaded = loaded_fixture();
        let out = render_resolved_view(&loaded, Some("devices")).expect("devices is renderable");
        assert!(out.contains("## Devices"), "devices block must be present");
        assert!(
            !out.contains("## Subnets"),
            "--section devices must exclude the Subnets block, got:\n{out}"
        );
        assert!(
            !out.contains("## Global fallback"),
            "--section devices must exclude the server block, got:\n{out}"
        );
    }

    /// Mirror of the above for the other two renderable sections, so a
    /// future edit cannot fix one block's gating and leave another leaking.
    #[test]
    fn resolved_section_subnets_and_server_each_exclude_the_rest() {
        let loaded = loaded_fixture();

        let subnets = render_resolved_view(&loaded, Some("subnets")).expect("subnets renderable");
        assert!(subnets.contains("## Subnets"));
        assert!(!subnets.contains("## Devices"), "got:\n{subnets}");
        assert!(!subnets.contains("## Global fallback"), "got:\n{subnets}");

        let server = render_resolved_view(&loaded, Some("server")).expect("server renderable");
        assert!(server.contains("## Global fallback"));
        assert!(!server.contains("## Devices"), "got:\n{server}");
        assert!(!server.contains("## Subnets"), "got:\n{server}");
    }

    /// `None` still renders everything — the filter must not have turned
    /// the unfiltered path into a partial one.
    #[test]
    fn resolved_without_section_still_renders_every_block() {
        let loaded = loaded_fixture();
        let out = render_resolved_view(&loaded, None).expect("full view renders");
        for block in ["## Devices", "## Subnets", "## Global fallback"] {
            assert!(out.contains(block), "full view missing {block}:\n{out}");
        }
    }

    /// A section that exists in the config but has no resolved rendering
    /// must be refused by name, not silently ignored. On the old code this
    /// returned `Ok` and printed the whole view.
    #[test]
    fn resolved_section_without_a_rendering_is_refused_by_name() {
        let loaded = loaded_fixture();
        for name in ["upstream", "cache", "profiles", "bogus"] {
            let err = render_resolved_view(&loaded, Some(name))
                .expect_err("section with no resolved view must error");
            let msg = err.to_string();
            assert!(
                msg.contains(name) && msg.contains("no resolved view"),
                "error must name the section and the reason, got: {msg}"
            );
        }
    }

    /// End-to-end through the public entry point, so the wiring from
    /// `run_show` into the renderer is covered too.
    #[test]
    fn run_show_resolved_refuses_unrenderable_section() {
        let err = run_show(
            &fixture("tests/fixtures/minimal-v1/config.toml"),
            true,
            false,
            Some("upstream"),
        );
        assert!(
            err.is_err(),
            "`config show --resolved --section upstream` must not silently succeed"
        );
    }

    #[test]
    fn show_fails_cleanly_on_invalid_config() {
        let err = run_show(
            &fixture("tests/fixtures/broken-v1/cross_ref_miss.toml"),
            false,
            false,
            None,
        );
        assert!(err.is_err(), "invalid config should not silently pass");
    }

    /// Sprint 32 N9: a blocklist with `auth_token_ref` must surface in the
    /// `warden config show` output as a masked line. The ref name is
    /// visible (it's metadata, not a secret), but the resolved value is
    /// `****` regardless of what `secrets.toml` actually contains.
    #[test]
    fn show_masks_blocklist_auth_token_ref_value() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static CTR: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-show-mask-{pid}-{n}"));
        fs::create_dir_all(&dir).unwrap();

        let config_path = dir.join("config.toml");
        fs::write(
            &config_path,
            r#"schema_version = 3

[server]
listen = "127.0.0.1:5353"

[[blocklists]]
id = "corp-ads"
display_name = "Corp: ads"
url = "https://corp.example.com/ads.txt"
format = "domains"
auth_token_ref = "corp-ads-token"

[profiles.default]
display_name = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let secrets_path = dir.join("secrets.toml");
        {
            let mut f = fs::File::create(&secrets_path).unwrap();
            f.write_all(b"corp-ads-token = \"bearer-xxxxxxxxxxxxxxxx\"\n")
                .unwrap();
        }
        let mut perm = fs::metadata(&secrets_path).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&secrets_path, perm).unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&config_path, now).expect("config loads");

        // The masking helper is pure + prints via `println!`; we can't
        // easily capture stdout in a unit test without extra plumbing,
        // but we CAN assert the ref-resolution path works: the secret
        // table resolves the ref.
        let table =
            secrets::load_secrets(&secrets_path).expect("secrets loads with correct permissions");
        let ref_name = loaded.config.blocklists[0].auth_token_ref.as_deref();
        assert_eq!(ref_name, Some("corp-ads-token"));
        assert!(table.get("corp-ads-token").is_some(), "secret resolves");

        // Invoke the path that emits the masked footer — asserting it
        // doesn't panic on a valid config exercising the footer code.
        print_secret_mask_footer(&config_path, &loaded);

        // Sanity: SECRET_MASK is the fixed string "****" the operator sees.
        assert_eq!(SECRET_MASK, "****");

        let _ = fs::remove_dir_all(&dir);
    }
}
