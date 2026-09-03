//! **The golden that makes the S1 direction refactor falsifiable.**
//!
//! `_docs/features/profile_list_policy.md` §4 S1 asks for one thing before
//! any code moves: a record of what the engine *decides*, taken from HEAD,
//! that the refactored engine must reproduce line for line.
//!
//! # Why verdicts and not masks
//!
//! S1 derives the new per-policy masks from the same `tags ∩ kind`
//! intersection the old shard-scalar `allow_bits` came from, so a test that
//! compared `old_formula == new_formula` would be comparing one calculation
//! with itself. §4 S1 says so outright: *"sarebbe un'identità algebrica […]
//! non misurerebbe niente."* The only thing that cannot be satisfied by
//! restating the arithmetic is the **verdict** a real query gets.
//!
//! # Three verdicts, not two
//!
//! [`FilterEngine::evaluate`] answers `Block` / `Forward`, and that is one
//! bit too few. A `Forward` because an allow-direction list matched and a
//! `Forward` because nothing matched at all are the same value — so a
//! refactor that dropped the allow side entirely would leave every row of a
//! two-valued golden untouched. The allow side is *precisely* where this
//! refactor is risky (§1.4: the superset error is the fail-open one), so the
//! third state is reconstructed from [`FilterEngine::list_membership`] and
//! recorded separately. [`allow_side_is_exercised`] then refuses to let the
//! table go blind.
//!
//! # Built through the production install path
//!
//! Config TOML → `load_config` → `merge_sources_with_blocklists` →
//! `SourceBitMap` → `ListManager::refresh` (`build_shard` →
//! `SortedShard::from_sorted_entries` → `swap_shard_sorted`) →
//! `ProfileResolver::build` → `resolve(ip)` → `evaluate`. Deliberately
//! **not** `FilterEngine::with_per_direction_domain_map` or
//! `SortedShard::from_pairs`: that pair is the two-mask *adapter*, the one
//! input shape that can express a list bit in both directions, and its own
//! doc records that a fixture built through it flipped a BLOCK to a FORWARD
//! roughly one run in sixteen depending on `SHARD_HASHER`'s per-process
//! seed. A golden that can lie on 1 run in 16 is worse than no golden.
//!
//! # Where the fixture shape comes from
//!
//! §4 S1 says to derive it from the live `the lab host` / `the lab host`
//! configs, and §1.1 records those verbatim: four blocklists, every one of
//! them `base = deny`, three tagged `uncategorized` and one untagged
//! (auto-promoted); `default` carrying `uncategorized` and `kids` carrying
//! `security` + `uncategorized`, where no list carries `security` at all.
//! That shape is reproduced here — including the two defects §1.1 names, so
//! that S1 is pinned to preserve them rather than to accidentally repair
//! them (E1: `kids` and `default` filter identically; E2: `kids`'s
//! `security` tag matches nothing and is silently dropped).
//!
//! **But those configs have no allow-direction list**, so a fixture derived
//! from them alone can never reach `allow_mask` — the exact blindness §4 S1
//! forbids. One synthetic `base = allow` list is therefore added on top
//! (tagged, because `ALLOW_LIST_REQUIRES_TAG`; consent-flagged, because it
//! is `trust = remote-unsigned`), together with the profile and the device
//! that subscribe to it. It is an addition to the measured shape, declared
//! here rather than blended into it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use purge_warden::config::loader::load_config;
use purge_warden::config::schema::ConfigV1;
use purge_warden::filter::engine::{FilterEngine, FilterResult};
use purge_warden::lists::catalog::Catalog;
use purge_warden::lists::manager::{merge_sources_with_blocklists, ListManager};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::lists::status::{LastOutcome, ListStatus};
use purge_warden::profiles::profile::ResolvedProfile;
use purge_warden::profiles::resolver::ProfileResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Committed golden. Regenerating it is **not** a way to make this test
/// pass — see the panic text in [`compare_with_golden`].
const GOLDEN: &str = include_str!("fixtures/plp_s1_verdicts.txt");

// ── the corpus ────────────────────────────────────────────────────────

/// One list body per configured source, keyed by the path the config
/// fetches it from.
///
/// Every name is under `.test` (RFC 6761 reserved). Neutrality: no
/// third-party provider appears, in either direction.
const BODIES: &[(&str, &str)] = &[
    ("/malicious.txt", "malicious-only.test\nboth-deny.test\n"),
    (
        "/ads.txt",
        "ads-only.test\nboth-deny.test\ncontested.test\ndeep-parent.test\n",
    ),
    ("/tracking.txt", "tracking-only.test\n"),
    ("/gambling.txt", "gambling-only.test\n"),
    // The synthetic allow-direction list. `contested.test` is carried by
    // BOTH this and the deny list above — that row is what proves
    // allow-beats-block still holds after the refactor. `deep-parent.test`
    // is deny-listed above and allow-listed here so the suffix walk's
    // OR-accumulation across two shards is exercised.
    (
        "/social.txt",
        "social-only.test\ncontested.test\ndeep-parent.test\n",
    ),
];

/// Every name probed, in a fixed order. Order is part of the golden.
const PROBES: &[&str] = &[
    "malicious-only.test",
    "ads-only.test",
    "tracking-only.test",
    "gambling-only.test",
    "both-deny.test",
    "social-only.test",
    "contested.test",
    // Suffix walk: neither name is in any list body, so the verdict can
    // only come from the parent — and for `deep-parent` from a parent that
    // two lists claim in opposite directions.
    "sub.tracking-only.test",
    "a.b.deep-parent.test",
    "unlisted.test",
];

/// Every client probed, in a fixed order: a label for the golden and the
/// source IP the resolver is asked about.
const CLIENTS: &[(&str, &str)] = &[
    ("dev-default", "192.0.2.10"),
    ("dev-kids", "192.0.2.11"),
    ("dev-marketing", "192.0.2.12"),
    // `default`'s tag set plus the allow list's tag. Until `plp-s3` this
    // was a device-level tag on the `default` profile, exercising the
    // per-device specialisation `specialise_with_effective_tags` performed;
    // it is now a profile of its own carrying the identical union, because
    // v3 has no per-device policy to migrate a device tag into. Same tags,
    // same bitmask, same rows.
    ("dev-default-plus-tag", "192.0.2.13"),
    // No device row: level-5 fallback to the default profile.
    ("anonymous", "198.51.100.7"),
];

// ── the in-process TLS origin ─────────────────────────────────────────

struct Origin {
    addr: SocketAddr,
    pem: String,
}

/// Serve each entry of [`BODIES`] at its path over real TLS.
///
/// No `ETag` / `Last-Modified`, so the manager never sends a conditional
/// GET and every refresh is a fresh 200 — the same choice
/// `e2e_config_to_verdict.rs` makes, for the same reason.
async fn serve() -> Origin {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_crypto));

    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let Ok(n) = tls.read(&mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = BODIES
                    .iter()
                    .find(|(path, _)| req.contains(path))
                    .map_or("", |(_, body)| *body);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Origin { addr, pem }
}

fn client_for(origin: &Origin) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("purge-warden/0.1")
        .timeout(Duration::from_secs(10))
        .resolve("lists.test", origin.addr)
        .add_root_certificate(reqwest::Certificate::from_pem(origin.pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

// ── the config ────────────────────────────────────────────────────────

/// The `the lab host` / `the lab host` shape of §1.1, plus the one
/// synthetic allow-direction list the measured shape cannot supply.
fn config_toml() -> String {
    "schema_version = 3\n\n\
     [server]\n\
     default_profile = \"default\"\n\n\
     # §1.1 verbatim: `uncategorized` only.\n\
     [profiles.default]\n\
     display_name = \"Default\"\n\
     tags = [\"uncategorized\"]\n\n\
     # §1.1 verbatim, defect E2 included: no list carries `security`, so this\n\
     # profile resolves identically to `default` (E1). S1 must PRESERVE that.\n\
     [profiles.kids]\n\
     display_name = \"Kids\"\n\
     tags = [\"security\", \"uncategorized\"]\n\n\
     # Synthetic: the only profile that reaches the allow-direction list.\n\
     [profiles.marketing]\n\
     display_name = \"Marketing\"\n\
     tags = [\"uncategorized\", \"social-exempt\"]\n\n\
     # Same tag set `dev-default-plus-tag` used to reach by carrying the\n\
     # allow list's tag on the DEVICE row: `default`'s tags plus\n\
     # `social-exempt`. Expressed as a profile so the union is a property of\n\
     # the profile, not of one device — see the note on the device below.\n\
     [profiles.default-plus-tag]\n\
     display_name = \"Default plus tag\"\n\
     tags = [\"uncategorized\", \"social-exempt\"]\n\n\
     [[blocklists]]\n\
     id = \"security-malicious\"\n\
     display_name = \"Malicious\"\n\
     url = \"https://lists.test/malicious.txt\"\n\
     format = \"domains\"\n\
     base = \"deny\"\n\
     tags = [\"uncategorized\"]\n\n\
     [[blocklists]]\n\
     id = \"privacy-ads\"\n\
     display_name = \"Ads\"\n\
     url = \"https://lists.test/ads.txt\"\n\
     format = \"domains\"\n\
     base = \"deny\"\n\
     tags = [\"uncategorized\"]\n\n\
     [[blocklists]]\n\
     id = \"privacy-tracking\"\n\
     display_name = \"Tracking\"\n\
     url = \"https://lists.test/tracking.txt\"\n\
     format = \"domains\"\n\
     base = \"deny\"\n\
     tags = [\"uncategorized\"]\n\n\
     # §1.1: untagged on the live hosts, auto-promoted to `uncategorized`.\n\
     [[blocklists]]\n\
     id = \"content-gambling\"\n\
     display_name = \"Gambling\"\n\
     url = \"https://lists.test/gambling.txt\"\n\
     format = \"domains\"\n\
     base = \"deny\"\n\n\
     # Synthetic. Tagged because `ALLOW_LIST_REQUIRES_TAG`; consent-flagged\n\
     # because `trust = remote-unsigned` (CLAUDE.md §Neutrality table row 4).\n\
     [[blocklists]]\n\
     id = \"social-exempt\"\n\
     display_name = \"Social exemption\"\n\
     url = \"https://lists.test/social.txt\"\n\
     format = \"domains\"\n\
     base = \"allow\"\n\
     trust = \"remote-unsigned\"\n\
     accept_unsigned_allow = true\n\
     tags = [\"social-exempt\"]\n\n\
     # Every device carries a MAC pin. `[server].enforce_device_mac` defaults\n\
     # to ON, and a device pinned by IP alone is dropped to the default profile\n\
     # under it (`resolver.rs`, the `<no-mac-pin>` branch) — which silently\n\
     # collapsed this whole grid onto one profile the first time it ran. The\n\
     # locally-administered `02:…` range names no vendor.\n\
     [[devices]]\n\
     id = \"dev-default\"\n\
     display_name = \"Default device\"\n\
     ip = \"192.0.2.10\"\n\
     mac = \"02:00:00:00:00:10\"\n\
     profile = \"default\"\n\n\
     [[devices]]\n\
     id = \"dev-kids\"\n\
     display_name = \"Kids device\"\n\
     ip = \"192.0.2.11\"\n\
     mac = \"02:00:00:00:00:11\"\n\
     profile = \"kids\"\n\n\
     [[devices]]\n\
     id = \"dev-marketing\"\n\
     display_name = \"Marketing device\"\n\
     ip = \"192.0.2.12\"\n\
     mac = \"02:00:00:00:00:12\"\n\
     profile = \"marketing\"\n\n\
     # Was a device-level tag (`profile = \"default\"` + `tags =\n\
     # [\"social-exempt\"]`), which reached the allow list through\n\
     # `specialise_with_effective_tags`'s per-DEVICE recomputation.\n\
     #\n\
     # Re-expressed as its own profile by `plp-s3`. Not a weakening: the\n\
     # effective tag set is byte-identical (`{uncategorized,\n\
     # social-exempt}`), so every row this client contributes to the golden\n\
     # is unchanged — proven by running this file against the pre-S3 engine\n\
     # with only this edit applied. What changes is the ROUTE: v3 carries\n\
     # policy per profile, and a device-level tag has no v3 form at all\n\
     # (`warden migrate v2-to-v3` refuses such a config outright, which is\n\
     # why the fixture could not simply be piped through the verb).\n\
     #\n\
     # Do NOT \"restore\" the device tag: it would make this fixture\n\
     # un-migratable and the golden unreplayable.\n\
     [[devices]]\n\
     id = \"dev-default-plus-tag\"\n\
     display_name = \"Default device on the plus-tag profile\"\n\
     ip = \"192.0.2.13\"\n\
     mac = \"02:00:00:00:00:13\"\n\
     profile = \"default-plus-tag\"\n\n\
     [upstream]\n\
     servers = [\"192.0.2.1:53\"]\n"
        .to_string()
}

// ── the chain ─────────────────────────────────────────────────────────

fn write_config(dir: &Path, toml: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(&p, toml).unwrap();
    p
}

/// Which configured sources did not arrive. A half-fetched corpus produces
/// verdicts that differ from the golden for a reason that has nothing to do
/// with list direction, so it must be reported as an environment fault, not
/// as a golden divergence. Same instrument, same reasoning, as
/// `e2e_config_to_verdict.rs::missing_sources`.
fn missing_sources(statuses: &[(String, Arc<ListStatus>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (id, st) in statuses {
        match &st.last_outcome {
            LastOutcome::Ok if st.unique_domains > 0 => {}
            LastOutcome::Ok => out.push(format!("`{id}` fetched OK but parsed 0 domains")),
            LastOutcome::Failed { reason } => out.push(format!("`{id}` FAILED to fetch: {reason}")),
            LastOutcome::NeverFetched => out.push(format!("`{id}` was never fetched")),
        }
    }
    out
}

async fn build_chain(
    config: &ConfigV1,
    config_path: &Path,
    origin: &Origin,
) -> (Arc<FilterEngine>, ProfileResolver) {
    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);
    let configured = merged_sources
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();

    let source_bits = SourceBitMap::build(&merged_sources, &config.blocklists).unwrap();
    // `plp-s3`: the operator's per-profile policy, projected onto the bit
    // assignment `source_bits` just made. Same production boundary the daemon
    // crosses in `cli/commands/start.rs`.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);
    let resolver_bits = SourceBitMap::build(&merged_sources, &config.blocklists).unwrap();

    let filter = Arc::new(FilterEngine::new());
    let cache_dir = config_path.parent().unwrap().join("lists-cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let mut mgr = ListManager::new(
        client_for(origin),
        filter.clone(),
        merged_sources,
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(cache_dir),
    );
    mgr.set_list_policy(policy_masks);
    let merged = mgr.refresh().await;

    let statuses = mgr.status_registry().snapshot();
    assert_eq!(
        statuses.len(),
        configured,
        "ENVIRONMENT, not the refactor: the status registry holds {} rows for \
         {configured} configured sources",
        statuses.len(),
    );
    let broken = missing_sources(&statuses);
    assert!(
        broken.is_empty(),
        "ENVIRONMENT, not the refactor: {} of {} sources did not arrive, so this \
         run says nothing about list direction (merged = {merged}).\n  {}",
        broken.len(),
        statuses.len(),
        broken.join("\n  "),
    );

    let resolver = ProfileResolver::build(
        config,
        &resolver_bits,
        &purge_warden::config::custom_list::CustomListStore::new(),
    );
    (filter, resolver)
}

// ── the verdict ───────────────────────────────────────────────────────

/// The third state `FilterResult` cannot express.
///
/// `AllowHit` is a `Forward` that an allow-direction Tier 1 list produced.
/// Reconstructed rather than reported because the engine's public surface
/// does not distinguish it — and that is exactly why it has to be
/// reconstructed here: a refactor that lost the allow side would leave a
/// two-valued table entirely unchanged.
/// # How `Allow-hit` is reconstructed after `plp-s3`, and why it is the same
/// # question
///
/// It used to be `filter.list_membership(domain).allow_mask &
/// profile.list_bitmask != 0` — the domain's allow-direction bits ANDed with
/// the profile's subscription. `plp-s3` removed `ResolvedProfile.list_bitmask`
/// (both halves of that pair now live beside the corpus, §2.4 D-ARCH-1), so
/// the AND has no second operand here.
///
/// The replacement asks the **same** question one layer down:
/// [`FilterEngine::list_membership_for`] returns the masks this profile
/// applies to this generation's bits, so a non-empty `allow_mask` means
/// exactly what the old expression meant — *an allow-direction list this
/// profile subscribes to matched*. It is not a weakening: the profile-side
/// operand moved, it did not disappear, and reading it from the engine is
/// strictly closer to what the hot path actually does.
///
/// **Not** `masks.allow_mask != 0` off the profile-less `list_membership`:
/// that would report a list the profile does not subscribe to, and every
/// `Forward` row for a non-subscribing client would turn into `Allow-hit`.
fn verdict(filter: &FilterEngine, profile: &ResolvedProfile, domain: &str) -> &'static str {
    match filter.evaluate(domain, profile) {
        FilterResult::Block => "Block",
        FilterResult::Forward => {
            if filter.list_membership_for(domain, &profile.name).allow_mask != 0 {
                "Allow-hit"
            } else {
                "Forward"
            }
        }
    }
}

/// Render the whole (client × domain) table in a fixed order.
fn table(filter: &FilterEngine, resolver: &ProfileResolver) -> String {
    let mut out = String::new();
    for (label, ip) in CLIENTS {
        let ip: IpAddr = ip.parse().unwrap();
        let profile = resolver
            .resolve(&ip)
            .profile
            .unwrap_or_else(|| panic!("{label} ({ip}) resolved to REFUSED — fixture fault"));
        for domain in PROBES {
            out.push_str(&format!(
                "{label:<22} {domain:<26} {}\n",
                verdict(filter, &profile, domain)
            ));
        }
    }
    out
}

/// The v2 fixture, put through `warden migrate v2-to-v3` in-process.
///
/// **This is the acceptance test of the cutover, and it has to be the verb.**
/// §5 asks for the binary post-migration to reproduce the S1 golden, which
/// comes from HEAD *before* S1 — code the new model has never touched. A
/// hand-written v3 twin would prove only that the author can write the answer
/// they expect; running the real migration makes the claim
/// *"the migration preserves every verdict"* instead.
///
/// The fixture stays in its **v2** shape above for the same reason: it is
/// what the migration has to be handed. The one edit `plp-s3` did make to it
/// — `dev-default-plus-tag` moving from a device tag to a profile — is
/// documented at that device, and was verified to leave the golden unchanged
/// on the pre-S3 engine before any of this landed.
fn migrated_config_path(dir: &Path) -> std::path::PathBuf {
    let v2 = write_config(dir, &config_toml());
    let v3 = dir.join("config.v3.toml");
    purge_warden::cli::commands::migrate::migrate_v2_to_v3(&v2, &v3, false)
        .expect("the fixture must migrate; a refusal here is a fixture fault");
    v3
}

async fn observed() -> String {
    let dir = tempfile::tempdir().unwrap();
    let cfg = migrated_config_path(dir.path());
    let config = load_config(&cfg, time::OffsetDateTime::now_utc())
        .map(|l| l.config)
        .unwrap_or_else(|e| panic!("migrated fixture config must load: {e:?}"));
    let origin = serve().await;
    let (filter, resolver) = build_chain(&config, &cfg, &origin).await;
    table(&filter, &resolver)
}

fn compare_with_golden(observed: &str) {
    if observed == GOLDEN {
        return;
    }
    let mut diff = String::new();
    let mut want = GOLDEN.lines();
    let mut got = observed.lines();
    loop {
        match (want.next(), got.next()) {
            (None, None) => break,
            (w, g) if w == g => {}
            (w, g) => {
                diff.push_str(&format!(
                    "  golden: {}\n  engine: {}\n",
                    w.unwrap_or("<missing>"),
                    g.unwrap_or("<missing>")
                ));
            }
        }
    }
    panic!(
        "VERDICT DIVERGENCE — {} row(s) differ from the golden.\n{diff}\n\
         This is a FAILURE, not a fixture update. `_docs/features/profile_list_policy.md`\n\
         §4 S1: \"Una divergenza è un fallimento, mai un aggiornamento della fixture.\"\n\
         The golden was recorded from the pre-S1 engine through the production install\n\
         path; S1 moves WHERE direction lives, never WHAT it decides. If a row here\n\
         genuinely should change, that is a behaviour change and belongs to S2 with the\n\
         schema that motivates it — not to a silent re-bless of this file.\n\n\
         Full observed table follows so it can be inspected, NOT pasted over the golden:\n\
         {observed}",
        diff.lines().count() / 2,
    );
}

// ── the tests ─────────────────────────────────────────────────────────

/// The golden itself.
#[tokio::test]
async fn engine_verdicts_match_the_pre_s1_golden() {
    compare_with_golden(&observed().await);
}

/// **The guard that stops the golden going blind.**
///
/// §4 S1: *"Il campione deve includere domini che oggi colpiscono
/// `allow_mask` e non solo `block_mask`, altrimenti il lato allow non viene
/// mai esercitato e il golden è cieco proprio dove il refactor è
/// rischioso."*
///
/// Asserted against the **committed** golden, not against a fresh run, so
/// it also fails if someone regenerates the table from a config that has
/// lost its allow-direction list — the failure mode where every other test
/// in this file stays green while measuring nothing.
#[test]
fn allow_side_is_exercised() {
    let allow_hits = GOLDEN.lines().filter(|l| l.ends_with("Allow-hit")).count();
    let blocks = GOLDEN.lines().filter(|l| l.ends_with("Block")).count();
    let forwards = GOLDEN.lines().filter(|l| l.ends_with("Forward")).count();
    assert!(
        allow_hits >= 3,
        "the golden holds {allow_hits} Allow-hit rows; a table that never reaches \
         `allow_mask` cannot detect the fail-open direction §1.4 names as the \
         dangerous one"
    );
    assert!(
        blocks >= 3,
        "the golden holds {blocks} Block rows; without them an engine that forwards \
         everything would satisfy the allow-side assertions"
    );
    assert!(
        forwards >= 1,
        "the golden holds {forwards} plain-Forward rows; without one, `Allow-hit` and \
         `Forward` are not actually distinguished by this table"
    );
}

/// The golden must cover every (client × domain) pair, so a row silently
/// dropped from `PROBES` / `CLIENTS` shrinks the table into a smaller test
/// instead of failing.
#[test]
fn golden_covers_the_whole_grid() {
    assert_eq!(
        GOLDEN.lines().count(),
        CLIENTS.len() * PROBES.len(),
        "the golden must hold exactly one row per (client × domain) pair"
    );
}
