//! End-to-end: a `config.toml` on disk → a query verdict.
//!
//! # The seam this closes
//!
//! Before this file, list direction was covered by two tests that never
//! met. `lists::manager`'s own tests prove a source bit lands in
//! `DomainMasks::allow_mask` rather than `block_mask`; `filter::engine`'s
//! prove `evaluate` honours an `allow_mask` it was handed directly. The
//! **join** — that a real config, loaded and validated, actually produces
//! the masks the engine then reads — was covered only by a manual smoke
//! on the CT. A manual smoke does not run in the gate, so nothing stops a
//! regression between the two halves.
//!
//! Everything here runs the production chain with production entry
//! points:
//!
//! ```text
//! config.toml
//!   → config::loader::load_config          (parse + validate)
//!   → merge_sources_with_blocklists        (config → fetch sources)
//!   → SourceBitMap::build / allow_bits     (which bit is which direction)
//!   → ListManager::new + set_allow_bits + refresh   (real HTTPS fetch)
//!   → FilterEngine (populated by the refresh)
//!   → ProfileResolver::build → default_profile      (tags → list_bitmask)
//!   → FilterEngine::evaluate               (the verdict)
//! ```
//!
//! # Why a real HTTPS server, and why that was not obvious
//!
//! The lists must be `trust = remote-unsigned`, so they have to travel the
//! HTTP path. That path is guarded: `lists::http_client::validate_list_url`
//! refuses any scheme but `https` **and** any literal private / loopback /
//! CGNAT IP, and it runs on the live download (`manager.rs`
//! `download_list`). A plain loopback mock is refused twice over — a
//! comment in `manager.rs` already says so ("the URL guard rejects a
//! loopback mock"), and the workaround it points at is the
//! `imported.local` bridge, which only serves `trust = local` lists and so
//! cannot express this scenario at all.
//!
//! **No production code is weakened to get around it.** The guard only
//! inspects *literal IP* hosts, so a hostname URL clears it honestly; the
//! test then pins that hostname to the in-process server with reqwest's
//! `resolve()` and trusts the throwaway cert with `add_root_certificate`
//! (not `danger_accept_invalid_certs` — certificate verification stays
//! on). `ListManager::new` has always taken the `reqwest::Client` from its
//! caller, which is the seam being used. `guard_still_refuses_a_loopback_
//! literal` pins that the guard is intact, so this file cannot become the
//! reason someone later relaxes it.
//!
//! # Measured capable of failing
//!
//! A green e2e test proves nothing until it has been watched going red,
//! and the failure mode that matters here is *silent direction collapse*
//! — every list routed one way — which a carelessly built test passes
//! either way. Both collapses were injected at `mgr.set_allow_bits` and
//! the results recorded:
//!
//! | Injected | Meaning | Caught by |
//! |---|---|---|
//! | `set_allow_bits(0)` | every list block-direction (the neutrality-06 regression) | `a_domain_in_an_allow_list_forwards…`, `swapping_both_kinds_is_a_no_op…` |
//! | `set_allow_bits(!0)` | every list allow-direction | `the_same_domain_blocks_once_no_allow_list_carries_it`, plus the deny-only control in two others |
//!
//! The second row is why this file needs a scenario whose correct answer
//! is `Block`: every "the allow-list wins" assertion is satisfied by an
//! implementation that has stopped reading `kind` altogether and just
//! forwards.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use purge_warden::config::loader::load_config;
use purge_warden::config::schema::ConfigV1;
use purge_warden::filter::engine::FilterEngine;
use purge_warden::lists::catalog::Catalog;
use purge_warden::lists::manager::{merge_sources_with_blocklists, ListManager};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::lists::status::{LastOutcome, ListStatus};
use purge_warden::profiles::resolver::ProfileResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The domain both lists carry. The whole file turns on what happens to
/// this one name.
const CONTESTED: &str = "contested.example";
/// Carried only by the deny list — the control that proves the deny list
/// is genuinely loaded and filtering in every scenario below.
const DENY_ONLY: &str = "denied-only.example";

// ── the in-process HTTPS origin ───────────────────────────────────────

/// A running test origin: the address to pin, and the PEM to trust.
struct Origin {
    addr: SocketAddr,
    pem: String,
}

/// Serve `/deny.txt` and `/allow.txt` over real TLS, one fixed body each.
async fn serve(deny_body: &'static str, allow_body: &'static str) -> Origin {
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
                // No ETag / Last-Modified is emitted, so the manager never
                // sends a conditional GET and every refresh is a fresh 200.
                // That is what lets a test rewrite a config and re-fetch
                // without fighting the cache.
                let body = if req.contains("/allow.txt") {
                    allow_body
                } else {
                    deny_body
                };
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

/// A client that reaches the test origin over TLS while leaving every
/// production guard in place. Mirrors `build_list_client`'s timeout; the
/// hardened redirect policy is irrelevant here (the origin never
/// redirects).
fn client_for(origin: &Origin) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("purge-warden/0.1")
        .timeout(Duration::from_secs(10))
        .resolve("lists.test", origin.addr)
        .add_root_certificate(reqwest::Certificate::from_pem(origin.pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

// ── the config under test ─────────────────────────────────────────────

/// Both lists remote-unsigned, both tagged `work`, and the profile
/// carries `work` so they apply. `deny_kind` / `allow_kind` are
/// parameters so property 2 can swap them without touching anything else.
fn config_toml(deny_kind: &str, allow_kind: &str, consent: bool, allow_tags: &str) -> String {
    let block_all = "";
    config_toml_full(deny_kind, allow_kind, consent, allow_tags, block_all)
}

fn config_toml_full(
    deny_kind: &str,
    allow_kind: &str,
    consent: bool,
    allow_tags: &str,
    profile_extra: &str,
) -> String {
    format!(
        "schema_version = 3\n\n\
         [server]\n\
         default_profile = \"default\"\n\n\
         [profiles.default]\n\
         display_name = \"Default\"\n\
         tags = [\"work\"]\n\
         {profile_extra}\n\
         [[blocklists]]\n\
         id = \"svc-a\"\n\
         display_name = \"Service A (deny)\"\n\
         url = \"https://lists.test/deny.txt\"\n\
         format = \"domains\"\n\
         base = \"{deny_kind}\"\n\
         trust = \"remote-unsigned\"\n\
         accept_unsigned_allow = {consent}\n\
         tags = [\"work\"]\n\n\
         [[blocklists]]\n\
         id = \"svc-b\"\n\
         display_name = \"Service B (allow)\"\n\
         url = \"https://lists.test/allow.txt\"\n\
         format = \"domains\"\n\
         base = \"{allow_kind}\"\n\
         trust = \"remote-unsigned\"\n\
         accept_unsigned_allow = {consent}\n\
         tags = {allow_tags}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
    )
}

fn write_config(dir: &Path, toml: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(&p, toml).unwrap();
    p
}

// ── the chain ─────────────────────────────────────────────────────────

/// Load, fetch and resolve exactly as `cli::commands::start` does, and
/// return the pieces a verdict needs.
///
/// Deliberately **not** `expect`-ing the load: property 3 needs the
/// loader's error, so the split is `load` here and `build_chain` below.
fn load(
    config_path: &Path,
) -> Result<purge_warden::config::loader::LoadedConfig, Vec<purge_warden::config::error::ConfigError>>
{
    load_config(config_path, time::OffsetDateTime::now_utc())
}

/// Which configured sources did **not** arrive, described one per entry.
/// Empty means the corpus is whole.
///
/// **The old guard was `merged > 0`, and that question has the wrong shape.**
/// This fixture fetches two lists — `deny.txt` and `allow.txt` — from a real
/// local TLS origin through the production path, under the 10 s client timeout
/// in [`client_for`]. On a loaded box one fetch can time out while the other
/// lands, and a **half**-fetched corpus satisfies `merged > 0` happily. The run
/// then continues into the four allow-direction properties, which fail with
/// messages blaming list **direction** for a fetch that never arrived.
///
/// That is worse than a flake: it is a diagnostic that lies. A reader following
/// those messages goes to the filter engine — which is correct — while the real
/// fault, a timed-out HTTP GET, appears nowhere in the output. Observed
/// 2026-08-16 in the united-tree gate: 4 of 7 red, the binary reporting
/// `finished in 27.35s` against 0.08-0.22 s warm, consistent with 10 s timeouts
/// firing.
///
/// So ask whether **everything** arrived. [`ListStatus::last_outcome`] is the
/// direct instrument, and `unique_domains` is this source's own body count —
/// deliberately not `entries`, which counts only a source's *net-new*
/// contribution and is legitimately `0` for a list whose domains an earlier
/// source already supplied. Asserting on `entries` would red on a duplicate
/// corpus that is perfectly well fetched.
///
/// Factored out of the assertion so both arms are directly assertable without
/// a network: see `guard_*` tests at the bottom of this file.
fn missing_sources(statuses: &[(String, Arc<ListStatus>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (id, st) in statuses {
        match &st.last_outcome {
            LastOutcome::Ok if st.unique_domains > 0 => {}
            LastOutcome::Ok => out.push(format!(
                "`{id}` fetched OK but parsed 0 domains from its body"
            )),
            LastOutcome::Failed { reason } => out.push(format!("`{id}` FAILED to fetch: {reason}")),
            LastOutcome::NeverFetched => out.push(format!("`{id}` was never fetched")),
        }
    }
    out
}

/// Panic unless every configured source arrived, naming the ones that did not.
/// See [`missing_sources`] for why `merged > 0` was not enough.
///
/// `expected` is how many **distinct** source URLs the config declared.
///
/// `ListStatusRegistry::new` (`status.rs:683`, called from `manager.rs:527`)
/// seeds one row per source *eagerly*, before any fetch, each defaulting to
/// `NeverFetched` — so a source that never gets attempted still has a row and
/// is caught by the `NeverFetched` arm of [`missing_sources`] rather than
/// vanishing. What the length check adds is narrower and worth stating
/// honestly: it pins that the manager was handed the same source set the
/// config declared, so the per-row scan below is scanning everything. Deduped
/// with a set because the registry is a `HashMap` keyed by URL and would
/// collapse a repeated one.
fn assert_every_source_arrived(mgr: &ListManager, merged: usize, expected: usize) {
    let statuses = mgr.status_registry().snapshot();
    assert_eq!(
        statuses.len(),
        expected,
        "ENVIRONMENT, not list direction: the status registry holds {} rows for \
         {expected} distinct configured sources, so the per-source scan below \
         would not be looking at all of them. Fixture or wiring fault.",
        statuses.len(),
    );

    let broken = missing_sources(&statuses);
    assert!(
        broken.is_empty(),
        "ENVIRONMENT, not list direction: {} of {} configured sources did not \
         arrive, so this run cannot say anything about allow/deny routing.\n  \
         {}\n\
         Most likely the 10 s client timeout in `client_for` fired under load; \
         a timed-out GET is not evidence about the filter engine. `merged` was \
         {merged}, which is exactly why the old `merged > 0` guard let a \
         half-fetched corpus through into the direction assertions.",
        broken.len(),
        statuses.len(),
        broken.join("\n  "),
    );
}

async fn build_chain(
    config: &ConfigV1,
    custom_lists: &purge_warden::config::custom_list::CustomListStore,
    config_path: &Path,
    origin: &Origin,
) -> (
    Arc<FilterEngine>,
    Arc<purge_warden::profiles::profile::ResolvedProfile>,
) {
    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);

    // Captured before `merged_sources` is moved into the manager — this is
    // what "every source" means for the corpus guard below. Deduped to match
    // the registry's own URL-keyed map.
    let configured_sources = merged_sources
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();

    let source_bits = SourceBitMap::build(&merged_sources, &config.blocklists).unwrap();
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);
    // A second, identical map: `ListManager::new` consumes one and
    // `ProfileResolver::build` borrows one. Same inputs, same bit
    // assignment — this is the pairing production makes too.
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
    // The line whose absence sends every list into `block_mask`
    // regardless of `kind` (neutrality-06). Production calls it at boot
    // and at reload; so does this.
    mgr.set_list_policy(policy_masks);
    let merged = mgr.refresh().await;
    assert_every_source_arrived(&mgr, merged, configured_sources);

    let resolver = ProfileResolver::build(config, &resolver_bits, custom_lists);
    let profile = resolver
        .default_profile()
        .expect("the config declares a default profile");
    (filter, profile)
}

fn verdict(
    filter: &FilterEngine,
    profile: &purge_warden::profiles::profile::ResolvedProfile,
    d: &str,
) -> String {
    format!("{:?}", filter.evaluate(d, profile))
}

// ── the five properties ───────────────────────────────────────────────

/// Run the whole chain on one config and report both verdicts.
async fn verdicts(toml: &str, origin: &Origin) -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), toml);
    let loaded = load(&cfg).expect("config must load");
    let (filter, profile) = build_chain(&loaded.config, &loaded.custom_lists, &cfg, origin).await;
    (
        verdict(&filter, &profile, CONTESTED),
        verdict(&filter, &profile, DENY_ONLY),
    )
}

fn corpus() -> (&'static str, &'static str) {
    // deny.txt carries both names; allow.txt carries only the contested
    // one. So DENY_ONLY is the probe that reports which direction
    // *deny.txt* was routed in, independently of the contested domain.
    (
        "contested.example\ndenied-only.example\n",
        "contested.example\n",
    )
}

/// **1.** The contested domain forwards: among lists, allow beats deny.
#[tokio::test]
async fn a_domain_in_an_allow_list_forwards_even_though_a_deny_list_carries_it() {
    let (deny, allow) = corpus();
    let origin = serve(deny, allow).await;
    let (contested, deny_only) =
        verdicts(&config_toml("deny", "allow", true, "[\"work\"]"), &origin).await;
    assert_eq!(
        contested, "Forward",
        "a domain in both lists must follow the allow direction"
    );
    assert_eq!(
        deny_only, "Block",
        "the deny list must still be filtering — otherwise the Forward above \
         proves nothing about direction"
    );
}

/// **2.** Turn the allow-list into a deny-list and the same domain blocks.
///
/// This is the half that makes the file capable of failing: an
/// implementation that routed *everything* into the allow direction
/// satisfies property 1 identically, and only a scenario whose correct
/// answer is `Block` can catch it.
///
/// **The literal reading of "swap the two kinds" does not do this** — see
/// `swapping_both_kinds_is_a_no_op_for_a_domain_in_both_lists` below,
/// which pins why. The domain under test is in *both* files, so exchanging
/// the two labels leaves it exactly where it was: in one allow-direction
/// list and one deny-direction list. What has to change is the number of
/// allow-direction lists carrying it, not which file wears which label.
#[tokio::test]
async fn the_same_domain_blocks_once_no_allow_list_carries_it() {
    let (deny, allow) = corpus();
    let origin = serve(deny, allow).await;
    let (contested, deny_only) =
        verdicts(&config_toml("deny", "deny", true, "[\"work\"]"), &origin).await;
    assert_eq!(
        contested, "Block",
        "with no allow-direction list carrying it, the same domain must block \
         — if this is Forward, direction is being ignored and property 1 was \
         vacuous"
    );
    assert_eq!(deny_only, "Block", "and the deny-only control blocks too");
}

/// The literal "invert the two `kind`s" construction, pinned as the
/// **no-op it is**, so nobody rewrites property 2 back into it.
///
/// `contested.example` sits in both files. Exchanging the labels moves it
/// from (allow.txt=allow, deny.txt=deny) to (deny.txt=allow,
/// allow.txt=deny) — still exactly one allow-direction list carrying it,
/// so still `Forward`. Nothing about the domain's situation changed.
///
/// The verdict that *does* move is `DENY_ONLY`: it rides deny.txt alone,
/// so it follows that file's label from `Block` to `Forward`. That flip is
/// the positive evidence that direction is genuinely being read from the
/// config — the contested domain staying `Forward` is correct, not inert.
#[tokio::test]
async fn swapping_both_kinds_is_a_no_op_for_a_domain_in_both_lists() {
    let (deny, allow) = corpus();
    let origin = serve(deny, allow).await;
    let (contested, deny_only) =
        verdicts(&config_toml("allow", "deny", true, "[\"work\"]"), &origin).await;
    assert_eq!(
        contested, "Forward",
        "a domain in both lists has an allow-direction list either way"
    );
    assert_eq!(
        deny_only, "Forward",
        "DENY_ONLY rides deny.txt alone, so it follows that file's new label \
         — this flip is what proves direction is read from the config"
    );
}

/// **3.** Drop the consent and the config stops loading, with the frozen
/// string. The gate is the loader's, not the CLI's — this is the property
/// that makes `accept_unsigned_allow` more than a CLI-side courtesy.
#[test]
fn without_consent_the_config_does_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        &config_toml("deny", "allow", false, "[\"work\"]"),
    );
    let errs = load(&cfg).expect_err("a remote unsigned allow-list without consent must not load");
    let joined = errs
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let expected = purge_warden::config::schema::validator::format_unsigned_allow_list_requires_ack(
        "svc-b",
        purge_warden::config::schema::blocklist::BlocklistTrust::RemoteUnsigned,
    );
    assert!(
        joined.contains(&expected),
        "must carry the frozen string verbatim, got:\n{joined}"
    );
}

/// **4.** Consent given, allow-list untagged: the config loads and the
/// contested domain is now **permitted** — with a WARN that says so.
///
/// # This assertion was inverted by `plp-s3`, deliberately
///
/// It used to read "…and permits nothing": an untagged allow-list
/// intersected no profile's tags, so its bit never entered `list_bitmask`
/// and the deny list was unopposed. `_docs/features/profile_list_policy.md`
/// §2.2 retires that property by name — *"Allow-list senza tag = inerte →
/// ritirato, perde la premessa"* — because direction is now inherited by
/// every profile from the list's own `kind`. An untagged allow-list is not
/// inert any more; it is maximally live.
///
/// **So the safety net moved rather than disappearing**, and the WARN is
/// what this test is really guarding. §2.5: the old refusal does not
/// transfer (refusing a word the operator typed is the defect that killed
/// `base = allow ⇒ trust = local`), but the *visibility* it bought does —
/// as a standing-exposure WARN re-stated at every load, for every trust.
///
/// **The WARN is asserted, not assumed.** Loading-and-permitting is
/// satisfied identically by a build that never emits the warning at all, so
/// "loads with the WARN" needs the warning itself in evidence.
/// `load_config_collect` returns the validator's audit WARNs in-band, which
/// is how this is reachable without widening anything.
#[tokio::test]
async fn an_untagged_allow_list_loads_with_a_warn_and_now_permits() {
    let origin = serve(
        "contested.example\ndenied-only.example\n",
        "contested.example\n",
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &config_toml("deny", "allow", true, "[]"));

    let (result, warns) =
        purge_warden::config::loader::load_config_collect(&cfg, time::OffsetDateTime::now_utc());
    let loaded = result.expect("an untagged allow-list is a WARN, not an error");
    let joined = warns.join("\n");
    assert!(
        joined.contains(
            &purge_warden::config::schema::validator::format_allow_direction_list_standing_exposure(
                "svc-b"
            )
        ),
        "the load must name the standing exposure an allow-direction list \
         creates, got:\n{joined}"
    );
    // Spelled as a literal, not via `format_allow_list_no_tags_no_effect`:
    // `plp-s5f` deleted that const, so the guard has to outlive the symbol it
    // used to name. Deleting the const is the stronger guarantee (a compile
    // error beats a runtime check), and this keeps the *behavioural* half —
    // if anyone reintroduces both the string and an emit path, the load below
    // starts contradicting itself again and this catches it.
    assert!(
        !joined.contains("has no tags — has no effect"),
        "the retired `has no effect` WARN must NOT fire: it would describe the \
         opposite of what this very test observes one assertion below, and a \
         diagnostic that lies is worse than a missing one. Got:\n{joined}"
    );
    // The standing-exposure WARN fires on every load too — the consent is
    // recorded once and keeps applying, so it is meant to stay visible.
    assert!(
        joined.contains(
            &purge_warden::config::schema::validator::format_unsigned_allow_list_accepted("svc-b")
        ),
        "an accepted unsigned allow-list must warn at every load, got:\n{joined}"
    );

    let (filter, profile) = build_chain(&loaded.config, &loaded.custom_lists, &cfg, &origin).await;
    assert_eq!(
        verdict(&filter, &profile, CONTESTED),
        "Forward",
        "post-`plp-s3` an allow-direction list applies to every profile that \
         does not override it — tags no longer gate it, so allow beats block"
    );
}

/// **5.** W1.2: `block_all` is a posture, and a list downloaded from the
/// internet does not pierce it. Only an admin rule in the operator's own
/// config can.
#[tokio::test]
async fn block_all_is_not_pierced_by_an_allow_direction_list() {
    let origin = serve(
        "contested.example\ndenied-only.example\n",
        "contested.example\n",
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        &config_toml_full("deny", "allow", true, "[\"work\"]", "block_all = true\n"),
    );
    let loaded = load(&cfg).expect("config must load");
    let (filter, profile) = build_chain(&loaded.config, &loaded.custom_lists, &cfg, &origin).await;
    assert!(profile.block_all, "the fixture must actually set block_all");
    assert_eq!(
        verdict(&filter, &profile, CONTESTED),
        "Block",
        "an allow-direction list must not pierce block_all (W1.2)"
    );
    // And the posture is what is blocking, not the list: a domain no list
    // mentions blocks too.
    assert_eq!(
        verdict(&filter, &profile, "unmentioned.example"),
        "Block",
        "block_all blocks everything it is not told to allow"
    );
}

// ── the corpus-completeness guard, asserted on both arms ──────────────
//
// `missing_sources` decides whether the run may proceed to the direction
// properties at all. Its arms are asserted here without a network, so the
// guard itself is not another thing that only works on a quiet box.

/// Synthetic status. `ListStatus` derives `Default`, so each test states only
/// the two fields the guard actually reads.
fn status(last_outcome: LastOutcome, unique_domains: u64) -> Arc<ListStatus> {
    Arc::new(ListStatus {
        last_outcome,
        unique_domains,
        ..Default::default()
    })
}

/// Arm 1: a whole corpus is accepted. Without this the guard could satisfy
/// every other test here by refusing everything.
#[test]
fn guard_accepts_a_corpus_where_every_source_arrived() {
    let statuses = vec![
        ("deny".to_string(), status(LastOutcome::Ok, 2)),
        ("allow".to_string(), status(LastOutcome::Ok, 1)),
    ];
    assert!(
        missing_sources(&statuses).is_empty(),
        "a fully fetched corpus must proceed to the direction assertions"
    );
}

/// Arm 2 — **the defect**. One source lands, one times out. `merged > 0` is
/// true, so the old guard waved this through and the direction properties
/// then failed while blaming direction.
#[test]
fn guard_names_the_source_whose_fetch_never_arrived() {
    let statuses = vec![
        ("deny".to_string(), status(LastOutcome::Ok, 2)),
        (
            "allow".to_string(),
            status(
                LastOutcome::Failed {
                    reason: "operation timed out".to_string(),
                },
                0,
            ),
        ),
    ];
    let missing = missing_sources(&statuses);
    assert_eq!(missing.len(), 1, "exactly one source is missing");
    assert!(
        missing[0].contains("allow") && missing[0].contains("operation timed out"),
        "the message must name the source AND carry the fetch reason, so the \
         reader goes to the network and not to the filter engine; got {:?}",
        missing[0]
    );
}

/// A source that answered but yielded nothing is equally unusable — a 200 with
/// an empty body would otherwise read as a successfully applied list.
#[test]
fn guard_catches_a_source_that_fetched_but_parsed_nothing() {
    let statuses = vec![("deny".to_string(), status(LastOutcome::Ok, 0))];
    assert_eq!(missing_sources(&statuses).len(), 1);
}

/// `NeverFetched` is the boot state — a source the refresh never reached at
/// all, which is not the same failure as one that tried and failed, and must
/// not be silently tolerated either.
#[test]
fn guard_catches_a_source_the_refresh_never_reached() {
    let statuses = vec![("deny".to_string(), status(LastOutcome::NeverFetched, 0))];
    assert_eq!(missing_sources(&statuses).len(), 1);
}

/// **Why the guard reads `unique_domains` and not `entries`.**
///
/// `entries` counts a source's *net-new* contribution, so a list whose domains
/// an earlier source already supplied reports `0` while being perfectly well
/// fetched. A guard written against `entries` would red on a duplicate corpus
/// — a false alarm of exactly the kind that gets a guard deleted. This test
/// fails if someone swaps the field.
#[test]
fn guard_accepts_a_fetched_source_whose_domains_were_all_contributed_by_another() {
    let statuses = vec![(
        "allow".to_string(),
        Arc::new(ListStatus {
            last_outcome: LastOutcome::Ok,
            unique_domains: 500,
            entries: 0, // every domain was charged to an earlier source
            ..Default::default()
        }),
    )];
    assert!(
        missing_sources(&statuses).is_empty(),
        "a fully fetched list must not be reported missing merely because \
         another source contributed the same domains first"
    );
}

/// End-to-end: shown to fail on a deliberately unreachable origin, rather than
/// merely to pass today.
///
/// Points the client at a closed port while leaving the URL, the URL guard and
/// the certificate honest — only the destination is dead, so this exercises the
/// real fetch path's failure and the real `ListStatus` it writes. Connection
/// refused is immediate, so this costs no timeout.
#[tokio::test]
#[should_panic(expected = "ENVIRONMENT, not list direction")]
async fn guard_fires_on_an_unreachable_origin() {
    // Borrow a valid cert from a real origin, then aim somewhere dead: the
    // failure under test is transport, not TLS.
    let live = serve(
        "contested.example\ndenied-only.example\n",
        "contested.example\n",
    )
    .await;
    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    }; // dropped — nothing is listening there now
    let dead = Origin {
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        pem: live.pem.clone(),
    };

    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        &config_toml("deny", "allow", true, "[\"work\"]"),
    );
    let loaded = load(&cfg).expect("config must load");
    // Must panic in the corpus guard, NOT reach a direction assertion.
    let _ = build_chain(&loaded.config, &loaded.custom_lists, &cfg, &dead).await;
}

/// The guard this file routes around is still doing its job. Pinned here,
/// next to the routing, so nobody later "fixes" a fetch failure by
/// loosening `validate_list_url` and finds the suite still green.
#[test]
fn guard_still_refuses_a_loopback_literal_and_plain_http() {
    use purge_warden::lists::http_client::validate_list_url;
    assert!(validate_list_url("https://127.0.0.1:8443/ads.txt").is_err());
    assert!(validate_list_url("https://192.168.1.10/ads.txt").is_err());
    assert!(validate_list_url("http://lists.test/ads.txt").is_err());
    assert!(validate_list_url("https://lists.test/ads.txt").is_ok());
}
