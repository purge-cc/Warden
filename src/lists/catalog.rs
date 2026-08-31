//! Purge.cc list catalog — resolves list IDs to download URLs.
//!
//! Single endpoint: `https://lists.purge.cc/index.json`, plain-domain lists
//! (one domain per line). The `rules.purge.cc` AdGuard-rules catalog was
//! retired — the server stopped generating it and the endpoint is gone.
//! Warden still supports the AdGuard rule syntax (`||domain^`) for any
//! third-party list an operator subscribes to
//! ([`BlocklistFormat::Adguard`] stays in the enum) — only the purge.cc
//! catalog of pre-built rule packs is gone.
//!
//! The `index.json` envelope carries an optional top-level `"format"`
//! discriminator (e.g. `"adguard_rules"`, `"hosts"`); when present, every
//! entry in that response is stamped with the matching `BlocklistFormat`
//! instead of the per-entry default. Absent → entries deserialise as
//! [`BlocklistFormat::Domains`] (the enum's `#[default]`), which is what
//! `lists.purge.cc` sends today.
//!
//! [`Catalog::fetch_unified`] and [`Catalog::fallback`] both resolve to
//! this one channel now; see `fetch_unified`'s doc comment for why it
//! still exists as a function distinct from `fetch`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::schema::BlocklistFormat;

const DEFAULT_CATALOG_URL: &str = "https://lists.purge.cc/index.json";

/// Per-channel timeout for [`Catalog::fetch_unified`]. Picked tight on
/// purpose: the catalog picker pauses opening until the fetch lands, so a
/// stuck purge.cc would otherwise freeze the TUI for the full reqwest
/// default timeout. 2s gives a healthy CDN ample headroom while keeping
/// the worst-case picker open at ~2s + render.
///
/// §4.34 (post-§4.28 b8): now ALSO applied per-call inside
/// [`Catalog::fetch_from`] so the daemon-boot path (`Catalog::fetch`,
/// which does NOT route through `fetch_unified`) is similarly bounded.
/// A DNS-poisoned upstream that slow-streams cannot stall boot
/// beyond `FETCH_TIMEOUT_SECS`.
const FETCH_TIMEOUT_SECS: u64 = 2;

/// §4.34: hard cap on the index.json body. The legitimate envelope
/// today is a few KiB (~5 KB); picking 1 MiB gives roughly a 200×
/// headroom while keeping a hostile / DNS-poisoned `lists.purge.cc`
/// from streaming gigabytes into RAM at boot. The catalog is the
/// boot-time entry point — making this operator-tunable before the
/// daemon can read its own config would be a chicken-and-egg surface,
/// so the cap is pinned at compile time.
const CATALOG_BODY_MAX_BYTES: usize = 1024 * 1024;

/// Top-level wrapper for the `index.json` response envelope.
#[derive(Debug, Clone, Deserialize)]
struct CatalogIndex {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    generated_at: String,
    /// Optional discriminator that names a wire format applying to every
    /// entry in this response (e.g. `"adguard_rules"`, `"hosts"`). Absent
    /// today — `lists.purge.cc` doesn't set it — so entries default to
    /// [`BlocklistFormat::Domains`].
    #[serde(default)]
    format: Option<String>,
    lists: Vec<CatalogEntry>,
}

/// A single entry in the purge.cc list catalog.
///
/// Maps a list ID (e.g. `"privacy/ads"`) to its metadata and download URL.
/// The `scope` groups lists by purpose (privacy, security, content, services).
/// The ID is constructed as `"scope/topic"` from the catalog fields.
///
/// `Serialize` exists for [`Catalog::save_to_disk`] only. The persisted
/// file is **our own serialization of `Vec<CatalogEntry>`, not a copy of
/// the wire `index.json`** — the wire shape is the [`CatalogIndex`]
/// envelope (`version` / `generated_at` / `format` / `lists`), which we
/// deliberately do not reproduce. The two shapes must stay mutually
/// consistent; `catalog_round_trips_through_disk` is what holds them
/// together. Drift is safe by construction — [`Catalog::load_from_disk`]
/// returns `None` on a parse error, so boot degrades to fetching — but a
/// future reader must not assume this file can be fed to a wire parser
/// or vice versa.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogEntry {
    /// Top-level grouping: `"privacy"`, `"security"`, `"content"`, `"services"`.
    pub scope: String,
    /// Specific topic within scope (e.g. `"ads"`, `"malicious"`).
    #[serde(default)]
    pub topic: Option<String>,
    /// Human-readable name (e.g. `"Ads"`).
    #[serde(default)]
    pub name: String,
    /// Full download URL for the list file.
    pub url: String,
    /// Number of domains in the list (from catalog metadata, may be 0).
    #[serde(default)]
    pub entries: u64,
    /// ISO 8601 timestamp of last list generation. Deserialized from catalog
    /// JSON and rendered in the TUI catalog picker's UPDATED column.
    ///
    /// **Empty for [`Catalog::fallback`]** — the hardcoded offline snapshot
    /// carries no timestamps. Every consumer must render the empty string as
    /// "unknown", never as a date: an operator with no egress would otherwise
    /// read a blank cell as a fact about the list.
    #[serde(default)]
    pub updated_at: String,
    /// Declared wire format for this list. `Adguard`/`Hosts` **force** the
    /// daemon's parser when downloading this URL (rev-2606 §06 parser-02);
    /// `Domains` — the default when absent (plain-domain lists.purge.cc) —
    /// defers to content auto-detection, which falls back to domain-per-line.
    /// An index.json with a top-level `"format"` discriminator (see the
    /// module docs) stamps every entry with the matching `BlocklistFormat`
    /// post-deserialise. The field is `#[serde(default)]` so existing JSON
    /// without `format` round-trips unchanged.
    #[serde(default)]
    pub format: BlocklistFormat,
}

impl CatalogEntry {
    /// Constructed list ID: `"scope/topic"` (e.g. `"privacy/ads"`).
    pub fn id(&self) -> String {
        match &self.topic {
            Some(t) => format!("{}/{}", self.scope, t),
            None => self.scope.clone(),
        }
    }

    /// Whether `candidate` equals this entry's [`id`](Self::id), without
    /// allocating the `scope/topic` string. Equivalent to
    /// `self.id() == candidate` — used in `resolve()`'s per-entry scan so a
    /// lookup does not `format!` a throwaway `String` for every entry.
    /// `scope` never contains `/`, so splitting on the first `/` recovers
    /// the same boundary `id()` builds.
    fn id_matches(&self, candidate: &str) -> bool {
        match &self.topic {
            Some(topic) => match candidate.split_once('/') {
                Some((scope, rest)) => scope == self.scope && rest == topic.as_str(),
                None => false,
            },
            None => candidate == self.scope,
        }
    }
}

/// Fetched catalog of available purge.cc lists.
#[derive(Debug, Clone)]
pub struct Catalog {
    entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// Fetch the catalog from the remote index.json.
    pub async fn fetch(client: &reqwest::Client) -> Result<Self, CatalogError> {
        Self::fetch_from(client, DEFAULT_CATALOG_URL).await
    }

    /// Fetch from a specific URL (for testing or custom catalogs).
    ///
    /// §4.34: the body is streamed through the bounded
    /// [`crate::lists::manager::read_bounded_body_bytes`] reader with
    /// [`CATALOG_BODY_MAX_BYTES`] as the cap, then parsed via
    /// `serde_json::from_slice` on the bounded buffer. The whole
    /// read+parse is wrapped in `tokio::time::timeout(FETCH_TIMEOUT_SECS, ...)`
    /// so a slow-streaming hostile upstream cannot stall the daemon at
    /// boot for the reqwest default timeout.
    pub async fn fetch_from(client: &reqwest::Client, url: &str) -> Result<Self, CatalogError> {
        tracing::info!(url, "fetching list catalog");
        let resp =
            client.get(url).send().await.map_err(|e| {
                CatalogError::Fetch(crate::lists::manager::classify_fetch_error(&e))
            })?;

        if !resp.status().is_success() {
            return Err(CatalogError::Fetch(format!("HTTP {}", resp.status())));
        }

        let bytes = match tokio::time::timeout(
            std::time::Duration::from_secs(FETCH_TIMEOUT_SECS),
            crate::lists::manager::read_bounded_body_bytes(resp, url, CATALOG_BODY_MAX_BYTES),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(CatalogError::Fetch(e.to_string())),
            Err(_) => {
                return Err(CatalogError::Fetch(format!(
                    "catalog body stream timed out after {FETCH_TIMEOUT_SECS}s"
                )));
            }
        };
        let index: CatalogIndex =
            serde_json::from_slice(&bytes).map_err(|e| CatalogError::Parse(e.to_string()))?;
        // Honour the top-level `"format"` discriminator when the envelope
        // sets one. Per-entry override stays possible (the JSON could
        // carry `format` on the list level too) but production today
        // never sets a top-level signal.
        let channel_format = match index.format.as_deref() {
            Some("adguard_rules") => Some(BlocklistFormat::Adguard),
            Some("hosts") => Some(BlocklistFormat::Hosts),
            // None or "domains" → no override; per-entry default applies
            _ => None,
        };
        let entries: Vec<CatalogEntry> = index
            .lists
            .into_iter()
            .map(|mut e| {
                if let Some(ch) = channel_format {
                    e.format = ch;
                }
                e
            })
            .collect();

        tracing::info!(count = entries.len(), "catalog loaded");
        Ok(Self { entries })
    }

    /// Fetch the catalog, falling back to the hardcoded entries on failure
    /// or timeout so the operator never sees an empty picker. Wrapped in
    /// its own 2s timeout so a slow CDN cannot freeze the TUI catalog
    /// picker — this bounds the whole call including the initial
    /// connect/headers phase, which `fetch_from`'s internal timeout does
    /// not cover on its own (see its doc comment). Kept distinct from
    /// `fetch` because that function is fallible and does not fall back:
    /// the TUI catalog picker needs the infallible contract so a fetch
    /// failure degrades to the hardcoded picker instead of propagating an
    /// error the picker isn't built to render.
    pub async fn fetch_unified(client: &reqwest::Client) -> Self {
        use tokio::time::{timeout, Duration};

        let catalog = match timeout(
            Duration::from_secs(FETCH_TIMEOUT_SECS),
            Self::fetch_from(client, DEFAULT_CATALOG_URL),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "catalog fetch failed, using hardcoded fallback");
                Self::fallback()
            }
            Err(_) => {
                tracing::warn!("catalog fetch timed out, using hardcoded fallback");
                Self::fallback()
            }
        };
        tracing::info!(count = catalog.entries.len(), "unified catalog loaded");
        catalog
    }

    /// Build a catalog from the hardcoded plain-domain fallback entries.
    /// Used by the daemon's slug-to-URL resolver and as the offline
    /// fallback for [`Self::fetch_unified`].
    pub fn fallback() -> Self {
        let entries = FALLBACK_ENTRIES
            .iter()
            .map(|(id, url)| CatalogEntry {
                scope: id.split('/').next().unwrap_or("unknown").to_string(),
                topic: Some(id.split('/').nth(1).unwrap_or("unknown").to_string()),
                name: id.split('/').nth(1).unwrap_or("unknown").to_string(),
                url: url.to_string(),
                entries: 0,
                updated_at: String::new(),
                format: BlocklistFormat::Domains,
            })
            .collect();
        Self { entries }
    }

    /// Filename of the persisted catalog inside the list cache dir.
    ///
    /// **Must not end in `.cache` or `.meta`.**
    /// [`ListManager::cleanup_stale_caches`](crate::lists::manager::ListManager::cleanup_stale_caches)
    /// deletes every file in this directory carrying either suffix whose stem
    /// is not an active source — this file would qualify, delete itself on the
    /// next boot, and put the catalog fetch back on the pre-bind path silently.
    /// `persisted_catalog_survives_stale_cache_cleanup` is the trip-wire.
    const DISK_FILENAME: &str = "catalog.json";

    /// Persist this catalog into `dir` so the next boot can resolve list
    /// sources without a network call.
    ///
    /// The file is **our own serialization of `Vec<CatalogEntry>`**, not
    /// the wire `index.json` envelope — see [`CatalogEntry`].
    ///
    /// Routed through
    /// [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write)
    /// with the same options as the `.cache` / `.meta` sidecars written into
    /// this very directory (`lists/manager.rs`'s `atomic_write`): no
    /// validator (there is no schema to check beyond "it is the JSON we just
    /// produced"), mode preserved-or-`0o640`, parent dir fsynced. A
    /// half-written catalog would be a parse failure on the next boot, which
    /// degrades to a fetch — but the temp-then-rename keeps even that from
    /// happening.
    ///
    /// `std::io::Result` rather than `AtomicWriteError` because both call
    /// sites log-and-continue: a catalog we cannot persist still works for
    /// this process, it just does not help the next boot.
    pub fn save_to_disk(&self, dir: &Path) -> std::io::Result<()> {
        let body = serde_json::to_vec(&self.entries).map_err(std::io::Error::other)?;
        crate::config::atomic_write::hardened_atomic_write(
            &dir.join(Self::DISK_FILENAME),
            &body,
            crate::config::atomic_write::AtomicWriteOpts::default(),
        )
        .map_err(std::io::Error::other)
    }

    /// Load a catalog previously written by [`Self::save_to_disk`].
    ///
    /// `None` on **any** failure — absent, unreadable, or unparseable. A
    /// corrupt file is a cache miss, never a panic and never a partial
    /// catalog: the caller falls back to fetching, and past that to
    /// [`FALLBACK_ENTRIES`]. That is also what makes a drift between this
    /// file's shape and the wire `index.json` safe rather than fatal.
    pub fn load_from_disk(dir: &Path) -> Option<Self> {
        let path = dir.join(Self::DISK_FILENAME);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read persisted catalog");
                return None;
            }
        };
        match serde_json::from_slice::<Vec<CatalogEntry>>(&bytes) {
            Ok(entries) => {
                tracing::debug!(count = entries.len(), "persisted catalog loaded");
                Some(Self { entries })
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "persisted catalog is unparseable, ignoring");
                None
            }
        }
    }

    /// Resolve a list ID (e.g. "privacy/ads") to its download URL.
    /// Also accepts raw URLs (starting with "http") as pass-through.
    pub fn resolve(&self, id_or_url: &str) -> Option<String> {
        if id_or_url.starts_with("http://") || id_or_url.starts_with("https://") {
            return Some(id_or_url.to_string());
        }
        self.entries
            .iter()
            .find(|e| e.id_matches(id_or_url))
            .map(|e| e.url.clone())
    }

    /// All entries in the catalog.
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// Build a catalog from hand-written entries.
    ///
    /// Test-only: every production path arrives through [`Self::fetch_from`]
    /// (parsed JSON) or [`Self::fallback`], and a public constructor would
    /// invite a third. Exists so a consumer can exercise entry shapes
    /// `lists.purge.cc` does not publish today — an `adguard`-stamped
    /// entry above all, which is what the TUI picker must keep rendering
    /// flat.
    #[cfg(test)]
    pub(crate) fn from_entries(entries: Vec<CatalogEntry>) -> Self {
        Self { entries }
    }
}

/// Default list sources for `warden init` — security + core privacy.
/// Conservative: 3 lists, well under the 64-source bitmask limit.
pub const DEFAULT_SOURCES: &[&str] = &["security/malicious", "privacy/ads", "privacy/tracking"];

/// Hardcoded fallback: all purge.cc plain-domain lists for offline bootstrap.
/// URLs match the live catalog at https://lists.purge.cc/index.json.
///
/// **This is a published API surface, not just an offline convenience.**
/// `cli::commands::lists::derive_subscription` resolves an operator's
/// `warden lists add <slug>` against *this* table, while `warden lists
/// catalog` displays [`Catalog::fetch`] — so a list published upstream
/// but absent here is one every operator can see and none can subscribe
/// to by slug. Keep it in step with `index.json`;
/// `fallback_entries_track_the_live_catalog` is the (network, `#[ignore]`d)
/// detector.
///
/// Entries are pointers to first-party purge.cc list files. That is the
/// reason this table is neutrality-legal where a table of the resolver
/// hostnames *inside* `resolvers.txt` would not be: warden learns no
/// third-party name from a URL. Never inline a list's contents here.
const FALLBACK_ENTRIES: &[(&str, &str)] = &[
    // privacy
    ("privacy/ads", "https://lists.purge.cc/ads.txt"),
    ("privacy/devices", "https://lists.purge.cc/devices.txt"),
    ("privacy/general", "https://lists.purge.cc/general.txt"),
    ("privacy/mobile", "https://lists.purge.cc/mobile.txt"),
    ("privacy/tracking", "https://lists.purge.cc/tracking.txt"),
    // security
    ("security/malicious", "https://lists.purge.cc/malicious.txt"),
    (
        "security/suspicious",
        "https://lists.purge.cc/suspicious.txt",
    ),
    // content
    ("content/adult", "https://lists.purge.cc/adult.txt"),
    ("content/dating", "https://lists.purge.cc/dating.txt"),
    ("content/gambling", "https://lists.purge.cc/gambling.txt"),
    ("content/hate", "https://lists.purge.cc/hate.txt"),
    ("content/piracy", "https://lists.purge.cc/piracy.txt"),
    // services
    ("services/apple", "https://lists.purge.cc/apple.txt"),
    ("services/meta", "https://lists.purge.cc/meta.txt"),
    ("services/microsoft", "https://lists.purge.cc/microsoft.txt"),
    // Published upstream, missing here until N1 — the gap `warden lists
    // catalog` showed and `warden lists add services/resolvers` refused.
    // Deliberately NOT in DEFAULT_SOURCES: subscribing every fresh
    // install to it by fiat is the non-neutral default `neutrality-03`
    // removed. The operator opts in.
    ("services/resolvers", "https://lists.purge.cc/resolvers.txt"),
    ("services/tiktok", "https://lists.purge.cc/tiktok.txt"),
];

/// Errors from catalog fetch/parse operations.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("failed to fetch catalog: {0}")]
    Fetch(String),
    #[error("failed to parse catalog: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_catalog_resolves_known_ids() {
        let catalog = Catalog::fallback();
        assert_eq!(
            catalog.resolve("privacy/ads"),
            Some("https://lists.purge.cc/ads.txt".to_string())
        );
        assert_eq!(
            catalog.resolve("security/malicious"),
            Some("https://lists.purge.cc/malicious.txt".to_string())
        );
    }

    #[test]
    fn fallback_catalog_returns_none_for_unknown() {
        let catalog = Catalog::fallback();
        assert_eq!(catalog.resolve("nonexistent/list"), None);
    }

    /// N1 — `services/resolvers` was published without landing here.
    ///
    /// This is not "offline operators miss an entry". `warden lists
    /// catalog` renders [`Catalog::fetch`] (live, 17 entries) while
    /// `derive_subscription` resolves against [`Catalog::fallback`]
    /// (built-in, then 16) — so **every** operator, online or not, was
    /// shown a list and refused when they typed its slug.
    #[test]
    fn fallback_carries_the_services_resolvers_list() {
        assert_eq!(
            Catalog::fallback().resolve("services/resolvers"),
            Some("https://lists.purge.cc/resolvers.txt".to_string()),
            "a slug `warden lists catalog` displays must be one `warden lists add` accepts"
        );
    }

    #[test]
    fn id_matches_is_equivalent_to_id_comparison() {
        // id_matches() is the no-alloc rewrite of resolve()'s per-entry scan;
        // it must agree with `id() == candidate` for every candidate shape,
        // including the topic=None (scope-only id) and extra-slash cases.
        let with_topic = CatalogEntry {
            scope: "privacy".to_string(),
            topic: Some("ads".to_string()),
            name: String::new(),
            url: "https://example.com/a.txt".to_string(),
            entries: 0,
            updated_at: String::new(),
            format: BlocklistFormat::default(),
        };
        let scope_only = CatalogEntry {
            topic: None,
            ..with_topic.clone()
        };

        for entry in [&with_topic, &scope_only] {
            for candidate in [
                "privacy/ads",
                "privacy",
                "privacy/tracking",
                "security/malicious",
                "privacy/ads/extra",
                "",
                "ads",
            ] {
                assert_eq!(
                    entry.id_matches(candidate),
                    entry.id() == candidate,
                    "id_matches disagreed for id {:?} vs candidate {candidate:?}",
                    entry.id()
                );
            }
        }
    }

    #[test]
    fn resolve_passthrough_for_raw_urls() {
        let catalog = Catalog::fallback();
        let url = "https://example.com/custom-blocklist.txt";
        assert_eq!(catalog.resolve(url), Some(url.to_string()));
    }

    #[test]
    fn fallback_resolves_tracking() {
        let catalog = Catalog::fallback();
        assert_eq!(
            catalog.resolve("privacy/tracking"),
            Some("https://lists.purge.cc/tracking.txt".to_string())
        );
    }

    #[test]
    fn fallback_resolves_all_scopes() {
        let catalog = Catalog::fallback();
        // One entry from each scope
        assert!(catalog.resolve("content/adult").is_some());
        assert!(catalog.resolve("services/meta").is_some());
    }

    #[test]
    fn fallback_has_expected_count() {
        // 16 → 17 at N1: `services/resolvers` was published upstream and
        // never landed here. Moving this number is the *intended* cost of
        // adding an entry — but move it only alongside a real addition,
        // never to quiet a red: this count and the published index are
        // supposed to agree (see
        // `fallback_entries_track_the_live_catalog`).
        let catalog = Catalog::fallback();
        assert_eq!(catalog.entries().len(), 17);
    }

    #[test]
    fn fallback_entries_default_to_domains_format() {
        // Plain-domain lists fallback must stamp every entry with
        // BlocklistFormat::Domains so the catalog picker subscribe path
        // writes `format = "domains"` into [[blocklists]].
        let catalog = Catalog::fallback();
        for e in catalog.entries() {
            assert_eq!(
                e.format,
                BlocklistFormat::Domains,
                "lists fallback entry '{}' must be Domains; got {:?}",
                e.id(),
                e.format
            );
        }
    }

    #[test]
    fn default_sources_resolve_in_fallback() {
        let catalog = Catalog::fallback();
        for src in DEFAULT_SOURCES {
            assert!(
                catalog.resolve(src).is_some(),
                "DEFAULT_SOURCES entry '{src}' should resolve in fallback catalog"
            );
        }
    }

    /// Hits the real `https://lists.purge.cc/index.json` — needs egress and
    /// a live CDN. Excluded from the default `cargo test` leg so the merge
    /// gate never depends on a third party (`tests-depend-on-live-cdn-gate-
    /// hostage`, P2: the 2026-07-23 `lists.purge.cc` proxy fault took this
    /// test red on both the dev box and the CT with zero code changes).
    /// Run explicitly, with egress, via:
    /// `cargo test --lib -- --ignored lists::catalog::tests::fetch_live_catalog`
    /// This is the one test that would notice the live catalog schema
    /// drifting away from the parser — do not delete it, only skip it.
    #[tokio::test]
    #[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
    async fn fetch_live_catalog() {
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let catalog = Catalog::fetch(&client).await.unwrap();
        assert!(!catalog.entries().is_empty());
        assert!(catalog.resolve("privacy/ads").is_some());
    }

    /// N1 — the drift detector for [`FALLBACK_ENTRIES`].
    ///
    /// `derive_subscription` resolves an operator's slug against the
    /// built-in catalog only, deliberately: `warden lists add` mutates
    /// the config, and making that depend on a live fetch would let a
    /// purge.cc outage change what the operator can do, and a poisoned
    /// index write a URL into their config. That choice is sound — but
    /// it makes [`FALLBACK_ENTRIES`] a **published API surface**, and
    /// until now nothing checked that it tracked the index. It fell one
    /// entry behind and the gap surfaced as an operator being refused a
    /// list the very same binary had just listed.
    ///
    /// Ignored by default and never wired into the tri-gate: a network
    /// test that gates commits is a purge.cc outage away from blocking
    /// all work (see [`fetch_live_catalog`], red on two boxes during the
    /// 2026-07-23 proxy fault). Run it when touching the catalog, and
    /// when the publisher ships a list:
    /// `cargo test --lib -- --ignored lists::catalog::tests::fallback_entries_track`
    ///
    /// Asserts fallback ⊇ live. The converse is deliberately allowed: an
    /// entry retired upstream must keep resolving here so an existing
    /// subscription does not break at the next `warden lists add`.
    #[tokio::test]
    #[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
    async fn fallback_entries_track_the_live_catalog() {
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let live = Catalog::fetch(&client).await.unwrap();
        let builtin = Catalog::fallback();

        let missing: Vec<String> = live
            .entries()
            .iter()
            .map(|e| e.id())
            .filter(|id| builtin.resolve(id).is_none())
            .collect();

        assert!(
            missing.is_empty(),
            "lists.purge.cc publishes {} list(s) this binary cannot resolve by slug: {missing:?}. \
             `warden lists catalog` displays them and `warden lists add <slug>` refuses them. \
             Add each to FALLBACK_ENTRIES.",
            missing.len()
        );
    }

    // --- §4.34 hostile-upstream regression tests --------------------

    /// Spawn a one-shot HTTP server that streams `total_bytes` of `0x61`
    /// after writing `headers`. Connection closes on EOF. Same pattern
    /// as the analogous helper at `lists/manager.rs:2028`; duplicated
    /// here to keep the catalog test independent of the manager test
    /// scaffolding.
    async fn spawn_one_shot_server(
        headers: &'static str,
        total_bytes: usize,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            if stream.write_all(headers.as_bytes()).await.is_err() {
                return;
            }
            let chunk = vec![b'a'; 64 * 1024];
            let mut sent = 0usize;
            while sent < total_bytes {
                let remaining = total_bytes - sent;
                let n = remaining.min(chunk.len());
                if stream.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                sent += n;
            }
        });
        addr
    }

    /// §4.34: a hostile / DNS-poisoned upstream that streams a multi-MiB
    /// body must be aborted by the projected-size guard inside
    /// `read_bounded_body_bytes`, surfaced as `CatalogError::Fetch`. The
    /// daemon must NOT buffer the entire body before noticing.
    #[tokio::test]
    async fn fetch_from_aborts_on_oversized_body() {
        // 4 MiB body, no Content-Length, connection closes at EOF —
        // exactly the OOM vector before §4.34. CATALOG_BODY_MAX_BYTES
        // is 1 MiB, so we expect a TooLarge / Fetch error within a few
        // chunks past the cap.
        let addr = spawn_one_shot_server(
            "HTTP/1.1 200 OK\r\n\
             Connection: close\r\n\
             Content-Type: application/json\r\n\
             \r\n",
            4 * 1024 * 1024,
        )
        .await;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("http://{addr}/index.json");
        let err = Catalog::fetch_from(&client, &url).await.unwrap_err();
        match err {
            CatalogError::Fetch(msg) => {
                assert!(
                    msg.contains("too large")
                        || msg.contains("response body")
                        || msg.contains("size")
                        || msg.contains("max"),
                    "expected oversized-body refusal message, got: {msg}"
                );
            }
            CatalogError::Parse(p) => {
                panic!("oversized body must be refused pre-parse, got Parse({p})");
            }
        }
    }

    /// §4.34 DISC-1: a slow-streaming upstream must be aborted by the
    /// per-call timeout, NOT by stalling the boot path indefinitely.
    #[tokio::test]
    async fn fetch_from_aborts_on_slow_stream_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            // Write headers, then dribble 1 byte every 500 ms forever.
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Connection: close\r\n\
                      Content-Type: application/json\r\n\
                      \r\n",
                )
                .await;
            loop {
                if stream.write_all(b"a").await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap();
        let url = format!("http://{addr}/index.json");
        let start = std::time::Instant::now();
        let err = Catalog::fetch_from(&client, &url).await.unwrap_err();
        let elapsed = start.elapsed();

        match err {
            CatalogError::Fetch(msg) => {
                assert!(
                    msg.contains("timed out") || msg.contains("timeout"),
                    "expected slow-stream timeout message, got: {msg}"
                );
            }
            CatalogError::Parse(p) => panic!("slow stream must time out pre-parse, got Parse({p})"),
        }
        // The FETCH_TIMEOUT_SECS cap is 2s; allow generous slack for
        // CI variance but assert we didn't sit on the reqwest default.
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "fetch_from took {elapsed:?} — timeout did not fire"
        );
    }

    // --- catalog disk persistence (boot_list_persistence §3.0) ------

    /// A persisted catalog round-trips and needs no network.
    #[test]
    fn catalog_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let original = Catalog::fallback();

        original.save_to_disk(dir.path()).expect("save");
        let loaded = Catalog::load_from_disk(dir.path()).expect("a saved catalog loads");

        let probe = original
            .entries()
            .first()
            .expect("fallback catalog is non-empty")
            .id();
        assert_eq!(
            loaded.resolve(&probe),
            original.resolve(&probe),
            "a round-tripped catalog must resolve identically"
        );
        assert!(
            loaded.resolve(&probe).is_some(),
            "the probe must actually resolve — two Nones would compare equal \
             and assert nothing"
        );
    }

    /// No persisted catalog means `None`, not a panic — the caller
    /// falls back to fetching, and past that to `FALLBACK_ENTRIES`.
    #[test]
    fn missing_catalog_on_disk_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Catalog::load_from_disk(dir.path()).is_none());
    }

    /// A corrupt file is a cache miss, not a crash and not a wrong catalog.
    ///
    /// Writes through [`Catalog::DISK_FILENAME`] rather than a hardcoded
    /// `"catalog.json"` on purpose: with the literal, renaming the const
    /// makes this test write a file the loader never opens, so it goes on
    /// passing while testing *absence* instead of corruption — measured,
    /// not assumed (it stayed green under the `catalog.cache` mutation).
    /// The filename's actual value is pinned where it matters, by
    /// `persisted_catalog_survives_stale_cache_cleanup`.
    #[test]
    fn corrupt_catalog_on_disk_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(Catalog::DISK_FILENAME), b"{ not json").unwrap();
        assert!(Catalog::load_from_disk(dir.path()).is_none());
    }

    /// The persisted catalog must survive `cleanup_stale_caches`, which
    /// shares its directory. This fails loudly if someone renames the
    /// file to `catalog.cache`.
    #[test]
    fn persisted_catalog_survives_stale_cache_cleanup() {
        use crate::lists::manager::{build_source_bit_map, ListManager};
        use std::sync::Arc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        Catalog::fallback().save_to_disk(dir.path()).expect("save");

        let source_bits = build_source_bit_map(&[]).expect("empty is fine");
        let mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(crate::filter::engine::FilterEngine::new()),
            vec![],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            1024 * 1024,
            10_000,
            Some(dir.path().to_path_buf()),
        );
        mgr.cleanup_stale_caches();

        assert!(
            Catalog::load_from_disk(dir.path()).is_some(),
            "cleanup_stale_caches must not eat the catalog — check the filename \
             suffix, it must be neither .cache nor .meta"
        );
    }
}
