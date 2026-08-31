//! Typed source-key facades for the list manager / profile resolver
//! contract (§4.24).
//!
//! Phase 1 (CLOSED 2026-05-06) introduced [`SourceBitMap`], replacing the
//! raw `HashMap<String, u8>` that the list-manager and the profile
//! resolver shared. The raw map keyed every entry by `String` and relied
//! on a kebab→slash compatibility shim to bridge URL-keyed producer ↔
//! id-keyed consumer. The 2026-05-06 silent-no-blocking incident showed
//! that this contract is too easy to break: a config cleanup that
//! emptied `[lists].sources = []` left every profile's `list_bitmask`
//! zeroed because no slash-form keys remained for the shim to translate
//! to.
//!
//! The typed facades expose lookup methods, one per source kind, so call
//! sites declare their intent at the lookup line:
//!
//! - [`SourceBitMap::bit_for_url`] / [`SourceBitMap::bit_for_v1_id`] /
//!   [`SourceBitMap::bit_for_legacy_catalog_id`] — the bit map (Phase 1).
//! - [`SourceTrustMap::trust_for_url`] / [`SourceTrustMap::trust_for_v1_id`]
//!   — per-source `BlocklistTrust`, fed to the `imported.local` loader
//!   bridge (Phase 2 §4.24-P2-A).
//! - [`SourceTokenMap::token_for_url`] / [`SourceTokenMap::token_for_v1_id`]
//!   — per-source bearer token resolved from `secrets.toml` (Phase 2
//!   §4.24-P2-B).
//!
//! Each facade owns its own seeding rules but shares the same
//! [`is_url_source`] heuristic for distinguishing URL-form vs legacy
//! slash-form catalog ids — the validator at
//! `src/config/schema/validator.rs` only accepts the two shapes.
//!
//! Phase B of the original kickoff removed the kebab→slash shim from
//! [`crate::profiles::profile::ResolvedProfile::build_v1`]. Phase 2 of
//! the workstream closes the sibling maps on the same call-site type
//! safety contract: `merge_sources_with_blocklists` returns
//! `(Vec<String>, SourceTrustMap)`, `build_source_tokens` returns
//! `SourceTokenMap`, and the `ListManager` struct fields carry the
//! typed shapes.

use std::collections::{BTreeMap, HashMap};

use ahash::RandomState;
use compact_str::CompactString;

use crate::config::schema::id::Id;
use crate::config::schema::{effective_direction, Blocklist, BlocklistTrust, ListPolicy, Profile};
use crate::filter::engine::{PolicyMasks, ProfileMasks};

use super::manager::{BitMapBuildError, MAX_LIST_SOURCES};

/// Typed facade over the URL ↔ v1-id ↔ legacy-catalog-id source bit map.
///
/// Internally three submaps share a single bit-index space (0..64). Every
/// bit that is reachable by URL is also reachable by v1 id (when a
/// matching `[[blocklists]]` row exists) and by legacy catalog id (when
/// the entry came from `[lists].sources` in slash form). The asymmetry
/// only goes one way: the URL channel is always populated; the id
/// channels are populated when the data is available.
#[derive(Debug, Clone, Default)]
pub struct SourceBitMap {
    by_url: HashMap<String, u8>,
    by_v1_id: HashMap<Id, u8>,
    by_legacy_catalog_id: HashMap<String, u8>,
}

impl SourceBitMap {
    /// Build the typed bit map from a merged `sources` vector
    /// (`merge_sources_with_blocklists` output) and the v1
    /// `[[blocklists]]` catalogue.
    ///
    /// **Bit assignment.** Sequential, one bit per `sources` entry.
    /// Returns [`BitMapBuildError::TooManySources`] when
    /// `sources.len() > MAX_LIST_SOURCES`. The error message is
    /// preserved verbatim from the legacy `build_source_bit_map` so
    /// frozen-strings tests stay green.
    ///
    /// **Seeding.** For each source, always populate `by_url` (the
    /// manager's fetch loop keys exactly on this string). When the
    /// source is a slash-form catalog id (heuristic: scheme is not
    /// `http://` / `https://`), also populate `by_legacy_catalog_id`
    /// and try to seed `by_v1_id` with `Id::new(source.replace('/','-'))`
    /// — invalid translations are silently skipped (the lookup simply
    /// returns `None` and the consumer treats it as "this list is not
    /// in the profile's bitmask").
    ///
    /// For each enabled blocklist whose URL has a bit, alias
    /// `by_v1_id[blocklist.id] → bit`. Disabled blocklists are skipped
    /// (their URL is not in `sources` per
    /// `merge_sources_with_blocklists`, so the alias would dangle).
    ///
    /// **Why both paths seed `by_v1_id`.** Pre-§4.24, pure-v1 configs
    /// (empty `[lists].sources`, populated `[[blocklists]]`) zeroed the
    /// profile resolver's bitmask because the URL-keyed map had no id
    /// to match. Mixed/legacy configs (`[lists].sources = ["privacy/ads"]`)
    /// only worked through the kebab→slash shim. With both channels
    /// seeding `by_v1_id`, the consumer collapses to a single
    /// `bit_for_v1_id(bid)` call regardless of source kind — closing
    /// the May 6 contract gap at the type level.
    pub fn build(sources: &[String], blocklists: &[Blocklist]) -> Result<Self, BitMapBuildError> {
        if sources.len() > MAX_LIST_SOURCES {
            return Err(BitMapBuildError::TooManySources {
                got: sources.len(),
                max: MAX_LIST_SOURCES,
            });
        }

        // Tighter capacity hints: every source contributes at most one
        // entry to each submap (`by_v1_id` is bounded by `sources +
        // blocklists`, the slash-form translation can never exceed
        // `sources`). Avoids one rehash on the typical 64-bit-cap path.
        let mut by_url: HashMap<String, u8> = HashMap::with_capacity(sources.len());
        let mut by_v1_id: HashMap<Id, u8> =
            HashMap::with_capacity(sources.len() + blocklists.len());
        let mut by_legacy_catalog_id: HashMap<String, u8> = HashMap::with_capacity(sources.len());

        for (i, source) in sources.iter().enumerate() {
            let bit = i as u8;
            by_url.insert(source.clone(), bit);

            if !is_url_source(source) {
                by_legacy_catalog_id.insert(source.clone(), bit);
                if let Ok(id) = Id::new(source.replace('/', "-")) {
                    by_v1_id.insert(id, bit);
                }
            }
        }

        for b in blocklists {
            if !b.enabled {
                continue;
            }
            if let Some(&bit) = by_url.get(b.url.as_str()) {
                by_v1_id.insert(b.id.clone(), bit);
            }
        }

        Ok(Self {
            by_url,
            by_v1_id,
            by_legacy_catalog_id,
        })
    }

    /// Project the operator's list policy onto **this** generation's bits.
    ///
    /// The one place a stable list id becomes a bit position. That boundary
    /// is the whole of `_docs/features/profile_list_policy.md` §2.4
    /// (D-ARCH-1): the config expresses policy per **list id**, which is
    /// stable, and only this function turns it into a `u64`, which is
    /// **positional** — `bit = i` over the merged sources vector, so removing
    /// one list slides every later list down one bit. A mask that crossed the
    /// config→engine boundary on its own could therefore meet a corpus that
    /// had re-assigned the bits it names, and under allow-beats-block the
    /// superset error is silent and fails open.
    ///
    /// The returned [`PolicyMasks`] goes straight into
    /// [`crate::filter::engine::ListPolicy::publish`] and travels in the same
    /// `Arc` as the entries it interprets. **Do not stash it anywhere else.**
    ///
    /// Direction per pair is [`effective_direction`] — one function, N
    /// callers (P5); this is not the place to re-derive the inheritance rule.
    ///
    /// **Disabled rows contribute nothing**, and not by an explicit test:
    /// `merge_sources_with_blocklists` never puts their URL in the merged
    /// sources vector, so `by_url` has no bit for them. Claiming one would be
    /// meaningless at best and, if a disabled row shadowed an enabled row's
    /// URL, actively wrong.
    ///
    /// **A list with no bit is skipped silently, and that is correct here.**
    /// It carries no domains in this generation, so no mask bit could ever
    /// meet it. The operator-facing complaint about a policy naming a list
    /// that does not exist belongs to the validator, which sees the config
    /// and can name the id.
    pub fn project_policy(
        &self,
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
    ) -> PolicyMasks {
        // The masks a profile carrying no override of its own gets. Same
        // rule as the per-profile loop below, reached through the same
        // mapping (`BlocklistBase::as_policy`) rather than re-spelled here
        // — P5, and the reason `Ignore` could not be forgotten at one of
        // the two sites.
        let mut inherited = ProfileMasks::INERT;
        for b in blocklists {
            let Some(bit) = self.bit_for_list(b) else {
                continue;
            };
            match b.base.as_policy() {
                ListPolicy::Deny => inherited.block |= 1u64 << bit,
                ListPolicy::Allow => inherited.allow |= 1u64 << bit,
                ListPolicy::Ignore => {}
            }
        }

        let mut per_profile: HashMap<CompactString, ProfileMasks, RandomState> =
            HashMap::with_capacity_and_hasher(profiles.len(), RandomState::new());
        for (pid, profile) in profiles {
            let mut masks = ProfileMasks::INERT;
            for b in blocklists {
                let Some(bit) = self.bit_for_list(b) else {
                    continue;
                };
                match effective_direction(profile, b) {
                    ListPolicy::Deny => masks.block |= 1u64 << bit,
                    ListPolicy::Allow => masks.allow |= 1u64 << bit,
                    ListPolicy::Ignore => {}
                }
            }
            debug_assert_eq!(
                masks.allow & masks.block,
                0,
                "profile `{pid}` has a list bit in both directions — \
                 `effective_direction` returned two answers for one pair",
            );
            per_profile.insert(CompactString::new(pid), masks);
        }

        PolicyMasks {
            base: inherited,
            per_profile,
        }
    }

    /// The bit this generation gave `b`, or `None` if it holds none.
    ///
    /// **Goes through [`Self::bit_for_v1_id`], not `by_url`, and the
    /// difference is the 2026-05-06 silent-no-blocking incident.** A config
    /// can name a source in two channels: a `[[blocklists]]` row (URL-keyed)
    /// or a slash-form slug in `[lists].sources` (translated to a v1 id).
    /// `by_url` only sees the first, so a slug-channel list would get no bit
    /// here — every profile would come out with an empty mask and the daemon
    /// would forward everything, which is exactly what happened for ~5h45m on
    /// the dev CT before §4.24 introduced the typed lookup. `by_v1_id` is
    /// seeded from **both** channels, which is why the consumer side has
    /// collapsed to one call since.
    ///
    /// Caught by `tests/dual_channel_source_dedup.rs`, which builds the
    /// slug-channel shape and asserts bit identity; the first draft of
    /// `project_policy` read `by_url` and both of its cases went to zero.
    ///
    /// Disabled rows return `None` for free: their URL never reaches the
    /// merged sources vector, so no channel seeds a bit for them.
    fn bit_for_list(&self, b: &Blocklist) -> Option<u8> {
        if !b.enabled {
            return None;
        }
        self.bit_for_v1_id(&b.id)
    }

    /// Look up the bit for a fetch URL. Used by the list manager's
    /// download loop.
    pub fn bit_for_url(&self, url: &str) -> Option<u8> {
        self.by_url.get(url).copied()
    }

    /// Look up the bit for a v1 entity [`Id`]. Called by the profile
    /// resolver once per applicable list when it turns the tag
    /// intersection into a subscription mask — `ResolvedProfile::build_v1`
    /// and `specialise_with_effective_tags`, both in
    /// `src/profiles/profile.rs`. The pre-v2 `profile.blocklists` field
    /// this comment used to name is gone; the ids now come from
    /// `blocklist.tags ∩ effective_tags`.
    pub fn bit_for_v1_id(&self, id: &Id) -> Option<u8> {
        self.by_v1_id.get(id).copied()
    }

    /// Look up the bit for a legacy slash-form catalog id (e.g.
    /// `"security/malicious"`). Used by tooling and migration paths
    /// that still speak the pre-v1 `[lists].sources` format.
    pub fn bit_for_legacy_catalog_id(&self, slash_id: &str) -> Option<u8> {
        self.by_legacy_catalog_id.get(slash_id).copied()
    }

    /// Iterate the URL → bit pairs in arbitrary order. Used by the
    /// list manager's fetch loop and by debug tooling.
    pub fn iter_urls(&self) -> impl Iterator<Item = (&str, u8)> {
        self.by_url.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Total number of URL keys (one per assigned bit).
    pub fn len(&self) -> usize {
        self.by_url.len()
    }

    /// `true` when no source has been seeded.
    pub fn is_empty(&self) -> bool {
        self.by_url.is_empty()
    }
}

/// Heuristic: an entry is a URL when it carries the `http://` or
/// `https://` scheme. Everything else is treated as a legacy slash-form
/// catalog id (the validator at `src/config/schema/validator.rs` only
/// accepts these two shapes for `[lists].sources`).
///
/// **The one seat for this classification, crate-wide** — the source-key
/// facades here, the `lists`/`blocklist` CLI verbs, and the catalog
/// resolver all route through it. The predicate decides where warden
/// fetches a blocklist from, so a second copy is a second scheme policy:
/// whichever copy a change misses keeps accepting or rejecting on the
/// old rule, silently and without a failing build.
///
/// Case-sensitive by contract: `HTTP://host/l.txt` is **not** a URL
/// here, it is a (nonsensical) legacy catalog id. Widening that is a
/// scheme-policy change and belongs in this function, not at a call
/// site.
pub(crate) fn is_url_source(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Canonical key for comparing blocklist identity.
///
/// **NOT used for fetching**: the original URL is still what gets
/// downloaded, and the on-disk cache stem is still derived from it
/// (`lists::manager::source_to_cache_stem`). This is purely an
/// equivalence key, so two entries that differ only in ways HTTP
/// considers meaningless compare equal.
///
/// `tag_model_consolidation` §3.2 — the single point of truth for
/// "are these two blocklists the same source?". Three callers share it:
/// the `warden blocklist add` gate, the `warden blocklist set <id> url`
/// gate, and the validator's duplicate check
/// ([`crate::config::schema::validator::BLOCKLIST_DUPLICATE_URL`]).
/// A byte-exact comparison let `.../ads.txt` and `.../ads.txt/` coexist,
/// and twins share one cache file and one ETag: a `304` for one silently
/// satisfies the other, and the last writer wins the body.
///
/// Normalisation, in order:
///
/// 1. scheme lowercased;
/// 2. host lowercased (userinfo, if any, left alone — it is a
///    credential, and two different credentials are not one source);
/// 3. default port dropped (`:80` on http, `:443` on https) — any other
///    port is kept;
/// 4. one trailing `/` dropped from the path;
/// 5. path left otherwise untouched, **case-sensitive** (RFC 3986 says
///    only scheme and host are case-insensitive; `/Ads.txt` and
///    `/ads.txt` are genuinely different resources on most servers);
/// 6. query and fragment left untouched, including their order.
///
/// Deliberately dependency-free (hand-rolled scan, no `url` crate) so
/// the key can be computed from the config layer, which must not pull
/// in an HTTP stack. Input that does not parse as `scheme://…` is
/// returned unchanged: a malformed URL is refused elsewhere with a
/// better message, and silently rewriting it here would only obscure it.
pub fn canonical_url_key(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let scheme = url[..scheme_end].to_ascii_lowercase();
    let rest = &url[scheme_end + 3..];

    // The authority runs to the first `/`, `?` or `#`.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];

    // `[userinfo@]host[:port]` — split on the LAST `@`, since userinfo
    // may itself contain one.
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };

    // An IPv6 literal is bracketed and its colons are not port
    // separators — only a colon AFTER the closing bracket is.
    let port_sep = if host_port.starts_with('[') {
        host_port
            .find(']')
            .and_then(|close| host_port[close + 1..].starts_with(':').then_some(close + 1))
    } else {
        // A bare host has at most one colon; more than one means a
        // malformed authority, so leave it alone rather than guess.
        (host_port.matches(':').count() == 1).then(|| host_port.find(':').unwrap_or(0))
    };
    let (host, port) = match port_sep {
        Some(i) => (&host_port[..i], Some(&host_port[i + 1..])),
        None => (host_port, None),
    };

    let keep_port = match (scheme.as_str(), port) {
        (_, None) => None,
        ("http", Some("80")) | ("https", Some("443")) => None,
        (_, Some(p)) => Some(p),
    };

    // Split the tail into path vs query/fragment so the trailing-slash
    // rule applies to the path and never eats a `/` inside a query.
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = tail[..path_end]
        .strip_suffix('/')
        .unwrap_or(&tail[..path_end]);
    let suffix = &tail[path_end..];

    let mut out = String::with_capacity(url.len());
    out.push_str(&scheme);
    out.push_str("://");
    if let Some(ui) = userinfo {
        out.push_str(ui);
        out.push('@');
    }
    out.push_str(&host.to_ascii_lowercase());
    if let Some(p) = keep_port {
        out.push(':');
        out.push_str(p);
    }
    out.push_str(path);
    out.push_str(suffix);
    out
}

/// Typed facade over the URL ↔ v1-id source → [`BlocklistTrust`] map
/// (§4.24 Phase 2).
///
/// Replaces the raw `HashMap<String, BlocklistTrust>` that
/// [`merge_sources_with_blocklists`](crate::lists::manager::merge_sources_with_blocklists)
/// historically returned. The trust is associated with each
/// `[[blocklists]]` row at the schema level; both `[lists].sources`
/// entries (legacy slash form, no schema-level trust) and absent rows
/// resolve to [`BlocklistTrust::RemoteUnsigned`] at the consumer via the
/// usual `unwrap_or` default — preserving pre-§4.24-P2 behaviour byte
/// for byte.
///
/// Two internal submaps share the same trust values:
///
/// - `by_url` — the manager's fetch loop keys exactly on the source
///   string. Every enabled or disabled `[[blocklists]]` row contributes
///   (the manager checks trust unconditionally on the fetch path; the
///   disabled rows simply never reach that path because the merged
///   sources vector omits them).
/// - `by_v1_id` — new in Phase 2. Lets future consumers (TUI, IPC,
///   audit) resolve trust by canonical [`Id`] without monkey-patching a
///   reverse lookup through the URL.
///
/// Build is infallible — the trust map has no per-list cap (the
/// 64-source cap is enforced exactly once, by [`SourceBitMap::build`],
/// which is the canonical entry point on the daemon hot path).
#[derive(Debug, Clone, Default)]
pub struct SourceTrustMap {
    by_url: HashMap<String, BlocklistTrust>,
    by_v1_id: HashMap<Id, BlocklistTrust>,
}

impl SourceTrustMap {
    /// Build the typed trust map from the v1 `[[blocklists]]`
    /// catalogue.
    ///
    /// Every blocklist row contributes both lookups regardless of
    /// `enabled`. The manager's fetch loop only sees enabled rows in
    /// the merged sources vector, but the trust map carries every row
    /// so that out-of-band consumers (a hypothetical `warden blocklist
    /// inspect <id>` verb, for instance) can still resolve trust for
    /// rows the operator has temporarily disabled.
    pub fn build(blocklists: &[Blocklist]) -> Self {
        let mut by_url: HashMap<String, BlocklistTrust> = HashMap::with_capacity(blocklists.len());
        let mut by_v1_id: HashMap<Id, BlocklistTrust> = HashMap::with_capacity(blocklists.len());
        for b in blocklists {
            by_url.insert(b.url.clone(), b.trust);
            by_v1_id.insert(b.id.clone(), b.trust);
        }
        Self { by_url, by_v1_id }
    }

    /// Look up trust by fetch URL. Used by the list manager's
    /// `imported.local` bridge guard at fetch time.
    pub fn trust_for_url(&self, url: &str) -> Option<BlocklistTrust> {
        self.by_url.get(url).copied()
    }

    /// Look up trust by canonical v1 entity [`Id`]. Added for symmetry
    /// with [`SourceBitMap::bit_for_v1_id`]; future id-keyed consumers
    /// (TUI lists tab inspection, audit attribution) can read trust
    /// without resolving the URL first.
    pub fn trust_for_v1_id(&self, id: &Id) -> Option<BlocklistTrust> {
        self.by_v1_id.get(id).copied()
    }

    /// Borrow the URL submap as a raw `HashMap<String, BlocklistTrust>`
    /// for transition consumers that pre-date this typed facade. New
    /// consumers should reach for [`trust_for_url`](Self::trust_for_url)
    /// or [`trust_for_v1_id`](Self::trust_for_v1_id) instead.
    pub fn url_trusts(&self) -> &HashMap<String, BlocklistTrust> {
        &self.by_url
    }

    /// Total number of distinct URL keys.
    pub fn len(&self) -> usize {
        self.by_url.len()
    }

    /// `true` when no blocklist row has been seeded.
    pub fn is_empty(&self) -> bool {
        self.by_url.is_empty()
    }
}

/// Typed facade over the source → bearer-token map used for
/// `Authorization: Bearer <value>` headers on blocklist fetches
/// (§4.24 Phase 2 P2-B).
///
/// Replaces the raw `HashMap<String, String>` that the start.rs
/// helper `build_source_tokens` historically returned. The token is
/// resolved at build time from each `[[blocklists]].auth_token_ref` →
/// `Secrets` entry; absence (no ref OR ref missing in `secrets.toml`)
/// leaves the request anonymous (a warn is emitted from build()).
///
/// Two internal submaps share the same token values:
///
/// - `by_url` — keyed by the **legacy slash-form source-key** produced
///   by the existing kebab→slash translation (`b.id.replacen('-','/',1)`).
///   The manager's [`download_list`](crate::lists::manager::ListManager)
///   path keys exactly on this string today, so the typed API preserves
///   pre-§4.24-P2 behaviour byte for byte. **Latent gap**: pure-v1
///   configs (`[lists].sources = []`) put URL strings in the manager's
///   source vector, which never matches a slash-form key — so a
///   blocklist whose ONLY entry is in `[[blocklists]]` with
///   `auth_token_ref` set currently fetches anonymously. Phase 2 leaves
///   this gap in place to keep the scope as pure refactor; the new
///   `token_for_v1_id` lookup positions a future fix (the manager's
///   `source_to_blocklist` reverse-mapping at line 251 already resolves
///   source → `Id`, so a follow-up commit can chain `Id → token` via
///   `token_for_v1_id`).
/// - `by_v1_id` — new in Phase 2. Lets future consumers resolve the
///   token by canonical [`Id`] without re-deriving the slash-form.
#[derive(Clone, Default)]
pub struct SourceTokenMap {
    by_url: HashMap<String, String>,
    by_v1_id: HashMap<Id, String>,
}

/// rev-2606 §06 `source_key-01`: hand-written `Debug` that redacts the
/// resolved bearer tokens. The derived `Debug` would print every secret
/// in cleartext on any accidental `{:?}` — a future `debug!(?token_map)`,
/// a `#[derive(Debug)]` on a containing struct that then gets logged, or
/// a test dump. Print only the counts; never the values.
impl std::fmt::Debug for SourceTokenMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceTokenMap")
            .field("by_url", &format_args!("<{} tokens>", self.by_url.len()))
            .field(
                "by_v1_id",
                &format_args!("<{} tokens>", self.by_v1_id.len()),
            )
            .finish()
    }
}

impl SourceTokenMap {
    /// Build the typed token map from the v1 `[[blocklists]]`
    /// catalogue and the loaded [`crate::config::secrets::Secrets`].
    ///
    /// For each enabled or disabled blocklist row with
    /// `auth_token_ref` set: resolve the named secret, insert the
    /// bearer string twice — once under the slash-form source-key
    /// (matches manager.rs:1032 lookup byte for byte) and once under
    /// the canonical [`Id`] (new typed surface). Rows whose
    /// `auth_token_ref` points at a missing secret emit a
    /// `tracing::warn!` and are skipped — the download proceeds
    /// anonymously, identical to pre-§4.24-P2 behaviour.
    pub fn build(
        config: &crate::config::schema::ConfigV1,
        secrets: &crate::config::secrets::Secrets,
    ) -> Self {
        let mut by_url: HashMap<String, String> = HashMap::new();
        let mut by_v1_id: HashMap<Id, String> = HashMap::new();
        for b in &config.blocklists {
            let Some(ref_name) = b.auth_token_ref.as_deref() else {
                continue;
            };
            let Some(value) = secrets.get(ref_name) else {
                tracing::warn!(
                    blocklist = %b.id,
                    auth_token_ref = ref_name,
                    "blocklist auth_token_ref points at a missing secret; download will \
                     proceed without an Authorization header"
                );
                continue;
            };
            // Kebab→slash translation matches the legacy
            // `build_source_tokens` key shape so the manager's
            // existing `source_tokens.get(source)` lookup at
            // `download_list` continues to hit byte-identically.
            let source_key = b.id.as_str().replacen('-', "/", 1);
            by_url.insert(source_key, value.to_string());
            by_v1_id.insert(b.id.clone(), value.to_string());
        }
        Self { by_url, by_v1_id }
    }

    /// Look up the bearer token by the source string used in the
    /// manager's sources vector (slash-form catalog id for legacy
    /// configs). Pure-v1 sources (URLs in the vector) do **not** hit
    /// — see the `by_url` doc-comment on the struct for the latent
    /// gap rationale.
    pub fn token_for_url(&self, source: &str) -> Option<&str> {
        self.by_url.get(source).map(String::as_str)
    }

    /// Look up the bearer token by canonical v1 entity [`Id`]. New
    /// surface in §4.24 Phase 2 — closes the URL-vs-id ambiguity at
    /// the type level and positions future consumers (the manager's
    /// `source_to_blocklist` reverse-mapping path) to fetch with
    /// authentication on pure-v1 configs.
    pub fn token_for_v1_id(&self, id: &Id) -> Option<&str> {
        self.by_v1_id.get(id).map(String::as_str)
    }

    /// Borrow the URL submap as a raw `HashMap<String, String>` for
    /// transition consumers that pre-date this typed facade. New
    /// consumers should reach for [`token_for_url`](Self::token_for_url)
    /// or [`token_for_v1_id`](Self::token_for_v1_id) instead.
    pub fn url_tokens(&self) -> &HashMap<String, String> {
        &self.by_url
    }

    /// Total number of resolved token entries (one per
    /// `auth_token_ref` that found a matching secret).
    pub fn len(&self) -> usize {
        self.by_url.len()
    }

    /// `true` when no blocklist resolved a token.
    pub fn is_empty(&self) -> bool {
        self.by_url.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};

    fn mk_blocklist(id: &str, url: &str, enabled: bool) -> Blocklist {
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    #[test]
    fn build_seeds_url_bit_for_each_source() {
        let sources = vec![
            "https://lists.purge.cc/ads.txt".to_string(),
            "https://lists.purge.cc/malicious.txt".to_string(),
        ];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_url("https://lists.purge.cc/ads.txt"), Some(0));
        assert_eq!(
            map.bit_for_url("https://lists.purge.cc/malicious.txt"),
            Some(1),
        );
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn build_pure_v1_config_seeds_v1_id_alias_from_blocklist() {
        // The May 6 case: empty `[lists].sources`, populated
        // `[[blocklists]]`. After `merge_sources_with_blocklists`, the
        // sources vector carries the URL — the v1 id alias must point
        // at the same bit so the profile resolver's `bit_for_v1_id`
        // lookup hits.
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let map = SourceBitMap::build(&sources, &blocklists).unwrap();
        assert_eq!(
            map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(0),
            "pure-v1 config must produce a non-zero bit for the v1 id; \
             the May 6 incident had this silently fall to None",
        );
        assert_eq!(map.bit_for_url("https://lists.purge.cc/ads.txt"), Some(0));
    }

    /// neutrality-06 — the shard builder needs to know which source bits
    /// are allow-direction. Direction is a per-source property, so it
    /// collapses to a single `u64` over the same bit space the corpus
    /// already uses.
    #[test]
    fn allow_bits_sets_only_allow_direction_sources() {
        let sources = vec![
            "https://lists.purge.cc/ads.txt".to_string(),
            "https://lists.purge.cc/compat.txt".to_string(),
        ];
        let deny = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", true);
        let mut allow = mk_blocklist("compat", "https://lists.purge.cc/compat.txt", true);
        allow.base = BlocklistBase::Allow;
        allow.trust = BlocklistTrust::Local;

        let map = SourceBitMap::build(&sources, &[deny.clone(), allow.clone()]).unwrap();

        assert_eq!(
            map.project_policy(&[deny, allow], &BTreeMap::new())
                .base
                .allow,
            0b10,
            "only the kind=allow source's bit may be set"
        );
    }

    /// A config with no allow-direction list must yield an empty mask —
    /// the pre-neutrality-06 behaviour, preserved exactly.
    #[test]
    fn allow_bits_is_zero_when_every_list_is_deny() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let deny = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", true);
        let map = SourceBitMap::build(&sources, std::slice::from_ref(&deny)).unwrap();
        assert_eq!(map.project_policy(&[deny], &BTreeMap::new()).base.allow, 0);
    }

    /// A disabled allow list never reaches the corpus, so it must not
    /// claim a bit in the mask either.
    #[test]
    fn allow_bits_ignores_disabled_allow_lists() {
        let sources = vec!["https://lists.purge.cc/compat.txt".to_string()];
        let mut allow = mk_blocklist("compat", "https://lists.purge.cc/compat.txt", false);
        allow.base = BlocklistBase::Allow;
        allow.trust = BlocklistTrust::Local;
        let map = SourceBitMap::build(&sources, std::slice::from_ref(&allow)).unwrap();
        assert_eq!(map.project_policy(&[allow], &BTreeMap::new()).base.allow, 0);
    }

    #[test]
    fn build_legacy_slash_form_seeds_v1_id_alias_via_translation() {
        // Pre-v1 configs carried slash-form catalog ids in
        // `[lists].sources`. The translation `"privacy/ads" →
        // Id("privacy-ads")` must be done at build time so the
        // consumer's `bit_for_v1_id(bid)` lookup hits without a
        // fallback.
        let sources = vec!["privacy/ads".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_legacy_catalog_id("privacy/ads"), Some(0));
        assert_eq!(
            map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(0),
            "legacy slash-form id must auto-alias to v1 id",
        );
    }

    #[test]
    fn build_skips_disabled_blocklists() {
        // Disabled entries don't appear in
        // `merge_sources_with_blocklists` output, so their URL has no
        // bit. The id alias would dangle — skip it.
        let sources: Vec<String> = vec![];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            false,
        )];
        let map = SourceBitMap::build(&sources, &blocklists).unwrap();
        assert!(map.is_empty());
        assert_eq!(map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()), None);
    }

    #[test]
    fn bit_for_v1_id_returns_none_for_unknown_id() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_v1_id(&Id::new("not-configured").unwrap()), None,);
    }

    #[test]
    fn bit_for_url_returns_none_for_unknown_url() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_url("https://other.example/ads.txt"), None);
    }

    #[test]
    fn build_errors_one_over_cap_with_legacy_message() {
        let sources: Vec<String> = (0..65).map(|i| format!("list/{i}")).collect();
        let err = SourceBitMap::build(&sources, &[]).expect_err("65 sources exceeds cap");
        let msg = err.to_string();
        assert!(msg.contains("65"), "report actual count: {msg}");
        assert!(msg.contains("64"), "report cap: {msg}");
        assert!(msg.contains("config.toml"), "preserve operator hint: {msg}");
    }

    #[test]
    fn blocklist_url_alias_overwrites_slash_form_v1_id_alias() {
        // §11.4 bit-shuffle gotcha pin. When BOTH source channels
        // alias the same logical list (slash-form `[lists].sources`
        // entry + matching `[[blocklists]]` row whose URL is a
        // separate entry in the merged sources vector), the
        // blocklist-step seeding overwrites the slash-form-translation
        // step's `by_v1_id` entry because `HashMap::insert` overwrites.
        // Final value points at the URL-derived bit, not the
        // slash-form-derived one. Pinning this explicitly prevents an
        // accidental order swap from breaking downstream test fixtures
        // (`init.rs:570` took this exact bite during Phase B).
        let sources = vec![
            "security/malicious".to_string(),
            "https://lists.purge.cc/security/malicious.txt".to_string(),
        ];
        let blocklists = vec![mk_blocklist(
            "security-malicious",
            "https://lists.purge.cc/security/malicious.txt",
            true,
        )];
        let map = SourceBitMap::build(&sources, &blocklists).unwrap();

        // Bit assignment is sequential: slash-form gets bit 0, URL bit 1.
        assert_eq!(map.bit_for_legacy_catalog_id("security/malicious"), Some(0));
        assert_eq!(
            map.bit_for_url("https://lists.purge.cc/security/malicious.txt"),
            Some(1),
        );

        // Slash-form translation step seeds `by_v1_id[Id] = 0` first;
        // blocklist-URL-alias step then overwrites with bit 1.
        assert_eq!(
            map.bit_for_v1_id(&Id::new("security-malicious").unwrap()),
            Some(1),
            "URL-derived alias must win over slash-form translation",
        );
    }

    #[test]
    fn iter_urls_yields_only_url_keys() {
        let sources = vec![
            "privacy/ads".to_string(),
            "https://lists.purge.cc/malicious.txt".to_string(),
        ];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        let urls: Vec<_> = map.iter_urls().collect();
        assert_eq!(urls.len(), 2, "iter_urls covers every assigned bit");
        // Both source kinds populate `by_url` — manager keys verbatim
        // on whatever string the operator put in `[lists].sources`.
        let keys: Vec<&str> = urls.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"privacy/ads"));
        assert!(keys.contains(&"https://lists.purge.cc/malicious.txt"));
    }

    fn mk_trusted_blocklist(id: &str, url: &str, trust: BlocklistTrust) -> Blocklist {
        let mut b = mk_blocklist(id, url, true);
        b.trust = trust;
        b
    }

    #[test]
    fn trust_map_build_pure_v1_seeds_url_and_v1_id_both_lookups() {
        let blocklists = vec![
            mk_trusted_blocklist(
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
                BlocklistTrust::RemoteUnsigned,
            ),
            mk_trusted_blocklist(
                "security-malicious",
                "https://lists.purge.cc/malicious.txt",
                BlocklistTrust::Signed,
            ),
        ];
        let map = SourceTrustMap::build(&blocklists);

        assert_eq!(
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
            Some(BlocklistTrust::RemoteUnsigned),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(BlocklistTrust::RemoteUnsigned),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("security-malicious").unwrap()),
            Some(BlocklistTrust::Signed),
        );
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn trust_map_build_seeds_disabled_blocklists_too() {
        // The pre-§4.24-P2 `merge_sources_with_blocklists` inserted
        // trust unconditionally (line 1643 of manager.rs at sprint
        // open). Phase 2 preserves this — a disabled blocklist's URL
        // still gets a trust lookup because the manager's mutate
        // helpers (`list_state` transitions, hypothetical `inspect`
        // verb) may legitimately ask about a list the operator has
        // toggled off. Disabled rows don't reach the fetch path
        // (`merge_sources_with_blocklists` skips them when building
        // `sources`), so the disabled entry's URL is unreachable from
        // the manager's download loop regardless.
        let blocklists = vec![{
            let mut b = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", false);
            b.trust = BlocklistTrust::Local;
            b
        }];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
            Some(BlocklistTrust::Local),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(BlocklistTrust::Local),
        );
    }

    #[test]
    fn trust_for_url_returns_none_when_passed_a_v1_id_string() {
        // Symmetric to `bit_for_url_returns_none_for_unknown_url` —
        // proves the typed contract at the lookup line: passing a
        // kebab-form `Id::as_str()` into `trust_for_url` does not
        // accidentally hit a legacy slash-translation fallback.
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::Signed,
        )];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(map.trust_for_url("privacy-ads"), None);
        assert_eq!(map.trust_for_url("privacy/ads"), None);
    }

    #[test]
    fn trust_for_v1_id_returns_none_when_id_not_in_blocklists() {
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::Signed,
        )];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(
            map.trust_for_v1_id(&Id::new("security-malicious").unwrap()),
            None,
        );
    }

    #[test]
    fn trust_map_url_trusts_accessor_matches_typed_lookup_byte_for_byte() {
        // `url_trusts()` is the legacy accessor for transition
        // consumers that still hold a `&HashMap<String, BlocklistTrust>`.
        // Phase 2 keeps it `pub` until no caller remains.
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::RemoteUnsigned,
        )];
        let map = SourceTrustMap::build(&blocklists);
        let raw = map.url_trusts();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw.get("https://lists.purge.cc/ads.txt").copied(),
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
        );
    }

    #[test]
    fn trust_map_empty_for_no_blocklists() {
        let map = SourceTrustMap::build(&[]);
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()), None,);
        assert_eq!(map.trust_for_url("https://lists.purge.cc/ads.txt"), None);
    }

    fn make_secrets_with(name: &str, value: &str) -> crate::config::secrets::Secrets {
        // Build a real `Secrets` via the public `load_secrets` path to
        // avoid leaning on private fields. Mirrors the pattern at
        // `cli::commands::start::tests::build_source_tokens_*`. Each
        // call gets a unique tempdir via a process-wide atomic counter
        // so concurrent test workers don't race on the same path
        // (`line!()` inside this helper is fixed, not per-caller).
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-stkn-{pid}-{n}"));
        fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("secrets.toml");
        {
            let mut f = fs::File::create(&sp).unwrap();
            writeln!(f, "{name} = \"{value}\"").unwrap();
        }
        let mut perm = fs::metadata(&sp).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&sp, perm).unwrap();
        let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
        let _ = fs::remove_dir_all(&dir);
        secrets
    }

    fn mk_blocklist_with_token_ref(id: &str, url: &str, token_ref: &str) -> Blocklist {
        let mut b = mk_blocklist(id, url, true);
        b.auth_token_ref = Some(token_ref.to_string());
        b
    }

    #[test]
    fn token_map_build_seeds_both_legacy_source_key_and_v1_id() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");

        let map = SourceTokenMap::build(&config, &secrets);
        // Legacy slash-form lookup — manager.rs:1032 byte-identical hit.
        assert_eq!(map.token_for_url("security/malicious"), Some("bearer-xyz"));
        // New typed v1-id lookup — symmetry with SourceBitMap /
        // SourceTrustMap.
        assert_eq!(
            map.token_for_v1_id(&Id::new("security-malicious").unwrap()),
            Some("bearer-xyz"),
        );
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
    }

    #[test]
    fn token_map_skips_blocklists_without_auth_token_ref() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        ));
        let secrets = make_secrets_with("ignored", "ignored");
        let map = SourceTokenMap::build(&config, &secrets);
        assert!(map.is_empty());
        assert_eq!(map.token_for_url("privacy/ads"), None);
        assert_eq!(map.token_for_v1_id(&Id::new("privacy-ads").unwrap()), None,);
    }

    #[test]
    fn token_map_skips_blocklists_with_missing_secret() {
        // Phase 2 preserves pre-existing behaviour: a `auth_token_ref`
        // pointing at a non-existent secret emits `tracing::warn!` and
        // the row is skipped (downloads anonymously, identical to
        // build_source_tokens pre-§4.24-P2).
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "missing-secret",
        ));
        let secrets = make_secrets_with("present-but-different", "ignored");
        let map = SourceTokenMap::build(&config, &secrets);
        assert!(map.is_empty());
        assert_eq!(
            map.token_for_v1_id(&Id::new("security-malicious").unwrap()),
            None,
        );
    }

    #[test]
    fn token_for_v1_id_returns_none_for_unknown_id() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");
        let map = SourceTokenMap::build(&config, &secrets);
        assert_eq!(
            map.token_for_v1_id(&Id::new("not-configured").unwrap()),
            None,
        );
    }

    #[test]
    fn token_map_url_tokens_accessor_matches_typed_lookup_byte_for_byte() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");
        let map = SourceTokenMap::build(&config, &secrets);
        let raw = map.url_tokens();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw.get("security/malicious").map(String::as_str),
            map.token_for_url("security/malicious"),
        );
    }

    #[test]
    fn debug_redacts_bearer_tokens() {
        // rev-2606 §06 source_key-01: the hand-written Debug must print
        // counts, never the secret values.
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "SUPER-SECRET-BEARER");
        let map = SourceTokenMap::build(&config, &secrets);
        // The token must actually be resolved, so the redaction is real.
        assert!(map
            .token_for_v1_id(&Id::new("security-malicious").unwrap())
            .is_some());
        let dbg = format!("{map:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-BEARER"),
            "Debug leaked a bearer token: {dbg}"
        );
        assert!(
            dbg.contains("tokens"),
            "Debug should summarise counts: {dbg}"
        );
    }

    // ── tag_model_consolidation §3.2 — canonical_url_key ─────────────

    #[test]
    fn tmc_canonical_key_lowercases_scheme_and_host_only() {
        assert_eq!(
            canonical_url_key("HTTPS://Lists.Purge.CC/Ads.txt"),
            "https://lists.purge.cc/Ads.txt",
            "path case is meaningful to the server and must survive",
        );
    }

    #[test]
    fn tmc_canonical_key_drops_default_ports_keeps_others() {
        assert_eq!(
            canonical_url_key("http://example.com:80/a.txt"),
            "http://example.com/a.txt",
        );
        assert_eq!(
            canonical_url_key("https://example.com:443/a.txt"),
            "https://example.com/a.txt",
        );
        // Wrong-scheme default port is NOT a default — keep it.
        assert_eq!(
            canonical_url_key("https://example.com:80/a.txt"),
            "https://example.com:80/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://example.com:8080/a.txt"),
            "http://example.com:8080/a.txt",
        );
    }

    #[test]
    fn tmc_canonical_key_drops_exactly_one_trailing_slash() {
        assert_eq!(
            canonical_url_key("https://example.com/list/"),
            canonical_url_key("https://example.com/list"),
        );
        // Bare host with and without the root slash are one source.
        assert_eq!(
            canonical_url_key("https://example.com/"),
            canonical_url_key("https://example.com"),
        );
        // Only ONE — a doubled slash is a different path.
        assert_eq!(
            canonical_url_key("https://example.com/list//"),
            "https://example.com/list/",
        );
    }

    #[test]
    fn tmc_canonical_key_leaves_query_and_fragment_alone() {
        // Trailing slash belongs to the path, not the query: stripping
        // must not reach past the `?`.
        assert_eq!(
            canonical_url_key("https://example.com/l/?v=2&a=1"),
            "https://example.com/l?v=2&a=1",
        );
        // Query order is meaningful to the server — do not sort.
        assert_ne!(
            canonical_url_key("https://example.com/l?a=1&v=2"),
            canonical_url_key("https://example.com/l?v=2&a=1"),
        );
        assert_eq!(
            canonical_url_key("https://example.com/l/#frag"),
            "https://example.com/l#frag",
        );
        // A `/` inside the query survives untouched.
        assert_eq!(
            canonical_url_key("https://example.com/l?path=a/"),
            "https://example.com/l?path=a/",
        );
    }

    #[test]
    fn tmc_canonical_key_handles_ipv6_literal_and_userinfo() {
        // Colons inside the brackets are not a port separator.
        assert_eq!(
            canonical_url_key("http://[2001:DB8::1]/a.txt"),
            "http://[2001:db8::1]/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://[2001:db8::1]:80/a.txt"),
            "http://[2001:db8::1]/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://[2001:db8::1]:8080/a.txt"),
            "http://[2001:db8::1]:8080/a.txt",
        );
        // Userinfo is a credential: host lowercases, the credential
        // does not, and two different credentials stay two keys.
        assert_eq!(
            canonical_url_key("https://User:Pw@Example.com/a.txt"),
            "https://User:Pw@example.com/a.txt",
        );
    }

    #[test]
    fn tmc_canonical_key_passes_through_unparseable_input() {
        // No `://` — refused elsewhere with a better message; rewriting
        // it here would only obscure the operator's typo.
        assert_eq!(canonical_url_key("not-a-url"), "not-a-url");
        assert_eq!(canonical_url_key(""), "");
    }

    #[test]
    fn tmc_canonical_key_is_idempotent() {
        for raw in [
            "HTTPS://Lists.Purge.CC:443/Ads.txt/",
            "http://example.com:80/",
            "https://a.example.com/l?x=1#f",
            "not-a-url",
        ] {
            let once = canonical_url_key(raw);
            assert_eq!(
                canonical_url_key(&once),
                once,
                "key must be a fixed point: {raw}",
            );
        }
    }

    /// The scheme contract, pinned at the seat rather than at N call
    /// sites. Widening it is a policy change; this test is what a
    /// widening has to argue with.
    #[test]
    fn is_url_source_accepts_only_the_two_lowercase_http_schemes() {
        for accepted in [
            "http://lists.purge.cc/ads.txt",
            "https://lists.purge.cc/ads.txt",
            "https://",
        ] {
            assert!(is_url_source(accepted), "must classify as URL: {accepted}");
        }
        for rejected in [
            // The legacy slash-form catalog ids the `else` branch exists for.
            "privacy/ads",
            "services/resolvers",
            // Case matters: uppercase is not a URL here.
            "HTTP://lists.purge.cc/ads.txt",
            "Https://lists.purge.cc/ads.txt",
            // Other schemes, including the one a local-import shortcut
            // would reach for.
            "ftp://lists.purge.cc/ads.txt",
            "file:///var/lib/purge-warden/lists/ads.txt",
            // Scheme-like text that does not start the string.
            " https://lists.purge.cc/ads.txt",
            "redirect?to=https://lists.purge.cc/ads.txt",
            "",
        ] {
            assert!(
                !is_url_source(rejected),
                "must NOT classify as URL: {rejected}"
            );
        }
    }

    /// Trip-wire: the CLI verbs that classify an operator-typed source
    /// must ask this function, not re-derive the scheme test inline.
    ///
    /// The predicate decides where warden fetches a blocklist from, so a
    /// copy that a scheme-policy change misses keeps enforcing the old
    /// rule with nothing going red. A hand-rolled copy compiles and
    /// passes every behavioural test on the day it is written — the only
    /// thing that can catch it is a reader, or this.
    ///
    /// The needle is assembled at run time so this test does not match
    /// itself.
    #[test]
    fn cli_source_classification_has_no_hand_rolled_copy() {
        let needle = format!("starts_with({:?})", "http://");
        for (path, src) in [
            (
                "src/cli/commands/lists.rs",
                include_str!("../cli/commands/lists.rs"),
            ),
            (
                "src/cli/commands/blocklists.rs",
                include_str!("../cli/commands/blocklists.rs"),
            ),
        ] {
            assert!(
                !src.contains(&needle),
                "{path} re-derives the URL-scheme test inline; call \
                 lists::source_key::is_url_source instead"
            );
        }
    }

    #[test]
    fn tmc_canonical_key_matches_the_live_ct_duplicate_pair() {
        // D3 on `.94`: `privacy-ads` and `ads` both point at
        // lists.purge.cc/ads.txt and were invisible to the byte-exact
        // gate that let them in.
        assert_eq!(
            canonical_url_key("https://lists.purge.cc/ads.txt"),
            canonical_url_key("https://lists.purge.cc/ads.txt/"),
        );
    }
}
