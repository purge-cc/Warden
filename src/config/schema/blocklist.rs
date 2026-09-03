//! [`Blocklist`] — external domain / rule list subscription.
//!
//! Each blocklist has a stable [`Id`] that profiles reference by name.

use serde::{Deserialize, Serialize};

use super::id::Id;
use super::profile::Profile;

/// Declared wire format of a subscribed list. `Adguard`/`Hosts` **force** the
/// matching parser; `Domains` — the default — defers
/// to content auto-detection (`src/lists/detector.rs`), which itself falls
/// back to domain-per-line. So an operator can override a misdetected list by
/// declaring its format, while rows that never set one keep auto-detecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// One domain per line, `#` comments. Matches the lists at
    /// `lists.purge.cc/*/*.txt`.
    #[default]
    Domains,
    /// AdGuard-style rules (`||domain^`, `@@||domain^`, modifiers).
    /// Matches `rules.purge.cc/*/*.txt`.
    Adguard,
    /// `/etc/hosts` style (`0.0.0.0 domain`, `127.0.0.1 domain`).
    Hosts,
}

/// The direction **every** profile inherits for this list unless it says
/// otherwise.
///
/// The default is [`BlocklistBase::Deny`] — the canonical block-direction
/// list. The engine honours [`BlocklistBase::Allow`] matches in a
/// dedicated evaluation step; admin `$important` deny stays sovereign,
/// so an allow-direction list cannot pierce an admin deny. The schema is
/// permissive about the combination here; the validator pass enforces
/// the trust/base compatibility rule.
///
/// **Why "base" and not "the default profile's direction".**
/// `[server].default_profile` is *optional* — with it unset, unresolved
/// clients land in REFUSED (`profiles/resolver.rs`, test
/// `level_5_refused_when_default_profile_unset`). Anchoring this to that
/// profile would make it mandatory, which is a resolver semantics change
/// this workstream does not own.
///
/// **Renamed from `BlocklistKind` / wire `kind`**, together
/// with the [`SCHEMA_VERSION_V1`](super::SCHEMA_VERSION_V1) bump to `3`.
/// No serde alias is provided, deliberately: a config accepted under
/// an alias would load with **no** `profiles.<id>.lists` overrides, so
/// every list would start applying to every profile — a silent verdict
/// change on exactly the configs the migration exists to convert. The
/// loader refuses a `kind` key by name instead
/// (`config/loader.rs`, `BLOCKLIST_KIND_RENAMED_TO_BASE`).
///
/// This has bitten before: an earlier rename (`Block` → `Deny`, wire
/// `kind = "block"` → `kind = "deny"`) missed the TUI's hand-rolled copy
/// of the token mapping, so every save was then refused at load with
/// `unknown variant` and the Lists modal could not write at all. That is
/// why [`Self::wire_str`] exists and why it is walked exhaustively by a
/// test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistBase {
    /// Default — list contributes domains to the deny side.
    #[default]
    Deny,
    /// List contributes domains to the allow side. On a source that is
    /// not [`BlocklistTrust::Local`] the operator must also set
    /// [`Blocklist::accept_unsigned_allow`], which declares the risk
    /// rather than removing it.
    Allow,
    /// The list is loaded, refreshed and counted, but contributes
    /// **neither** allow nor deny domains to any profile that does not
    /// override it.
    ///
    /// **Legitimate, never silent.** An earlier incident hit this exact
    /// shape: eight lists added, ~40 minutes of zero-blocking, no error
    /// and no warning, because an untagged list matched no device. The
    /// state stays because the operator asked for it; what is forbidden
    /// is the silence. The validator therefore emits
    /// [`BASE_IGNORE_LIST_IS_INERT`](super::validator::BASE_IGNORE_LIST_IS_INERT)
    /// at **every** load, naming the list.
    ///
    /// It is the global twin of [`ListPolicy::Ignore`], which says the
    /// same thing for one profile and is deliberately **not** warned
    /// about — a per-profile `ignore` is the narrow, reviewed form, and
    /// warning on it would teach operators to skim past the WARN that
    /// matters.
    Ignore,
}

/// Direction a **single profile** applies to a **single list**, overriding
/// that list's own [`Blocklist::base`] for that profile only.
///
/// This is the value half of [`Profile::lists`](super::profile::Profile::lists).
/// The effective direction for a `(profile, list)` pair is:
///
/// ```text
/// effective(profile, list) = profile.lists[list.id]   if present
///                          = list.base                otherwise
/// ```
///
/// **Why a separate type from [`BlocklistBase`].** They carry the same
/// vocabulary but not the same defaults or the same reach. `BlocklistBase`
/// is a property of the *list* and defaults to `Deny`; `ListPolicy` is a
/// property of the *(profile, list) pair* and has **no** default — its
/// absence from the map is what means "inherit", so a `Default` impl here
/// would invent a third way to spell inheritance and let a missing entry
/// read as an explicit direction. The concrete hazard is a future call
/// site spelling the lookup `profile.lists.get(&id).copied()
/// .unwrap_or_default()`, which compiles the moment a `Default` exists
/// and silently converts "inherit" into whichever variant is defaulted —
/// discarding the list's own `kind`. The absence is pinned below rather
/// than left to prose, because prose does not fail a build:
///
/// ```compile_fail
/// use purge_warden::config::schema::ListPolicy;
///
/// // error[E0599]: no function or associated item named `default` found
/// let _ = ListPolicy::default();
/// ```
///
/// A doctest compiles as a separate crate linking the lib, so this
/// observes the crate boundary only — which is enough here, since
/// `ListPolicy` is re-exported from `config::schema` and a `Default`
/// impl would be visible at exactly that boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListPolicy {
    /// This profile treats the list as a block-direction list, whatever
    /// the list's own `base` says.
    Deny,
    /// This profile treats the list as an allow-direction list. Carries
    /// the same bypass exposure as [`BlocklistBase::Allow`] — see
    /// [`Blocklist::accept_unsigned_allow`] — at profile scope rather
    /// than global scope.
    Allow,
    /// This profile ignores the list entirely: it contributes neither
    /// allow nor deny domains here. The list stays loaded and keeps
    /// applying to every other profile.
    Ignore,
}

impl ListPolicy {
    /// TOML token for this variant, per `#[serde(rename_all = "lowercase")]`.
    ///
    /// Exists for the same reason as [`BlocklistBase::wire_str`] — see
    /// that method's doc-comment for the incident. Walked exhaustively by
    /// `wire_str_round_trips_through_deserialize`.
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Ignore => "ignore",
        }
    }
}

/// The direction `profile` applies to `list` — the **one** place that rule
/// is written down.
///
/// ```text
/// effective(profile, list) = profile.lists[list.id]   if present
///                          = list.base                otherwise
/// ```
///
/// **One function, N callers, never a second copy.** A related field
/// (`effective_tags`) was once computed in two places that answered
/// differently: the validator saw a superset, and the "device not
/// filtered" WARN went silent on devices the resolver really did leave
/// uncovered — a **false negative on a security warning**. Every caller here
/// asks the same question: the publish-time projection
/// (`lists::source_key::SourceBitMap::project_policy`), the validator's
/// coverage WARN, `warden resolve`, and the `blocklist list` / `show`
/// enforcement report.
///
/// Says nothing about [`Blocklist::enabled`]. A disabled list never reaches
/// the merged sources vector, so it holds no bit and can produce no verdict;
/// callers that enumerate lists filter on `enabled` themselves rather than
/// having this function quietly conflate "the operator turned it off" with
/// "this profile ignores it".
#[must_use]
pub fn effective_direction(profile: &Profile, list: &Blocklist) -> ListPolicy {
    profile
        .lists
        .get(&list.id)
        .copied()
        .unwrap_or(list.base.as_policy())
}

/// Provenance / integrity guarantee on the source of a blocklist.
///
/// The default is [`BlocklistTrust::RemoteUnsigned`] so the existing
/// HTTPS lists at `lists.purge.cc` keep their current trust model.
/// [`BlocklistTrust::Local`] is a file authored by the operator on
/// disk, and is the only trust level that pairs with
/// [`BlocklistBase::Allow`] with nothing further to declare — a remote
/// unsigned allow-list is the canonical bypass vector, so it needs
/// [`Blocklist::accept_unsigned_allow`]. [`BlocklistTrust::Signed`] is
/// parked for a future signed-feed release; the validator refuses it
/// for now with a frozen string, consent or no consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BlocklistTrust {
    /// File on disk authored / vetted by the operator.
    Local,
    /// Future signed-feed support. Validator currently rejects this
    /// variant with `TRUST_SIGNED_NOT_YET_SUPPORTED`.
    Signed,
    /// Default — fetched over HTTPS with no integrity guarantee beyond
    /// TLS. Unremarkable for `base = deny` (the existing model); for
    /// `base = allow` it needs [`Blocklist::accept_unsigned_allow`],
    /// because TLS authenticates the *server*, not the *content*, and
    /// an allow-list's content is what decides the unblocking.
    #[default]
    RemoteUnsigned,
}

/// The exact token each variant occupies in a TOML config file.
///
/// **Why these exist.** Serde already owns this mapping via the
/// `rename_all` attributes above, but that knowledge is only reachable
/// through a `Serializer`. Call sites that assemble a config row by hand —
/// the TUI's Lists modal, the CLI's `blocklist set-kind` — used to
/// re-declare the mapping in a local `match`, which is a second source of
/// truth for a value that has already been renamed once (`Block` → `Deny`,
/// wire `"block"` → `"deny"`, no alias). The TUI's copy was missed by that
/// rename and kept writing `kind = "block"`, so every save was refused at
/// load with `unknown variant` and the Lists modal could not write at all.
///
/// `wire_str` moves the token back onto the type. The unit test
/// `wire_str_round_trips_through_deserialize` walks every variant and
/// proves the token it returns deserialises back to the same variant, so a
/// future rename that forgets one of these fails the suite instead of
/// bricking a surface.
impl BlocklistBase {
    /// The [`ListPolicy`] a profile inherits when it does **not** override
    /// this list.
    ///
    /// **The whole point is that there is exactly one of these** — one
    /// function, N callers, never a second copy. A related field
    /// (`effective_tags`) was once computed in two places that answered
    /// differently, so the validator saw a superset and the "device not
    /// filtered" WARN went silent on devices the resolver really did
    /// leave uncovered. A false negative on a security warning.
    ///
    /// Two callers exist today and both are the inheritance rule:
    /// [`effective_direction`]'s fallback arm, and the base-mask loop in
    /// `lists::source_key::SourceBitMap::project_policy`. A third variant
    /// (`Ignore`) landed after both were written; because the mapping is
    /// here and not spelled out at each site, adding it was a compile
    /// error at one place instead of a silent default at two.
    #[must_use]
    pub const fn as_policy(self) -> ListPolicy {
        match self {
            Self::Deny => ListPolicy::Deny,
            Self::Allow => ListPolicy::Allow,
            Self::Ignore => ListPolicy::Ignore,
        }
    }

    /// TOML token for this variant, per `#[serde(rename_all = "lowercase")]`.
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Ignore => "ignore",
        }
    }
}

impl BlocklistFormat {
    /// TOML token for this variant, per `#[serde(rename_all = "lowercase")]`.
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Domains => "domains",
            Self::Adguard => "adguard",
            Self::Hosts => "hosts",
        }
    }
}

impl BlocklistTrust {
    /// TOML token for this variant, per `#[serde(rename_all = "kebab-case")]`.
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Signed => "signed",
            Self::RemoteUnsigned => "remote-unsigned",
        }
    }
}

fn default_update_interval_hours() -> u32 {
    12
}

/// Per-`[[blocklists]]` entry cap. Must stay in step with
/// [`crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES`] and
/// `settings::default_max_list_entries` — see the former for the measured
/// rationale behind 20M (largest real list 9.03M). Sized against list
/// size alone, with no merged-map doubling-cliff constraint entangled.
///
/// This value is validated and stored on every `[[blocklists]]` entry,
/// but not enforced — only the global `[lists] max_entries` reaches the
/// parser.
///
/// A cap sized too low silently drops list content: a 5M cap once sat
/// *below* four of the eight live sources, so the daemon silently
/// dropped 19% of the corpus.
fn default_max_entries() -> u64 {
    20_000_000
}

fn default_enabled() -> bool {
    true
}

/// ```toml
/// [[blocklists]]
/// id = "privacy-ads"
/// display_name = "Privacy: Ads"
/// url = "https://lists.purge.cc/privacy/ads.txt"
/// format = "domains"
/// update_interval_hours = 12
/// max_entries = 5000000
/// enabled = true
/// auth_token_ref = "privacy-ads-token"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Blocklist {
    pub id: Id,
    pub display_name: String,
    /// Fetched over HTTP(S). Protocol validated at load time.
    pub url: String,
    #[serde(default)]
    pub format: BlocklistFormat,
    #[serde(
        default = "default_update_interval_hours",
        alias = "refresh_interval_hours"
    )]
    pub update_interval_hours: u32,
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional key in `secrets.toml` that holds the Authorization bearer
    /// token for authenticated private lists. Resolved at fetch time,
    /// not at schema load.
    #[serde(default)]
    pub auth_token_ref: Option<String>,
    /// The direction **every** profile inherits for this list
    /// unless `profiles.<id>.lists` overrides it. Defaults to
    /// [`BlocklistBase::Deny`]. The engine honours `Allow`-direction
    /// matches in a dedicated evaluation step; `Ignore` makes the
    /// list inert everywhere and is WARNed about at every load.
    ///
    /// Wire name `base` — `kind` in schema_version 2 and earlier.
    /// **No serde alias**: see [`BlocklistBase`] for why an alias would
    /// be a silent verdict change rather than a kindness.
    #[serde(default)]
    pub base: BlocklistBase,
    /// Provenance / integrity. Defaults to
    /// [`BlocklistTrust::RemoteUnsigned`] for the HTTPS list model.
    /// Pairing `base = Allow` with a non-`Local` trust requires
    /// [`Blocklist::accept_unsigned_allow`]; without it the validator
    /// refuses the list with the frozen string
    /// `UNSIGNED_ALLOW_LIST_REQUIRES_ACK`.
    #[serde(default)]
    pub trust: BlocklistTrust,
    /// The operator's explicit acceptance of the risk carried by an
    /// allow-direction list fetched from a remote URL without an
    /// integrity guarantee.
    ///
    /// **What you are accepting.** An allow-direction list wins over
    /// every deny-direction list, so whoever controls this URL decides
    /// which domains warden stops blocking. They can add a domain at
    /// any refresh — the default cadence is every 12 hours — and
    /// nothing reviews the change: no signature, no diff, no prompt.
    /// A publisher who is honest today, is compromised tomorrow, or
    /// simply sells the domain, silently inherits that power. The
    /// blast radius is every device the list's tags reach.
    ///
    /// The risk is not removed by setting this flag, only declared.
    /// It stays visible in the operator's own TOML, and the validator
    /// keeps emitting a WARN at every load so it cannot be forgotten
    /// once set.
    ///
    /// **What it does not do.** The allow direction stays *soft*: it
    /// does not pierce `block_all`, and it never beats an admin
    /// `$important` deny rule. The operator's own config remains
    /// sovereign over any list.
    ///
    /// Ignored unless `base = allow` and `trust` is not `local` — a
    /// local file is authored by the operator, so there is no third
    /// party to trust and no risk to accept. Leave it `false` and
    /// import the file with `warden blocklist import-local` if you
    /// would rather own the content than subscribe to it.
    #[serde(default)]
    pub accept_unsigned_allow: bool,
    /// How many consecutive refresh failures the manager tolerates
    /// before the list flips to
    /// [`crate::config::list_state::ListStatus::Failed`]. Default 5.
    /// With the default 12h `update_interval_hours`, this is ~2.5 days
    /// before the list is declared Failed.
    ///
    /// **Stale-cache fallback.** A list that has succeeded at
    /// least once keeps its cache after flipping to Failed; the
    /// resolver continues to apply the stale bytes (badge red but
    /// filtering active). A list that never succeeded ends up with
    /// `cache_path = None` after the same flip and contributes
    /// nothing.
    ///
    /// Configurable per list via `[blocklists.<id>].max_consecutive_failures`.
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,
}

fn default_max_consecutive_failures() -> u32 {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `wire_str` token must deserialise back to the variant that
    /// produced it — the guard against a hand-rolled TUI/CLI token
    /// mapping drifting from the serde one (see [`BlocklistBase`]).
    ///
    /// Both directions are checked deliberately. Asserting only that the
    /// token *parses* would pass if two variants collapsed onto one token;
    /// asserting the resulting variant is the original catches that too.
    /// The lists are exhaustive by hand — a new variant added without a
    /// `wire_str` arm already fails to compile, and one added here without
    /// a serde rename fails this test.
    #[test]
    fn wire_str_round_trips_through_deserialize() {
        for k in [
            BlocklistBase::Deny,
            BlocklistBase::Allow,
            BlocklistBase::Ignore,
        ] {
            let parsed: BlocklistBase = toml::from_str(&format!("v = \"{}\"", k.wire_str()))
                .map(|w: WireProbe<_>| w.v)
                .unwrap_or_else(|e| {
                    panic!("kind {k:?} token {:?} is unreadable: {e}", k.wire_str())
                });
            assert_eq!(
                parsed,
                k,
                "kind token {:?} decoded to the wrong variant",
                k.wire_str()
            );
        }
        for f in [
            BlocklistFormat::Domains,
            BlocklistFormat::Adguard,
            BlocklistFormat::Hosts,
        ] {
            let parsed: BlocklistFormat = toml::from_str(&format!("v = \"{}\"", f.wire_str()))
                .map(|w: WireProbe<_>| w.v)
                .unwrap_or_else(|e| {
                    panic!("format {f:?} token {:?} is unreadable: {e}", f.wire_str())
                });
            assert_eq!(
                parsed,
                f,
                "format token {:?} decoded to the wrong variant",
                f.wire_str()
            );
        }
        for p in [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore] {
            let parsed: ListPolicy = toml::from_str(&format!("v = \"{}\"", p.wire_str()))
                .map(|w: WireProbe<_>| w.v)
                .unwrap_or_else(|e| {
                    panic!("policy {p:?} token {:?} is unreadable: {e}", p.wire_str())
                });
            assert_eq!(
                parsed,
                p,
                "policy token {:?} decoded to the wrong variant",
                p.wire_str()
            );
        }
        for t in [
            BlocklistTrust::Local,
            BlocklistTrust::Signed,
            BlocklistTrust::RemoteUnsigned,
        ] {
            let parsed: BlocklistTrust = toml::from_str(&format!("v = \"{}\"", t.wire_str()))
                .map(|w: WireProbe<_>| w.v)
                .unwrap_or_else(|e| {
                    panic!("trust {t:?} token {:?} is unreadable: {e}", t.wire_str())
                });
            assert_eq!(
                parsed,
                t,
                "trust token {:?} decoded to the wrong variant",
                t.wire_str()
            );
        }
    }

    /// Wrapper so a bare enum token can be fed through `toml::from_str`,
    /// which needs a table at the document root.
    #[derive(Deserialize)]
    struct WireProbe<T> {
        v: T,
    }

    #[test]
    fn minimal_blocklist_deserialises() {
        let toml_src = r#"
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.id.as_str(), "privacy-ads");
        assert_eq!(b.format, BlocklistFormat::Domains);
        assert_eq!(b.update_interval_hours, 12);
        // Must track `default_max_entries` — if you are here because
        // this failed, size the new value against the largest real
        // list plus headroom. A cap sized too low silently drops list
        // content (see `default_max_entries` doc).
        assert_eq!(b.max_entries, 20_000_000);
        assert!(b.enabled);
        assert!(b.auth_token_ref.is_none());
    }

    #[test]
    fn full_blocklist_deserialises() {
        let toml_src = r#"
id = "corp-custom"
display_name = "Corp: custom list"
url = "https://dl.corp.example/lists/custom.txt"
format = "adguard"
update_interval_hours = 1
max_entries = 2000000
enabled = false
auth_token_ref = "corp-custom-token"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.format, BlocklistFormat::Adguard);
        assert_eq!(b.update_interval_hours, 1);
        assert_eq!(b.max_entries, 2_000_000);
        assert!(!b.enabled);
        assert_eq!(b.auth_token_ref.as_deref(), Some("corp-custom-token"));
    }

    #[test]
    fn unknown_field_rejected() {
        let toml_src = r#"
id = "priv-ads"
display_name = "X"
url = "https://example.com/x.txt"
made_up_field = 42
"#;
        let err = toml::from_str::<Blocklist>(toml_src).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn invalid_id_rejected() {
        let toml_src = r#"
id = "Priv Ads"
display_name = "X"
url = "https://example.com/x.txt"
"#;
        let err = toml::from_str::<Blocklist>(toml_src).unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn format_parses_all_variants() {
        for (raw, expected) in [
            ("\"domains\"", BlocklistFormat::Domains),
            ("\"adguard\"", BlocklistFormat::Adguard),
            ("\"hosts\"", BlocklistFormat::Hosts),
        ] {
            let f: BlocklistFormat = toml::from_str(&format!("x = {raw}"))
                .map(|w: toml::Value| {
                    let s = w.get("x").unwrap().as_str().unwrap();
                    match s {
                        "domains" => BlocklistFormat::Domains,
                        "adguard" => BlocklistFormat::Adguard,
                        "hosts" => BlocklistFormat::Hosts,
                        _ => unreachable!(),
                    }
                })
                .unwrap();
            assert_eq!(f, expected);
        }
    }

    #[test]
    fn legacy_refresh_interval_hours_aliases_to_update_interval_hours() {
        // Operator configs with the pre-rename key still deserialise
        // into the canonical `update_interval_hours` field via
        // `#[serde(alias)]`. The loader emits the deprecation WARN
        // separately (see `src/config/loader/tests.rs`); this test
        // pins the struct-level alias so raw `toml::from_str` paths
        // also honour retro-compat.
        let toml_src = r#"
id = "legacy-fixture"
display_name = "Legacy Alias"
url = "https://example.com/lst.txt"
refresh_interval_hours = 6
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.update_interval_hours, 6);
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let b = Blocklist {
            id: Id::new("priv-track").unwrap(),
            display_name: "Privacy: Tracking".into(),
            url: "https://lists.purge.cc/privacy/tracking.txt".into(),
            format: BlocklistFormat::Domains,
            update_interval_hours: 6,
            max_entries: 1_000_000,
            enabled: true,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        };
        let s = toml::to_string(&b).unwrap();
        let back: Blocklist = toml::from_str(&s).unwrap();
        assert_eq!(back, b);
    }

    /// `accept_unsigned_allow` carries **no**
    /// `skip_serializing_if` — the struct has none and the symmetry is
    /// deliberate. So every serialised `Blocklist` grows one line for
    /// it, including lists that never opted in. Pinned because any writer
    /// that round-trips a config through `toml::to_string` (backup,
    /// cluster policy, `import-local`) emits it from now on, and a
    /// later "tidy-up" adding `skip_serializing_if` would silently
    /// change what lands in the operator's file.
    #[test]
    fn accept_unsigned_allow_is_always_serialised_even_when_false() {
        let b: Blocklist = toml::from_str(
            r#"
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
"#,
        )
        .unwrap();
        let s = toml::to_string(&b).unwrap();
        assert!(
            s.contains("accept_unsigned_allow = false"),
            "expected the field on the wire even at its default, got:\n{s}"
        );
    }

    // ── kind / trust / category fields ──

    /// A blocklist with no `kind` / `trust` / `tags` fields uses the
    /// documented defaults. (The third field was previously named
    /// `category`.)
    #[test]
    fn s49_minimal_blocklist_uses_documented_defaults() {
        let toml_src = r#"
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.base, BlocklistBase::Deny);
        assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);
    }

    /// NOTE ON THE URL: `file://` is not a supported source scheme —
    /// `config::validator` rejects anything that is not `http(s)://`, so
    /// a URL using it would parse here and then fail to load. This test
    /// is about `kind` / `trust` deserialising, and its URL should not
    /// imply a capability the validator refuses.
    ///
    /// An operator-authored local list uses the `imported.local` bridge
    /// (`warden blocklist import-local`), which resolves to
    /// `<config_dir>/lists/<id>.<ext>` and carries the trust check.
    /// Widening the validator to real `file://` URLs would route around
    /// that check, so it is deliberately not done here.
    /// `s49_file_url_is_rejected_by_the_validator` pins the refusal.
    #[test]
    fn s49_kind_allow_deserialises() {
        let toml_src = r#"
id = "trusted-internal"
display_name = "Trusted internal"
url = "https://imported.local/trusted.txt"
base = "allow"
trust = "local"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.base, BlocklistBase::Allow);
        assert_eq!(b.trust, BlocklistTrust::Local);
    }

    #[test]
    fn s49_trust_remote_unsigned_uses_kebab_case() {
        // `RemoteUnsigned` serialises to `remote-unsigned` because the
        // enum carries `#[serde(rename_all = "kebab-case")]`. Pinning
        // this here avoids a future format-rename slipping through.
        let toml_src = r#"
id = "remote-list"
display_name = "Remote"
url = "https://example.com/list.txt"
trust = "remote-unsigned"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);

        let serialised = toml::to_string(&b).unwrap();
        assert!(
            serialised.contains("trust = \"remote-unsigned\""),
            "expected kebab-case on the wire, got:\n{serialised}"
        );
    }

    /// `category = "..."` is no longer a recognised field and is
    /// refused via `#[serde(deny_unknown_fields)]`. `migrate.rs`
    /// handles the rename for existing on-disk configs.
    #[test]
    fn lc2_legacy_category_field_rejected() {
        let toml_src = r#"
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
category = "default"
"#;
        let err = toml::from_str::<Blocklist>(toml_src).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn s49_unknown_kind_variant_rejected() {
        let toml_src = r#"
id = "x"
display_name = "X"
url = "https://example.com/x.txt"
base = "redirect"
"#;
        let err = toml::from_str::<Blocklist>(toml_src).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn s49_unknown_trust_variant_rejected() {
        let toml_src = r#"
id = "x"
display_name = "X"
url = "https://example.com/x.txt"
trust = "vendor-signed"
"#;
        let err = toml::from_str::<Blocklist>(toml_src).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn s49_kind_default_via_rust_api() {
        assert_eq!(BlocklistBase::default(), BlocklistBase::Deny);
    }

    #[test]
    fn s49_trust_default_via_rust_api() {
        assert_eq!(BlocklistTrust::default(), BlocklistTrust::RemoteUnsigned);
    }

    /// Wire format is `base = "deny"` (not `"block"`). Pin the
    /// spelling to catch silent rewrites.
    #[test]
    fn lc2_kind_deny_wire_format_pinned() {
        let b: Blocklist = toml::from_str(
            r#"
id = "x"
display_name = "X"
url = "https://example.com/x.txt"
base = "deny"
"#,
        )
        .unwrap();
        assert_eq!(b.base, BlocklistBase::Deny);

        let serialised = toml::to_string(&b).unwrap();
        assert!(
            serialised.contains("base = \"deny\""),
            "expected base = \"deny\" on the wire, got:\n{serialised}"
        );
    }

    // ── per-list consent for remote allow-lists ──

    /// The operator's explicit acceptance of the remote-allow-list risk
    /// deserialises from the wire under its own name. Until the field
    /// exists this fails on `deny_unknown_fields` with `unknown field`.
    #[test]
    fn accept_unsigned_allow_deserialises() {
        let toml_src = r#"
id = "vendor-allow"
display_name = "Vendor allow"
url = "https://lists.example.com/allow.txt"
base = "allow"
trust = "remote-unsigned"
accept_unsigned_allow = true
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert!(b.accept_unsigned_allow);
    }

    /// The whole point of the default: a config written before this
    /// field existed must deserialise unchanged, and must NOT be read
    /// as having accepted anything.
    #[test]
    fn accept_unsigned_allow_defaults_to_false_when_absent() {
        let toml_src = r#"
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
"#;
        let b: Blocklist = toml::from_str(toml_src).unwrap();
        assert!(
            !b.accept_unsigned_allow,
            "absent field must never read as consent"
        );
    }

    /// Legacy `base = "block"` is no longer accepted.
    #[test]
    fn lc2_legacy_kind_block_rejected() {
        let err = toml::from_str::<Blocklist>(
            r#"
id = "x"
display_name = "X"
url = "https://example.com/x.txt"
base = "block"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }
}
