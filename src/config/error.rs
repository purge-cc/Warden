//! Structured error type for the v1 configuration pipeline.
//!
//! Every failure mode of the schema / loader / validator produces a
//! [`ConfigError`] that carries enough context for the operator to fix the
//! problem without grepping the codebase: the offending file + line when
//! known, the entity id that triggered the failure, a human-readable
//! reason, and an optional suggestion for the most common fix.
//!
//! The legacy `Vec<String>` validator in `config/validator.rs` (schema v0)
//! is untouched; the v1 surface uses this type exclusively.

use std::fmt;
use std::path::PathBuf;

/// Common context attached to every [`ConfigError`] variant.
///
/// Every config failure carries the
/// tuple `(file, line, entity, reason, suggestion)`. Sharing the payload
/// across variants keeps the variants themselves categorical (Parse vs
/// DuplicateId vs CrossRefMiss …) without duplicating five fields per
/// branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorContext {
    /// The file the problem was located in, when known. `None` for
    /// synthetic or in-memory configs built by tests.
    pub file: Option<PathBuf>,
    /// Line number inside [`file`](Self::file), 1-based. `None` when the
    /// underlying error source (e.g. toml crate) did not surface a span.
    pub line: Option<usize>,
    /// The entity `id` (or section name) whose definition triggered the
    /// error, e.g. `"devices.operator-iphone-01"` or `"profiles.default"`.
    pub entity: Option<String>,
    /// Human-readable description of what is wrong. Required.
    pub reason: String,
    /// Optional hint pointing the operator at the fix, e.g.
    /// `"remove the duplicate block or change its id"`.
    pub suggestion: Option<String>,
}

impl ErrorContext {
    /// Build a context with only a `reason`. Use the `with_*` builders to
    /// decorate further.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            file: None,
            line: None,
            entity: None,
            reason: reason.into(),
            suggestion: None,
        }
    }

    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    pub fn with_entity(mut self, entity: impl Into<String>) -> Self {
        self.entity = Some(entity.into());
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

impl fmt::Display for ErrorContext {
    /// Format: `<reason> [at <file>[:<line>]] [for <entity>]. suggestion: <s>`
    ///
    /// All decorations are optional; only `reason` is guaranteed to print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)?;
        if let Some(file) = &self.file {
            write!(f, " at {}", file.display())?;
            if let Some(line) = self.line {
                write!(f, ":{line}")?;
            }
        }
        if let Some(entity) = &self.entity {
            write!(f, " for {entity}")?;
        }
        if let Some(s) = &self.suggestion {
            write!(f, ". suggestion: {s}")?;
        }
        Ok(())
    }
}

/// All failure modes of the v1 configuration pipeline.
///
/// Variant rationale not obvious from the name alone:
///
/// - [`ConfigError::InvalidId`] — an id string failed the [`super::schema::id::Id`]
///   character / length invariants ("id is the stable cross-reference key;
///   lowercase-ascii-dashes-only"). Separated from
///   `UnknownField` because the repair is different (fix the id string, not
///   the schema).
/// - [`ConfigError::IdRecentlyRetired`] — an id in the
///   retired-ids window (<90 days) cannot be reused. Separated from
///   `DuplicateId` because the conflict is temporal, not spatial.
/// - [`ConfigError::ValidationFailed`] — catch-all for semantic violations
///   that are not cross-reference misses (e.g. an empty `cidrs` array on a
///   subnet, a schedule with `target_type` but no `target_id`).
/// - [`ConfigError::UnsignedAllowListRequiresAck`] — a consent
///   gate rather than a categorical one: `base = allow` on a list that is
///   not `trust = local` is refused **unless** the operator declared
///   `accept_unsigned_allow = true` on that list. The bypass risk is
///   unchanged — whoever controls the URL decides what stops being
///   blocked — but it is now accepted explicitly and visibly instead of
///   being forbidden outright.
/// - [`ConfigError::TrustSignedNotYetSupported`] — `trust = signed` is
///   parked for a future signed-feed release; the validator refuses
///   it now so an operator does not deploy a config that the daemon will
///   silently downgrade.
/// - [`ConfigError::InvalidTagSlug`] — a tag slug failed the
///   `TagSlug` regex `^[a-z][a-z0-9-]{0,31}$` or
///   length bound. Separated from `InvalidId` because the charset is
///   stricter (must start with `[a-z]`) and the length budget is shorter
///   (32 vs 64).
///
/// All variants carry an [`ErrorContext`] (matching every existing variant)
/// rather than struct-style fields — the structured payload (offending
/// id, source kind, observed trust level) lives inside
/// `ErrorContext::entity` and `ErrorContext::reason`, keeping the
/// `context()` accessor uniform across variants.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// TOML syntax / type error surfaced by the `toml` crate.
    #[error("parse error: {0}")]
    Parse(ErrorContext),

    /// A required field is missing on an entity where serde would normally
    /// default it, but the schema requires an explicit choice from the
    /// operator (e.g. `schema_version`).
    #[error("missing required field: {0}")]
    MissingRequired(ErrorContext),

    /// An unknown field appeared on a struct marked
    /// `#[serde(deny_unknown_fields)]`. Almost always a typo.
    #[error("unknown field: {0}")]
    UnknownField(ErrorContext),

    /// A *known* field carried a value outside its enum's variant set —
    /// serde's `unknown variant`. Split out of [`ConfigError::UnknownField`]
    /// because the two point the operator in opposite directions: an
    /// unknown field means "this key does not exist, check the spelling of
    /// the key", an unknown variant means "the key is fine, the value is
    /// not — here are the values it accepts". Reporting the second as the
    /// first sent a real investigation hunting a phantom typo'd key for
    /// hours while a mis-serialised `kind = "block"` sat in plain sight
    /// (`s-tui-lists-edit-save-rejected`).
    #[error("unknown value: {0}")]
    UnknownVariant(ErrorContext),

    /// Two entities of the same type share the same id.
    #[error("duplicate id: {0}")]
    DuplicateId(ErrorContext),

    /// An entity references an id of another entity type that does not
    /// exist (e.g. `device.profile = "family"` but no profile with id
    /// `"family"` is defined).
    #[error("cross-reference miss: {0}")]
    CrossRefMiss(ErrorContext),

    /// The `schema_version` declared in the master config is not
    /// supported by this binary.
    #[error("schema version mismatch: {0}")]
    VersionMismatch(ErrorContext),

    /// An id string fails the ascii-lowercase-dashes charset or the 1..=64
    /// length bound. Carries the offending string in `ErrorContext::reason`.
    #[error("invalid id: {0}")]
    InvalidId(ErrorContext),

    /// An id that was retired less than 90 days ago cannot be reused.
    /// `ErrorContext::entity` carries the id; `reason` carries the
    /// `retired_at` timestamp.
    #[error("id retired recently: {0}")]
    IdRecentlyRetired(ErrorContext),

    /// A blocklist with `base = allow` whose `trust` is not
    /// `local` has not declared `accept_unsigned_allow = true`.
    /// `ErrorContext::entity` carries the offending blocklist id;
    /// `reason` includes the actual trust level seen.
    #[error("unsigned allow-list needs accept_unsigned_allow: {0}")]
    UnsignedAllowListRequiresAck(ErrorContext),

    /// A blocklist declares `trust = signed`, which is parked for
    /// a future signed-feed release.
    #[error("trust=signed not yet supported: {0}")]
    TrustSignedNotYetSupported(ErrorContext),

    /// A tag slug failed the
    /// `TagSlug` regex `^[a-z][a-z0-9-]{{0,31}}$`
    /// or length bound. Carries the offending string in
    /// `ErrorContext::reason`. Separated from
    /// [`ConfigError::InvalidId`] because the regex is stricter (must
    /// start with `[a-z]`) and the length budget is shorter (32 vs 64).
    #[error("invalid tag slug: {0}")]
    InvalidTagSlug(ErrorContext),

    /// Any other semantic validation failure not covered by the categories
    /// above.
    #[error("validation failed: {0}")]
    ValidationFailed(ErrorContext),
}

impl ConfigError {
    /// Access the inner [`ErrorContext`] regardless of the variant.
    pub fn context(&self) -> &ErrorContext {
        match self {
            Self::Parse(c)
            | Self::MissingRequired(c)
            | Self::UnknownField(c)
            | Self::UnknownVariant(c)
            | Self::DuplicateId(c)
            | Self::CrossRefMiss(c)
            | Self::VersionMismatch(c)
            | Self::InvalidId(c)
            | Self::IdRecentlyRetired(c)
            | Self::UnsignedAllowListRequiresAck(c)
            | Self::TrustSignedNotYetSupported(c)
            | Self::InvalidTagSlug(c)
            | Self::ValidationFailed(c) => c,
        }
    }

    /// Mutably access the inner [`ErrorContext`] regardless of the variant.
    /// Mirrors [`ConfigError::context`] so callers that need to decorate an
    /// error in flight (e.g. `attach_file`) do not have to open-code a
    /// per-variant match.
    pub fn context_mut(&mut self) -> &mut ErrorContext {
        match self {
            Self::Parse(c)
            | Self::MissingRequired(c)
            | Self::UnknownField(c)
            | Self::UnknownVariant(c)
            | Self::DuplicateId(c)
            | Self::CrossRefMiss(c)
            | Self::VersionMismatch(c)
            | Self::InvalidId(c)
            | Self::IdRecentlyRetired(c)
            | Self::UnsignedAllowListRequiresAck(c)
            | Self::TrustSignedNotYetSupported(c)
            | Self::InvalidTagSlug(c)
            | Self::ValidationFailed(c) => c,
        }
    }

    /// Short label for the variant (`"parse"`, `"duplicate_id"`, …) suitable
    /// for machine-readable output (JSON, lint tooling).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Parse(_) => "parse",
            Self::MissingRequired(_) => "missing_required",
            Self::UnknownField(_) => "unknown_field",
            Self::UnknownVariant(_) => "unknown_variant",
            Self::DuplicateId(_) => "duplicate_id",
            Self::CrossRefMiss(_) => "cross_ref_miss",
            Self::VersionMismatch(_) => "version_mismatch",
            Self::InvalidId(_) => "invalid_id",
            Self::IdRecentlyRetired(_) => "id_recently_retired",
            Self::UnsignedAllowListRequiresAck(_) => "unsigned_allow_list_requires_ack",
            Self::TrustSignedNotYetSupported(_) => "trust_signed_not_yet_supported",
            Self::InvalidTagSlug(_) => "invalid_tag_slug",
            Self::ValidationFailed(_) => "validation_failed",
        }
    }
}

/// Truncate an operator-supplied string for safe embedding in an error
/// message. An over-long id, or a toml Display excerpt of a
/// multi-MB single-line config, would otherwise put an unbounded amount of
/// user input into [`ErrorContext::reason`], which then flows into logs /
/// IPC / the TUI. Cuts on a char boundary at ~256 bytes and appends a
/// marker carrying the true length.
pub(crate) fn truncate_for_error(s: &str) -> std::borrow::Cow<'_, str> {
    const MAX: usize = 256;
    if s.len() <= MAX {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut end = MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!(
        "{}…(truncated, {} bytes total)",
        &s[..end],
        s.len()
    ))
}

/// Drop every backtick- or double-quote-delimited span from a message,
/// keeping only the unquoted "skeleton". toml and our own validators wrap
/// the offending USER value in `` `…` `` / `"…"`, so the skeleton holds the
/// diagnostic's structural prose and none of the operator's content.
fn unquoted_skeleton(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut in_backtick = false;
    let mut in_quote = false;
    for c in msg.chars() {
        match c {
            '`' if !in_quote => in_backtick = !in_backtick,
            '"' if !in_backtick => in_quote = !in_quote,
            _ if in_backtick || in_quote => {}
            _ => out.push(c),
        }
    }
    out
}

/// Shared classifier: map a toml / deserialise error `msg` to
/// the most specific [`ConfigError`] variant, applying `ctx`. Both the
/// single-file (`schema::load`) and merged (`loader`) paths route here so
/// the substring ladder can't drift between them.
///
/// Matching runs against [`unquoted_skeleton`] — the message with quoted
/// user content stripped — so an operator value like `"see unknown field
/// docs"` can't flip the classification (the `kind()` tag is machine-read
/// by tooling). The `"tag slug"` arm precedes `InvalidId`: `TagSlug` shares
/// wording with `Id` ("cannot be empty", "bytes (max", "invalid
/// character"), so the more-specific match must win.
pub(crate) fn classify_config_error(msg: &str, ctx: ErrorContext) -> ConfigError {
    let skel = unquoted_skeleton(msg);
    // `unknown variant` before `unknown field`: they are distinct repairs
    // (fix the value vs fix the key) and collapsing the first onto the
    // second told the operator to hunt a typo'd key that did not exist.
    if skel.contains("unknown variant") {
        ConfigError::UnknownVariant(ctx)
    } else if skel.contains("unknown field") {
        ConfigError::UnknownField(ctx)
    } else if skel.contains("missing field") {
        ConfigError::MissingRequired(ctx)
    } else if skel.contains("tag slug") {
        ConfigError::InvalidTagSlug(ctx)
    } else if skel.contains("invalid character")
        || skel.contains("cannot be empty")
        || skel.contains("cannot start or end with a dash")
        || skel.contains("bytes (max")
    {
        ConfigError::InvalidId(ctx)
    } else {
        ConfigError::Parse(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_display_bare_reason() {
        let c = ErrorContext::new("boom");
        assert_eq!(c.to_string(), "boom");
    }

    #[test]
    fn truncate_for_error_bounds_long_input() {
        assert_eq!(truncate_for_error("abc").as_ref(), "abc");
        let long = "x".repeat(10_000);
        let t = truncate_for_error(&long);
        assert!(t.len() < 400, "truncated len {}", t.len());
        assert!(t.contains("truncated, 10000 bytes total"), "got {t}");
    }

    #[test]
    fn classify_masks_quoted_user_content() {
        // A higher-priority keyword inside a QUOTED user value must
        // not flip the classification — only the unquoted skeleton matches.
        assert_eq!(
            classify_config_error(
                "invalid character in id `see unknown field docs`",
                ErrorContext::new("x"),
            )
            .kind(),
            "invalid_id"
        );
        // Genuine toml structural errors still classify correctly.
        assert_eq!(
            classify_config_error(
                "unknown field `categories`, expected one of `server`",
                ErrorContext::new("x"),
            )
            .kind(),
            "unknown_field"
        );
        assert_eq!(
            classify_config_error("missing field `id`", ErrorContext::new("x")).kind(),
            "missing_required"
        );
        // A tag-slug failure still beats the InvalidId arm.
        assert_eq!(
            classify_config_error("invalid tag slug `Ads!`", ErrorContext::new("x")).kind(),
            "invalid_tag_slug"
        );
    }

    /// A bad *value* on a good field must
    /// never be reported as a bad *field*. Both arms used to fold into
    /// `UnknownField`, so the Lists modal told the operator it had written
    /// an unknown field when the field was `kind` (now `base`) — perfectly
    /// known — and
    /// only the value (`"block"`) was wrong. Hours went into looking for a
    /// key that was never the problem.
    #[test]
    fn unknown_variant_is_not_reported_as_unknown_field() {
        let e = classify_config_error(
            "unknown variant `block`, expected `deny` or `allow`",
            ErrorContext::new("unknown variant `block`, expected `deny` or `allow`"),
        );
        assert_eq!(e.kind(), "unknown_variant");
        let shown = e.to_string();
        assert!(
            !shown.contains("unknown field"),
            "must not claim an unknown field: {shown}"
        );
        assert!(
            shown.starts_with("unknown value:"),
            "operator-facing prefix must name the value: {shown}"
        );
        // The offending value survives into the rendered message — this is
        // the half of the message the modal's 2-row budget used to cut.
        assert!(shown.contains("block"), "offending value dropped: {shown}");
    }

    #[test]
    fn context_display_with_file_and_line() {
        let c = ErrorContext::new("boom")
            .with_file("/etc/purge-warden/config.toml")
            .with_line(42);
        assert_eq!(c.to_string(), "boom at /etc/purge-warden/config.toml:42");
    }

    #[test]
    fn context_display_with_entity_and_suggestion() {
        let c = ErrorContext::new("profile not found")
            .with_entity("devices.iphone")
            .with_suggestion("add a matching [profiles.family] block");
        assert_eq!(
            c.to_string(),
            "profile not found for devices.iphone. suggestion: add a matching \
             [profiles.family] block"
        );
    }

    #[test]
    fn error_kind_tags() {
        let dup = ConfigError::DuplicateId(ErrorContext::new("two"));
        assert_eq!(dup.kind(), "duplicate_id");
        let parse = ConfigError::Parse(ErrorContext::new("one"));
        assert_eq!(parse.kind(), "parse");
    }

    #[test]
    fn error_display_delegates_to_context() {
        let err = ConfigError::CrossRefMiss(
            ErrorContext::new("profile \"family\" not found")
                .with_entity("devices.edo-iphone")
                .with_suggestion("add a [profiles.family] block"),
        );
        let s = err.to_string();
        assert!(s.starts_with("cross-reference miss: "));
        assert!(s.contains("profile \"family\" not found"));
        assert!(s.contains("devices.edo-iphone"));
        assert!(s.contains("suggestion: add a [profiles.family] block"));
    }

    #[test]
    fn error_context_accessor_works_for_every_variant() {
        let cases = [
            ConfigError::Parse(ErrorContext::new("a")),
            ConfigError::MissingRequired(ErrorContext::new("b")),
            ConfigError::UnknownField(ErrorContext::new("c")),
            ConfigError::DuplicateId(ErrorContext::new("d")),
            ConfigError::CrossRefMiss(ErrorContext::new("e")),
            ConfigError::VersionMismatch(ErrorContext::new("f")),
            ConfigError::InvalidId(ErrorContext::new("g")),
            ConfigError::IdRecentlyRetired(ErrorContext::new("h")),
            ConfigError::UnsignedAllowListRequiresAck(ErrorContext::new("j")),
            ConfigError::TrustSignedNotYetSupported(ErrorContext::new("k")),
            ConfigError::InvalidTagSlug(ErrorContext::new("m")),
            ConfigError::ValidationFailed(ErrorContext::new("l")),
        ];
        let reasons: Vec<_> = cases.iter().map(|e| e.context().reason.clone()).collect();
        assert_eq!(
            reasons,
            vec!["a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "m", "l"]
        );
    }

    #[test]
    fn s49_t2_new_variant_kinds_are_distinct_and_stable() {
        // DanglingCategoryRef was retired with `[[categories]]` in the
        // v2-tags migration. Pin the remaining `kind()` tags so a future
        // rename surfaces in code review (the kind is what JSON / lint
        // output keys on; renaming silently would break tooling).
        assert_eq!(
            ConfigError::UnsignedAllowListRequiresAck(ErrorContext::new("x")).kind(),
            // Renamed with the variant when the categorical gate
            // became a consent gate. `kind()` is what JSON / lint output
            // keys on, so this is a BREAKING change for any tooling that
            // matched the old `allow_list_requires_local_trust` tag —
            // deliberate, because the old tag names a rule that no longer
            // exists.
            "unsigned_allow_list_requires_ack"
        );
        assert_eq!(
            ConfigError::TrustSignedNotYetSupported(ErrorContext::new("x")).kind(),
            "trust_signed_not_yet_supported"
        );
    }

    #[test]
    fn lc2_foundation_invalid_tag_slug_kind_is_distinct_and_stable() {
        // Pin its `kind()` tag for the same reason as the variants above.
        assert_eq!(
            ConfigError::InvalidTagSlug(ErrorContext::new("x")).kind(),
            "invalid_tag_slug"
        );
    }
}
