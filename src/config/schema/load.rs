//! Minimal load helper for [`ConfigV1`] — parses a single TOML source
//! string, categorises any [`toml::de::Error`] into the appropriate
//! [`ConfigError`] variant, and runs the semantic validator.
//!
//! Reused as the single-file fast path inside the multi-file loader
//! (globs, includes, path security, cycle detection, load limits). Also
//! drives the `tests/fixtures/broken-v1/` regression suite: it gives every
//! `ConfigError` variant a natural production path.

use std::path::Path;

use time::OffsetDateTime;

use super::super::error::{ConfigError, ErrorContext};
use super::super::loader::ProvenanceMap;
use super::super::secrets::Secrets;
use super::retired_keys;
use super::validator::{validate_collect, AuditWarnings};
use super::ConfigV1;

/// Parse and validate a v1 configuration from a raw string.
///
/// `file` is attached to every error's [`ErrorContext::file`] for
/// downstream pretty-printing (it is NOT opened — the caller has already
/// read the file). `now` is passed through to the validator so that
/// retired-id window checks are deterministic in tests.
///
/// Thin delegate to [`load_from_str_collect`] with an
/// [`AuditWarnings::emitting`] collector that is then discarded — byte-for-byte
/// the behaviour this function had when it called `validate` directly, since
/// `validate` is itself `validate_collect(.., emitting(), None, None)`.
pub fn load_from_str(
    src: &str,
    file: Option<&Path>,
    now: OffsetDateTime,
) -> Result<ConfigV1, Vec<ConfigError>> {
    load_from_str_collect(src, file, now, &mut AuditWarnings::emitting(), None, None)
}

/// [`load_from_str`] that validates **once** into a caller-supplied
/// [`AuditWarnings`] collector, and can carry the secrets table + provenance
/// map the full validator wants.
///
/// The loader's single-file fast path —
/// which is the *shipped* layout, and the one both the reference fixture and
/// every lint fixture take — used to validate **twice**: once through
/// `load_from_str` (emitting to `tracing`, but unable to accept a collector)
/// and then again via `validate_collect` with a silent collector purely to
/// harvest the same messages as data. Correctness was never at risk; it was a
/// wasted validator pass, plus two places that had to be kept in agreement
/// about secrets and error attribution.
///
/// `secrets` / `provenance` follow the existing `validate_collect` convention
/// exactly: `None` means "not available at this call site" and disables only
/// the checks that need them, never any other rule.
pub fn load_from_str_collect(
    src: &str,
    file: Option<&Path>,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
    provenance: Option<&ProvenanceMap>,
) -> Result<ConfigV1, Vec<ConfigError>> {
    match parse_v1(src, file) {
        Ok(config) => match validate_collect(&config, now, warns, secrets, provenance) {
            Ok(()) => Ok(config),
            Err(errs) => Err(errs.into_iter().map(|e| attach_file(e, file)).collect()),
        },
        Err(err) => Err(vec![err]),
    }
}

/// Deserialise a [`ConfigV1`], stripping retired schema keys first when
/// the source still carries any.
///
/// **This is the half of the `tags` removal that keeps the daemon
/// starting.** All five entity structs are
/// `#[serde(deny_unknown_fields)]`, so a config still carrying
/// `tags = [...]` is *refused*, not ignored, the moment the field goes.
/// Both shipped hosts were measured carrying the key, and a config that
/// does not load is a household with no DNS until someone SSHes in.
///
/// It has to live **here** and not only in
/// `config::loader::normalise_deprecated_keys`, because the loader's
/// single-file fast path — which is the shipped layout — re-parses the raw
/// bytes through this function and never observes the table that
/// `normalise_deprecated_keys` mutated. Both call the same
/// [`retired_keys::strip_retired_tag_keys`], so the two entry points
/// cannot drift into disagreeing about what a config means.
///
/// The operator-facing note comes from the loader, which runs on both
/// exits (`loader.rs`, above the fast-path branch) and reaches
/// `warden config lint`. This arm is silent on purpose: emitting from here
/// too would double the notice on the single-file path.
///
/// A config with no retired key takes the byte-identical parse it always
/// did, spans and all; only one that still carries the key pays the table
/// round-trip, and its errors then lose their line numbers (the note tells
/// the operator to migrate, which restores them).
fn parse_v1(src: &str, file: Option<&Path>) -> Result<ConfigV1, ConfigError> {
    if retired_keys::src_may_carry_retired_tag_key(src) {
        let mut table: toml::Table =
            toml::from_str(src).map_err(|err| classify_toml_error(err, src, file))?;
        retired_keys::strip_retired_tag_keys(&mut table);
        return toml::Value::Table(table)
            .try_into::<ConfigV1>()
            .map_err(|err| classify_toml_error(err, src, file));
    }
    toml::from_str::<ConfigV1>(src).map_err(|err| classify_toml_error(err, src, file))
}

/// Convenience wrapper reading from disk. Used by the fixture-based
/// tests.
pub fn load_from_path(path: &Path, now: OffsetDateTime) -> Result<ConfigV1, Vec<ConfigError>> {
    let src = std::fs::read_to_string(path).map_err(|io_err| {
        vec![ConfigError::Parse(
            ErrorContext::new(format!("cannot read config: {io_err}"))
                .with_file(path.to_path_buf()),
        )]
    })?;
    load_from_str(&src, Some(path), now)
}

/// `pub(crate)` so the loader's single-file fast path can attribute the
/// `auth_token_ref` cross-check errors it surfaces to the master file,
/// exactly as [`load_from_str`] does for its own.
pub(crate) fn attach_file(mut err: ConfigError, file: Option<&Path>) -> ConfigError {
    if err.context().file.is_none() {
        if let Some(p) = file {
            err.context_mut().file = Some(p.to_path_buf());
        }
    }
    err
}

/// Map a [`toml::de::Error`] to the most specific [`ConfigError`] variant
/// by inspecting the message string. The toml crate emits stable
/// substrings for the cases we care about — "unknown field", "missing
/// field", "invalid character", "unknown variant" — so matching on them
/// is reliable across minor version bumps. Anything unrecognised falls
/// through to [`ConfigError::Parse`].
///
/// The `"tag slug"` arm is checked *before* the `InvalidId` arm: a
/// `TagSlug::validate` failure shares wording with `Id::validate`
/// ("cannot be empty", "bytes (max", "invalid character"), so without the
/// earlier, more-specific match a bad tag slug would be misclassified as
/// `InvalidId` and its dedicated repair hint lost.
fn classify_toml_error(err: toml::de::Error, src: &str, file: Option<&Path>) -> ConfigError {
    let msg = err.to_string();
    let line = err.span().map(|s| line_of(src, s.start));
    // Bound the stored reason (toml can excerpt a multi-MB line);
    // classification still matches on the full `msg`.
    let mut ctx = ErrorContext::new(super::super::error::truncate_for_error(&msg).into_owned());
    if let Some(p) = file {
        ctx = ctx.with_file(p.to_path_buf());
    }
    if let Some(l) = line {
        ctx = ctx.with_line(l);
    }
    // One shared, drift-proof classifier for both the single-file
    // and merged paths; matches against the user-content-masked skeleton.
    super::super::error::classify_config_error(&msg, ctx)
}

/// Convert a byte offset into a 1-based line number. Used for error
/// contextualisation (toml's span is byte-level).
fn line_of(src: &str, offset: usize) -> usize {
    let clamped = offset.min(src.len());
    src[..clamped].bytes().filter(|b| *b == b'\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        // Matches the retired_at in tests/fixtures/broken-v1/id_recently_retired.toml
        // (2026-04-01) + ~3 weeks → still inside the 90-day window.
        datetime!(2026-04-22 12:00:00 UTC)
    }

    // ── minimal-v1 fixture ────────────────────────────────

    const MINIMAL_V1: &str = include_str!("../../../tests/fixtures/minimal-v1/config.toml");

    #[test]
    fn minimal_v1_fixture_parses_and_validates() {
        let c = load_from_str(MINIMAL_V1, None, now()).expect("minimal-v1 must validate clean");
        assert_eq!(c.schema_version, super::super::SCHEMA_VERSION_V1);
        assert_eq!(c.blocklists.len(), 2);
        assert_eq!(c.profiles.len(), 2);
        assert_eq!(c.devices.len(), 2);
        assert_eq!(c.groups.len(), 2);
        assert_eq!(c.subnets.len(), 1);
        assert_eq!(c.schedules.len(), 2);
        assert_eq!(c.admin_rules.len(), 2);
        assert_eq!(c.retired.len(), 1);
    }

    #[test]
    fn minimal_v1_fixture_roundtrips_semantically() {
        // Load, re-serialise, reload — the second parse must match the
        // first. Pins that every entity round-trips through serde without
        // losing fields or introducing defaults.
        let first = load_from_str(MINIMAL_V1, None, now()).unwrap();
        let reserialised = toml::to_string(&first).unwrap();
        let second = load_from_str(&reserialised, None, now()).unwrap();
        // `ConfigV1` no longer implements `PartialEq` (it now wraps
        // legacy pass-through types that don't). Compare via a second
        // serialisation round — byte-identical output implies semantic
        // equivalence after the re-parse.
        assert_eq!(toml::to_string(&second).unwrap(), reserialised);
    }

    // ── broken-v1 fixtures ────────────────────────────────

    /// Every broken-v1 fixture is pinned by (kind, required substring in
    /// the combined error output). The expected kind matches
    /// [`ConfigError::kind`] output, and the substring keeps the
    /// regression guard pinned to a stable symbol (id / profile / CIDR
    /// / file name) rather than the full error wording, so message
    /// rewording does not produce false failures.
    fn broken_case(name: &'static str, expected_kind: &'static str, needle: &'static str) {
        let src = match name {
            "parse" => include_str!("../../../tests/fixtures/broken-v1/parse.toml"),
            "unknown_field" => include_str!("../../../tests/fixtures/broken-v1/unknown_field.toml"),
            "missing_required" => {
                include_str!("../../../tests/fixtures/broken-v1/missing_required.toml")
            }
            "version_mismatch" => {
                include_str!("../../../tests/fixtures/broken-v1/version_mismatch.toml")
            }
            "invalid_id" => include_str!("../../../tests/fixtures/broken-v1/invalid_id.toml"),
            "duplicate_id" => include_str!("../../../tests/fixtures/broken-v1/duplicate_id.toml"),
            "cross_ref_miss" => {
                include_str!("../../../tests/fixtures/broken-v1/cross_ref_miss.toml")
            }
            "id_recently_retired" => {
                include_str!("../../../tests/fixtures/broken-v1/id_recently_retired.toml")
            }
            "validation_failed" => {
                include_str!("../../../tests/fixtures/broken-v1/validation_failed.toml")
            }
            "admin_rule_unparseable" => {
                include_str!("../../../tests/fixtures/broken-v1/admin_rule_unparseable.toml")
            }
            _ => panic!("unknown broken fixture: {name}"),
        };
        let errs = load_from_str(src, None, now())
            .err()
            .unwrap_or_else(|| panic!("fixture {name} should have failed to validate"));
        let kinds: Vec<&'static str> = errs.iter().map(|e| e.kind()).collect();
        assert!(
            kinds.contains(&expected_kind),
            "fixture {name}: expected a ConfigError with kind {expected_kind:?}, got {kinds:?}"
        );
        let combined = errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            combined.contains(needle),
            "fixture {name}: expected substring {needle:?} in errors, got:\n{combined}"
        );
    }

    #[test]
    fn broken_parse() {
        broken_case("parse", "parse", "");
    }

    #[test]
    fn broken_unknown_field() {
        broken_case("unknown_field", "unknown_field", "extra_section");
    }

    #[test]
    fn broken_missing_required() {
        broken_case("missing_required", "missing_required", "schema_version");
    }

    #[test]
    fn broken_version_mismatch() {
        broken_case("version_mismatch", "version_mismatch", "schema_version = 1");
    }

    #[test]
    fn broken_invalid_id() {
        broken_case("invalid_id", "invalid_id", "BAD ID");
    }

    #[test]
    fn broken_duplicate_id() {
        broken_case("duplicate_id", "duplicate_id", "privacy-ads");
    }

    #[test]
    fn broken_cross_ref_miss() {
        broken_case("cross_ref_miss", "cross_ref_miss", "ghost");
    }

    #[test]
    fn broken_id_recently_retired() {
        broken_case(
            "id_recently_retired",
            "id_recently_retired",
            "freshly-retired",
        );
    }

    #[test]
    fn broken_validation_failed() {
        broken_case("validation_failed", "validation_failed", "cidrs");
    }

    #[test]
    fn broken_admin_rule_unparseable() {
        // An unclosed regex group in [[admin_rules]].rule is a load
        // error, not a silently inert rule.
        broken_case(
            "admin_rule_unparseable",
            "validation_failed",
            "poster-child",
        );
    }

    // ── file-path propagation ─────────────────────────────

    #[test]
    fn load_from_path_attaches_file_to_errors() {
        // Write a temp file with a broken payload, load, and verify
        // every error carries the file name.
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "schema_version = 3\n[profiles.default]\ndisplay_name = \"Default\"\n[[devices]]\nid = \"iphone\"\ndisplay_name = \"iPhone\"\nip = \"10.0.0.1\"\nprofile = \"ghost\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        )
        .unwrap();
        let errs = load_from_path(tmp.path(), now()).unwrap_err();
        assert!(!errs.is_empty());
        for e in &errs {
            assert_eq!(
                e.context().file.as_deref(),
                Some(tmp.path()),
                "expected file path on every error, got {e:?}"
            );
        }
    }

    #[test]
    fn load_from_path_missing_file_returns_parse_error() {
        let errs = load_from_path(Path::new("/nonexistent/path/config.toml"), now()).unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, ConfigError::Parse(_))));
    }

    // ── line-number extraction ─────────────────────────────

    #[test]
    fn line_of_counts_newlines() {
        let src = "a\nb\nc\nd";
        assert_eq!(line_of(src, 0), 1);
        assert_eq!(line_of(src, 1), 1);
        assert_eq!(line_of(src, 2), 2);
        assert_eq!(line_of(src, 4), 3);
        assert_eq!(line_of(src, 6), 4);
    }

    #[test]
    fn line_of_out_of_bounds_clamps() {
        assert_eq!(line_of("abc", 999), 1);
    }
}
