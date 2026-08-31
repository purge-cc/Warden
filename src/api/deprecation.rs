//! Deprecation-header helper for additive REST-API rename/migration.
//!
//! When a REST endpoint is renamed, [§3 R1 of the terminology-normalization
//! design][design] mandates an *additive* rollout: the new path is introduced
//! next to the old one, and the old path keeps responding with a
//! `Deprecation: true` header plus a `Sunset` HTTP-date (RFC 8594) and a
//! `Link: <new>; rel="successor-version"` pointer (RFC 8288) for two tagged
//! releases before the old path is retired.
//!
//! This module is the single source of the three-header triple so each
//! handler (or middleware) that deprecates a path attaches the same shape.
//! Sprint 42 Phase 3 (T3) introduced the helper as scaffolding — no live
//! endpoint uses it yet, because the `upstream`/`resolver` rename had no
//! legacy route to deprecate. Sprint 42 Phase 5 (T5) is the first consumer:
//! it attaches the triple to `/api/clients` when introducing
//! `/api/devices`.
//!
//! [design]: ../../_docs/rules/terminology_normalization.md

use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

/// HTTP header name for the deprecation signal
/// ([draft-ietf-httpapi-deprecation-header]).
///
/// [draft-ietf-httpapi-deprecation-header]:
///     https://datatracker.ietf.org/doc/draft-ietf-httpapi-deprecation-header/
const DEPRECATION: HeaderName = HeaderName::from_static("deprecation");

/// HTTP header name for [RFC 8594] Sunset.
///
/// [RFC 8594]: https://www.rfc-editor.org/rfc/rfc8594
const SUNSET: HeaderName = HeaderName::from_static("sunset");

/// Error returned by [`deprecation_headers`] when the triple cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum DeprecationHeaderError {
    /// The sunset timestamp could not be formatted as an RFC 2822 date
    /// (e.g. a year outside `0000..=9999`).
    #[error("could not format sunset timestamp as RFC 2822: {0}")]
    SunsetFormat(#[from] time::error::Format),
    /// A header value contained bytes illegal in an HTTP header value.
    #[error("invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] axum::http::header::InvalidHeaderValue),
}

/// Build the three-header [`HeaderMap`] a deprecated endpoint must return.
///
/// * `Deprecation: true` — endpoint is deprecated right now.
/// * `Sunset: <http-date>` — planned removal date (RFC 7231 IMF-fixdate /
///   RFC 2822 form). Callers should pick a date at least two tagged releases
///   in the future.
/// * `Link: <successor_path>; rel="successor-version"` — RFC 8288 pointer
///   to the replacement endpoint.
///
/// Returns `Err` if `sunset` is outside the RFC 2822-formattable range
/// (year ∉ `0000..=9999`) or `successor_path` contains bytes that cannot
/// appear in an HTTP header value. Pass a static literal and a near-future
/// date and the call is infallible in practice.
pub fn deprecation_headers(
    successor_path: &str,
    sunset: OffsetDateTime,
) -> Result<HeaderMap, DeprecationHeaderError> {
    let mut headers = HeaderMap::with_capacity(3);

    headers.insert(DEPRECATION, HeaderValue::from_static("true"));

    let sunset_str = sunset.format(&Rfc2822)?;
    headers.insert(SUNSET, HeaderValue::try_from(sunset_str)?);

    let link_value = format!("<{successor_path}>; rel=\"successor-version\"");
    headers.insert(axum::http::header::LINK, HeaderValue::try_from(link_value)?);

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn deprecation_headers_produces_expected_triple() {
        let sunset = datetime!(2026-12-31 23:59:59 UTC);
        let headers = deprecation_headers("/api/devices", sunset).expect("static inputs valid");

        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get("deprecation").unwrap(), "true");
        assert!(headers.contains_key("sunset"));
        let link = headers.get("link").unwrap().to_str().unwrap();
        assert_eq!(link, "</api/devices>; rel=\"successor-version\"");
    }

    #[test]
    fn deprecation_headers_sunset_formats_as_http_date() {
        let sunset = datetime!(2026-12-31 23:59:59 UTC);
        let headers = deprecation_headers("/api/devices", sunset).expect("static inputs valid");

        let sunset_str = headers.get("sunset").unwrap().to_str().unwrap();
        // RFC 2822 format: `Thu, 31 Dec 2026 23:59:59 +0000`
        assert!(
            sunset_str.starts_with("Thu, 31 Dec 2026 23:59:59"),
            "unexpected sunset format: {sunset_str}"
        );
    }
}
