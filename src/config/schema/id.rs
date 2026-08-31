//! [`Id`] — the stable, parse-don't-validate identifier newtype that every
//! v1 config entity uses as cross-reference key.
//!
//! Design doc §8 sets the contract: ids are "lowercase-ascii-dashes-only".
//! The concrete charset here is `[a-z0-9-]` and the length bound is
//! `1..=64` bytes (twice the budget of the Sprint 22 device-tag
//! newtype, which proved livable under real operator use).
//!
//! Ids are how profile references survive a display-name rename (A3):
//! `display_name` can change freely, but renaming an `id` is an explicit
//! retirement operation (N8) that goes through the retired-ids list.

use std::fmt;

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

use super::super::error::{ConfigError, ErrorContext};

/// Stable identifier for a config entity.
///
/// Charset: ASCII lowercase letters, digits, and `-`. Length: 1..=64 bytes.
/// Constructed via [`Id::new`], [`Id::try_from`], or serde (which routes
/// through `TryFrom<String>`). Once constructed, the invariants hold for
/// the lifetime of the value — no call site needs to re-validate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(CompactString);

impl Id {
    /// Maximum id length in bytes. Ids are ASCII-only so this also bounds
    /// the character count.
    pub const MAX_LEN: usize = 64;

    /// Construct a validated id, returning a [`ConfigError::InvalidId`] on
    /// charset / length violations.
    pub fn new(s: impl Into<String>) -> Result<Self, ConfigError> {
        let s = s.into();
        Self::validate(&s)?;
        // `CompactString` stores ids <=24 bytes inline (no heap alloc), so
        // cloning an `Id` on the resolver path is a memcpy rather than a
        // malloc. Signature stays `impl Into<String>` so every caller is
        // unchanged; only the backing storage differs.
        Ok(Self(CompactString::from(s)))
    }

    /// Reject empty, over-length, and any non-ASCII / non-allowed-charset
    /// input. Also reject leading / trailing dashes — while technically
    /// inside the charset, `"-foo"` or `"foo-"` read as typos to humans and
    /// confuse shell completion.
    fn validate(s: &str) -> Result<(), ConfigError> {
        if s.is_empty() {
            return Err(ConfigError::InvalidId(ErrorContext::new(
                "id cannot be empty".to_string(),
            )));
        }
        if s.len() > Self::MAX_LEN {
            // error-01: `s` is over-long by definition here — bound the echo
            // (the char/dash errors below only run for s.len() <= MAX_LEN, so
            // they need no truncation).
            let shown = crate::config::error::truncate_for_error(s);
            return Err(ConfigError::InvalidId(
                ErrorContext::new(format!(
                    "id \"{shown}\" is {} bytes (max {})",
                    s.len(),
                    Self::MAX_LEN
                ))
                .with_suggestion(format!("shorten the id to <= {} bytes", Self::MAX_LEN)),
            ));
        }
        for (i, c) in s.chars().enumerate() {
            let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
            if !ok {
                return Err(ConfigError::InvalidId(
                    ErrorContext::new(format!(
                        "id \"{s}\" has invalid character {c:?} at position {i} \
                         (allowed: lowercase a-z, digits, and '-')"
                    ))
                    .with_suggestion("rename using only [a-z0-9-]".to_string()),
                ));
            }
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(ConfigError::InvalidId(
                ErrorContext::new(format!("id \"{s}\" cannot start or end with a dash"))
                    .with_suggestion("drop the leading / trailing dash".to_string()),
            ));
        }
        Ok(())
    }

    /// Borrow the id as a `&str`.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl TryFrom<String> for Id {
    type Error = ConfigError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Id {
    type Error = ConfigError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.to_string())
    }
}

// Serde plumbing: deserialize via `TryFrom<String>` so every TOML load path
// enforces the invariants, serialize as the bare id string for round-tripping.
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_simple() {
        assert!(Id::new("default").is_ok());
    }

    #[test]
    fn ok_with_dashes_and_digits() {
        assert!(Id::new("alex-iphone-01").is_ok());
    }

    #[test]
    fn ok_single_char() {
        assert!(Id::new("a").is_ok());
    }

    #[test]
    fn ok_at_max_len() {
        let s = "a".repeat(Id::MAX_LEN);
        assert!(Id::new(s).is_ok());
    }

    #[test]
    fn rejects_empty() {
        let err = Id::new("").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidId(_)));
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn rejects_over_max_len() {
        let s = "a".repeat(Id::MAX_LEN + 1);
        let err = Id::new(&s).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidId(_)));
        assert!(err.to_string().contains(&format!("{} bytes", s.len())));
    }

    #[test]
    fn rejects_uppercase() {
        let err = Id::new("Default").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn rejects_underscore() {
        let err = Id::new("foo_bar").unwrap_err();
        assert!(err.to_string().contains("'_'"));
    }

    #[test]
    fn rejects_space() {
        assert!(Id::new("foo bar").is_err());
    }

    #[test]
    fn rejects_dot() {
        assert!(Id::new("foo.bar").is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(Id::new("caffè").is_err());
    }

    #[test]
    fn rejects_leading_dash() {
        let err = Id::new("-foo").unwrap_err();
        assert!(err.to_string().contains("cannot start or end with"));
    }

    #[test]
    fn rejects_trailing_dash() {
        assert!(Id::new("foo-").is_err());
    }

    #[test]
    fn display_is_the_raw_id() {
        let id = Id::new("family").unwrap();
        assert_eq!(id.to_string(), "family");
        assert_eq!(id.as_str(), "family");
    }

    #[test]
    fn serde_roundtrip_via_toml() {
        #[derive(Serialize, Deserialize)]
        struct W {
            id: Id,
        }
        let w = W {
            id: Id::new("family").unwrap(),
        };
        let serialised = toml::to_string(&w).unwrap();
        assert!(serialised.contains("id = \"family\""));
        let back: W = toml::from_str(&serialised).unwrap();
        assert_eq!(back.id, w.id);
    }

    #[test]
    fn serde_rejects_invalid_via_toml() {
        #[derive(Debug, Deserialize)]
        struct W {
            #[allow(dead_code)]
            id: Id,
        }
        let err = toml::from_str::<W>("id = \"BAD\"").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }
}
