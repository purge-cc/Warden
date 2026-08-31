//! API token generation, hashing, and constant-time verification.
//!
//! Token format: `ps_` + 64 hex chars (256-bit random via OsRng).
//! Storage: SHA-256 hash of the full token string, stored as hex in config.toml.
//! Verification: constant-time comparison via `subtle::ConstantTimeEq`.

use rand_core::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TOKEN_PREFIX: &str = "ps_";
const TOKEN_BYTES: usize = 32; // 256 bits

/// Generate a new API token. Returns `(plaintext_token, sha256_hex_hash)`.
///
/// The plaintext is shown once to the user. The hash is stored in config.
pub fn generate_token() -> (String, String) {
    let mut buf = [0u8; TOKEN_BYTES];
    rand_core::OsRng.fill_bytes(&mut buf);

    let plaintext = format!("{TOKEN_PREFIX}{}", hex::encode(buf));
    let hash = hash_token(&plaintext);
    (plaintext, hash)
}

/// SHA-256 hash of a token string, returned as lowercase hex.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Constant-time verification of a token against a stored hash.
///
/// Returns `true` if `hash_token(token) == stored_hash` (timing-safe).
pub fn verify_token(token: &str, stored_hash: &str) -> bool {
    let candidate = hash_token(token);
    candidate.as_bytes().ct_eq(stored_hash.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format() {
        let (plaintext, _hash) = generate_token();
        assert!(plaintext.starts_with("ps_"));
        // ps_ (3) + 64 hex chars = 67
        assert_eq!(plaintext.len(), 67);
    }

    #[test]
    fn token_uniqueness() {
        let (t1, _) = generate_token();
        let (t2, _) = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_deterministic() {
        let h1 = hash_token("ps_abc123");
        let h2 = hash_token("ps_abc123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let h = hash_token("test");
        assert_eq!(h.len(), 64); // SHA-256 = 32 bytes = 64 hex
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_correct_token() {
        let (plaintext, hash) = generate_token();
        assert!(verify_token(&plaintext, &hash));
    }

    #[test]
    fn verify_wrong_token_rejected() {
        let (_plaintext, hash) = generate_token();
        assert!(!verify_token("ps_wrong_token", &hash));
    }

    #[test]
    fn verify_empty_hash_rejected() {
        assert!(!verify_token("ps_test", ""));
    }
}
