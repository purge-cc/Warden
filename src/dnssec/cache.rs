//! Validation-verdict cache (§4.10-3a).
//!
//! Walking the chain of trust is expensive — several upstream round-trips and
//! signature verifications per name. This cache memoises the [`ChainResult`] for
//! a `(name, record type)` pair so a repeated query reuses the verdict instead of
//! re-walking. Entries share one time-to-live (`dnssec.cache_ttl_secs`, default
//! 1 h); the design keeps verdict lifetime independent of the answer's own DNS
//! TTL so a short-lived record does not force constant re-validation.
//!
//! Validation runs **off** the hot query path (the chain walk awaits upstream
//! fetches), so unlike the answer cache this may use a lock-bearing cache —
//! [`moka`], the same crate the answer cache uses. The cache is engine-only this
//! sprint: nothing in the live path reads or writes it yet (that is §4.10-4).

use std::time::Duration;

use compact_str::CompactString;
use hickory_proto::rr::{Name, RecordType};
use moka::future::Cache;

use crate::config::settings::DnssecConfig;
use crate::dnssec::chain::ChainResult;

/// Default upper bound on cached verdicts. Validation touches far fewer names
/// than the answer cache, so a modest cap keeps memory bounded without evicting
/// useful entries in practice.
const DEFAULT_CAPACITY: u64 = 10_000;

/// Key: the case-normalised name plus the queried record type. DNSSEC verdicts
/// are class-agnostic in this validator (IN only), so class is not keyed.
type VerdictKey = (CompactString, RecordType);

/// A TTL-bounded cache of chain-validation verdicts.
#[derive(Clone)]
pub struct VerdictCache {
    cache: Cache<VerdictKey, ChainResult>,
}

impl VerdictCache {
    /// Build a cache whose entries live for `dnssec.cache_ttl_secs`.
    #[must_use]
    pub fn new(cfg: &DnssecConfig) -> Self {
        Self::with_ttl(Duration::from_secs(cfg.cache_ttl_secs), DEFAULT_CAPACITY)
    }

    /// Build a cache with an explicit TTL and capacity (used by tests to exercise
    /// expiry without waiting a configured hour).
    #[must_use]
    pub fn with_ttl(ttl: Duration, capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// The cached verdict for `(name, rtype)`, if present and unexpired.
    pub async fn get(&self, name: &Name, rtype: RecordType) -> Option<ChainResult> {
        self.cache.get(&key(name, rtype)).await
    }

    /// Cache `result` for `(name, rtype)` for the configured TTL.
    ///
    /// Defense-in-depth (cache-01): only STABLE verdicts are cacheable. A
    /// transient [`ChainResult::Indeterminate`] (a tripped DoS cap, a failed
    /// fetch, no anchor match, or a no-DS delegation awaiting a denial proof) is
    /// dropped — caching it would pin a transient outage for the full TTL
    /// (`dnssec_validation.md` §4.10-4b). The out-of-section caller already
    /// filters; keeping the invariant here means a future caller cannot silently
    /// regress availability.
    pub async fn insert(&self, name: &Name, rtype: RecordType, result: ChainResult) {
        if matches!(result, ChainResult::Indeterminate(_)) {
            return;
        }
        self.cache.insert(key(name, rtype), result).await;
    }
}

/// Build the case-normalised cache key for a name/type pair.
fn key(name: &Name, rtype: RecordType) -> VerdictKey {
    // DNS names compare case-insensitively (RFC 4343), so ASCII-fold in place.
    // This keeps the key to a single allocation (the `to_string`) instead of the
    // `to_string()` + `to_lowercase()` pair the previous form allocated.
    let mut s = name.to_string();
    s.make_ascii_lowercase();
    (CompactString::from(s), rtype)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::chain::{ChainBogus, Indeterminate};
    use crate::dnssec::verify::BogusReason;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[tokio::test]
    async fn insert_then_hit() {
        let cache = VerdictCache::new(&DnssecConfig::default());
        assert_eq!(cache.get(&n("example.org."), RecordType::A).await, None);
        cache
            .insert(&n("example.org."), RecordType::A, ChainResult::Secure)
            .await;
        assert_eq!(
            cache.get(&n("example.org."), RecordType::A).await,
            Some(ChainResult::Secure)
        );
    }

    #[tokio::test]
    async fn key_is_case_insensitive_and_type_specific() {
        let cache = VerdictCache::new(&DnssecConfig::default());
        cache
            .insert(
                &n("Example.Org."),
                RecordType::A,
                ChainResult::Bogus(ChainBogus::Hop(BogusReason::SignatureInvalid)),
            )
            .await;
        // 0x20-cased lookup hits the same entry…
        assert_eq!(
            cache.get(&n("eXaMpLe.oRg."), RecordType::A).await,
            Some(ChainResult::Bogus(ChainBogus::Hop(
                BogusReason::SignatureInvalid
            )))
        );
        // …but a different record type is a separate entry.
        assert_eq!(cache.get(&n("example.org."), RecordType::AAAA).await, None);
    }

    #[tokio::test]
    async fn entry_expires_after_ttl() {
        let cache = VerdictCache::with_ttl(Duration::from_millis(40), 16);
        // A STABLE verdict (cache-01: an Indeterminate would be refused) so the
        // test exercises TTL expiry, not the cacheability gate.
        cache
            .insert(&n("example.org."), RecordType::A, ChainResult::Secure)
            .await;
        assert!(cache.get(&n("example.org."), RecordType::A).await.is_some());
        tokio::time::sleep(Duration::from_millis(80)).await;
        cache.cache.run_pending_tasks().await;
        assert_eq!(
            cache.get(&n("example.org."), RecordType::A).await,
            None,
            "verdict must expire after its TTL"
        );
    }

    #[tokio::test]
    async fn insert_refuses_indeterminate() {
        let cache = VerdictCache::new(&DnssecConfig::default());
        // cache-01: a transient verdict must never be cached…
        cache
            .insert(
                &n("example.org."),
                RecordType::A,
                ChainResult::Indeterminate(Indeterminate::FetchFailed),
            )
            .await;
        assert_eq!(
            cache.get(&n("example.org."), RecordType::A).await,
            None,
            "Indeterminate must not be cached"
        );
        // …but a stable verdict still caches.
        cache
            .insert(&n("example.org."), RecordType::A, ChainResult::Secure)
            .await;
        assert_eq!(
            cache.get(&n("example.org."), RecordType::A).await,
            Some(ChainResult::Secure)
        );
    }
}
