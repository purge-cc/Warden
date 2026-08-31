//! Per-query-type classification for tracking stats.
//!
//! Maps the ~100 hickory `RecordType` variants down to a closed 10-bucket
//! enum so per-type counters can use a fixed-size `[AtomicU64; 10]` array
//! instead of a `HashMap` lookup on every query. Indexed by
//! `bucket as usize` so the hot path is branch-free after the classifier
//! match.
//!
//! See `_docs/features/query_type_stats.md` §"Data structures" for the design
//! rationale and the security signal table that drives the bucket choice.

use hickory_proto::rr::RecordType;

/// Number of distinct buckets. Sizes the per-type counter arrays.
pub const TYPE_BUCKET_COUNT: usize = 10;

/// Closed bucket set covering the 9 named record types operators care
/// about, plus `Other` for the long tail (ANY, CAA, DNSKEY, DS, NSEC,
/// AXFR, CNAME, MX, …). Aligns 1:1 with array indices in
/// `GlobalStats::per_type` and `DeviceStats::per_type`.
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeBucket {
    A = 0,
    Aaaa = 1,
    Txt = 2,
    Ptr = 3,
    Ns = 4,
    Soa = 5,
    Srv = 6,
    Svcb = 7,
    Https = 8,
    Other = 9,
}

impl TypeBucket {
    /// All variants in canonical order; index equals `variant as usize`.
    /// Callers iterating per-type counters use this to keep the IPC /
    /// snapshot / TUI layers in lockstep with the enum.
    pub const ALL: [TypeBucket; TYPE_BUCKET_COUNT] = [
        TypeBucket::A,
        TypeBucket::Aaaa,
        TypeBucket::Txt,
        TypeBucket::Ptr,
        TypeBucket::Ns,
        TypeBucket::Soa,
        TypeBucket::Srv,
        TypeBucket::Svcb,
        TypeBucket::Https,
        TypeBucket::Other,
    ];

    /// Classify a hickory `RecordType` into a tracking bucket.
    ///
    /// CNAME, MX, ANY, CAA, DNSKEY, DS, NSEC, AXFR, and every other rare
    /// type fold into `Other`. A high `Other` rate is itself a signal —
    /// operators notice unusual query mixes (zone walking, DNSSEC probing,
    /// amplification reflectors).
    #[inline]
    pub fn classify(rt: RecordType) -> Self {
        match rt {
            RecordType::A => TypeBucket::A,
            RecordType::AAAA => TypeBucket::Aaaa,
            RecordType::TXT => TypeBucket::Txt,
            RecordType::PTR => TypeBucket::Ptr,
            RecordType::NS => TypeBucket::Ns,
            RecordType::SOA => TypeBucket::Soa,
            RecordType::SRV => TypeBucket::Srv,
            RecordType::SVCB => TypeBucket::Svcb,
            RecordType::HTTPS => TypeBucket::Https,
            _ => TypeBucket::Other,
        }
    }

    /// Stable display label used in IPC payloads, snapshot JSON keys, and
    /// TUI labels. Frozen across releases — operator-facing.
    pub const fn name(self) -> &'static str {
        match self {
            TypeBucket::A => "A",
            TypeBucket::Aaaa => "AAAA",
            TypeBucket::Txt => "TXT",
            TypeBucket::Ptr => "PTR",
            TypeBucket::Ns => "NS",
            TypeBucket::Soa => "SOA",
            TypeBucket::Srv => "SRV",
            TypeBucket::Svcb => "SVCB",
            TypeBucket::Https => "HTTPS",
            TypeBucket::Other => "Other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_named_buckets() {
        assert_eq!(TypeBucket::classify(RecordType::A), TypeBucket::A);
        assert_eq!(TypeBucket::classify(RecordType::AAAA), TypeBucket::Aaaa);
        assert_eq!(TypeBucket::classify(RecordType::TXT), TypeBucket::Txt);
        assert_eq!(TypeBucket::classify(RecordType::PTR), TypeBucket::Ptr);
        assert_eq!(TypeBucket::classify(RecordType::NS), TypeBucket::Ns);
        assert_eq!(TypeBucket::classify(RecordType::SOA), TypeBucket::Soa);
        assert_eq!(TypeBucket::classify(RecordType::SRV), TypeBucket::Srv);
        assert_eq!(TypeBucket::classify(RecordType::SVCB), TypeBucket::Svcb);
        assert_eq!(TypeBucket::classify(RecordType::HTTPS), TypeBucket::Https);
    }

    #[test]
    fn classify_other_catches_long_tail() {
        // CNAME and MX are common but deliberately fold into Other per
        // design doc — keeps the bucket count at 10 for cache-line
        // alignment and the security signal table stable.
        assert_eq!(TypeBucket::classify(RecordType::CNAME), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::MX), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::ANY), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::CAA), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::DNSKEY), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::DS), TypeBucket::Other);
        assert_eq!(TypeBucket::classify(RecordType::AXFR), TypeBucket::Other);
    }

    #[test]
    fn all_array_indices_match_variant_discriminants() {
        // Pin the contract that array index == enum discriminant, so
        // `per_type[bucket as usize]` is sound across all consumers.
        for (i, bucket) in TypeBucket::ALL.iter().enumerate() {
            assert_eq!(*bucket as usize, i);
        }
        assert_eq!(TypeBucket::ALL.len(), TYPE_BUCKET_COUNT);
    }

    #[test]
    fn names_are_stable_uppercase_labels() {
        assert_eq!(TypeBucket::A.name(), "A");
        assert_eq!(TypeBucket::Aaaa.name(), "AAAA");
        assert_eq!(TypeBucket::Txt.name(), "TXT");
        assert_eq!(TypeBucket::Ptr.name(), "PTR");
        assert_eq!(TypeBucket::Ns.name(), "NS");
        assert_eq!(TypeBucket::Soa.name(), "SOA");
        assert_eq!(TypeBucket::Srv.name(), "SRV");
        assert_eq!(TypeBucket::Svcb.name(), "SVCB");
        assert_eq!(TypeBucket::Https.name(), "HTTPS");
        assert_eq!(TypeBucket::Other.name(), "Other");
    }
}
