/// A checked quota failure. `actual=None` denotes arithmetic overflow or a
/// compiler limit for which the attempted allocation size is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("operator-rule budget {limit} exceeded (actual {actual:?}, maximum {maximum})")]
pub struct BudgetExceeded {
    pub limit: &'static str,
    pub actual: Option<usize>,
    pub maximum: usize,
}

pub(crate) fn ensure(
    limit: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), BudgetExceeded> {
    if actual > maximum {
        Err(BudgetExceeded {
            limit,
            actual: Some(actual),
            maximum,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn add(a: usize, b: usize) -> Result<usize, BudgetExceeded> {
    a.checked_add(b).ok_or(BudgetExceeded {
        limit: "arithmetic",
        actual: None,
        maximum: usize::MAX,
    })
}

pub(crate) fn mul(a: usize, b: usize) -> Result<usize, BudgetExceeded> {
    a.checked_mul(b).ok_or(BudgetExceeded {
        limit: "arithmetic",
        actual: None,
        maximum: usize::MAX,
    })
}

macro_rules! compile_limits {
    ($($name:ident: $default:expr => $ceiling:expr),+ $(,)?) => {
        /// Node-local admission limits. Every value is in 1..=its hard ceiling.
        /// Each immutable regex DFA is bounded by `max_regex_program_bytes`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct RuleCompileLimits { $(pub $name: usize,)+ }

        impl Default for RuleCompileLimits {
            fn default() -> Self { Self { $($name: $default,)+ } }
        }

        impl RuleCompileLimits {
            pub const HARD_CEILINGS: Self = Self { $($name: $ceiling,)+ };

            pub fn validate(&self) -> Result<(), BudgetExceeded> {
                $(if self.$name == 0 || self.$name > Self::HARD_CEILINGS.$name {
                    return Err(BudgetExceeded { limit: stringify!($name), actual: Some(self.$name), maximum: Self::HARD_CEILINGS.$name });
                })+
                Ok(())
            }

            #[cfg(test)]
            pub(super) fn fields() -> Vec<LimitField> {
                vec![$((stringify!($name), |limits: &mut Self| &mut limits.$name)),+]
            }
        }
    };
}

#[cfg(test)]
type LimitField = (&'static str, fn(&mut RuleCompileLimits) -> &mut usize);

compile_limits! {
    max_lists: 256 => 1024,
    max_file_bytes: 1 << 20 => 4 << 20,
    max_total_bytes: 32 << 20 => 64 << 20,
    max_rules_per_list: 25_000 => 100_000,
    max_indexed_rules_per_profile: 100_000 => 250_000,
    max_indexed_rules_total: 500_000 => 1_000_000,
    max_advanced_rules_per_profile: 256 => 512,
    max_advanced_rules_total: 2048 => 4096,
    max_regex_rules_per_profile: 32 => 64,
    max_regex_rules_total: 128 => 256,
    max_store_indexed_rules: 500_000 => 1_000_000,
    max_store_advanced_rules: 2048 => 4096,
    max_store_regex_rules: 128 => 256,
    max_rule_bytes: 4096 => 16384,
    max_regex_program_bytes: 1 << 20 => 2 << 20,
    max_store_compiled_bytes: 32 << 20 => 64 << 20,
    max_compiled_bytes_per_profile: 8 << 20 => 16 << 20,
    max_compiled_bytes_total: 32 << 20 => 64 << 20,
}

impl RuleCompileLimits {
    pub(crate) fn check_store_counts(
        &self,
        counts: ProjectionCounts,
    ) -> Result<(), BudgetExceeded> {
        ensure(
            "max_store_indexed_rules",
            counts.indexed,
            self.max_store_indexed_rules,
        )?;
        ensure(
            "max_store_advanced_rules",
            counts.advanced,
            self.max_store_advanced_rules,
        )?;
        ensure(
            "max_store_regex_rules",
            counts.regex,
            self.max_store_regex_rules,
        )
    }

    pub(crate) fn check_profile_counts(
        &self,
        counts: ProjectionCounts,
    ) -> Result<(), BudgetExceeded> {
        ensure(
            "max_indexed_rules_per_profile",
            counts.indexed,
            self.max_indexed_rules_per_profile,
        )?;
        ensure(
            "max_advanced_rules_per_profile",
            counts.advanced,
            self.max_advanced_rules_per_profile,
        )?;
        ensure(
            "max_regex_rules_per_profile",
            counts.regex,
            self.max_regex_rules_per_profile,
        )
    }

    pub(crate) fn check_total_counts(
        &self,
        counts: ProjectionCounts,
    ) -> Result<(), BudgetExceeded> {
        ensure(
            "max_indexed_rules_total",
            counts.indexed,
            self.max_indexed_rules_total,
        )?;
        ensure(
            "max_advanced_rules_total",
            counts.advanced,
            self.max_advanced_rules_total,
        )?;
        ensure(
            "max_regex_rules_total",
            counts.regex,
            self.max_regex_rules_total,
        )
    }
}

/// Distinct projections before merging index slots, counted per list and mount.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionCounts {
    pub indexed: usize,
    pub advanced: usize,
    pub regex: usize,
}

impl ProjectionCounts {
    pub fn checked_add(self, other: Self) -> Result<Self, BudgetExceeded> {
        Ok(Self {
            indexed: add(self.indexed, other.indexed)?,
            advanced: add(self.advanced, other.advanced)?,
            regex: add(self.regex, other.regex)?,
        })
    }
}

/// Deterministic byte quota, independent of allocator layout and RSS.
/// Store bytes include origins/ASTs, projections, declared-pack containers and
/// shared regex programs. Profile bytes include their own containers/projections
/// plus a virtual full charge per distinct regex. Snapshot bytes charge shared
/// programs/origins once, then add only profile-owned structures.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompiledCostV1 {
    pub store_bytes: usize,
    pub profile_bytes_total: usize,
    pub profile_owned_bytes_total: usize,
    pub snapshot_bytes: usize,
    pub store_counts: ProjectionCounts,
    pub profile_counts_total: ProjectionCounts,
    pub regex_programs: usize,
}

impl CompiledCostV1 {
    pub const VERSION: u32 = 2;
    /// Root slice descriptors, store Arc and snapshot container reserve.
    pub const STORE_BASE_BYTES: usize = 256;

    /// Eight-byte rounding, including checked rounding overflow.
    pub fn aligned_bytes(n: usize) -> Result<usize, BudgetExceeded> {
        mul(add(n, 7)? / 8, 8)
    }

    /// T(s) = 32 + A(UTF-8 byte length + 1), including inline strings.
    pub fn text_bytes(n: usize) -> Result<usize, BudgetExceeded> {
        add(32, Self::aligned_bytes(add(n, 1)?)?)
    }

    /// Origin header, owned list ID, semantic digest and all occurrence records.
    pub fn origin_bytes(id_bytes: usize, rows: usize) -> Result<usize, BudgetExceeded> {
        add(add(96, Self::text_bytes(id_bytes)?)?, mul(48, rows)?)
    }

    /// AST tag/flags and its single owned normalized pattern.
    pub fn ast_bytes(pattern_bytes: usize) -> Result<usize, BudgetExceeded> {
        add(32, Self::text_bytes(pattern_bytes)?)
    }

    pub fn indexed_bytes(domain_bytes: usize) -> Result<usize, BudgetExceeded> {
        add(128, Self::text_bytes(domain_bytes)?)
    }

    pub fn advanced_bytes(pattern_bytes: usize) -> Result<usize, BudgetExceeded> {
        add(96, Self::text_bytes(pattern_bytes)?)
    }

    /// R bytes for each of at most two dense automata (ordinary search and
    /// Unicode boundary search), plus 64 KiB for their representations and Arc.
    /// The second automaton's reservation is charged even when unnecessary.
    pub fn regex_bytes(program_limit: usize) -> Result<usize, BudgetExceeded> {
        add(mul(2, program_limit)?, 65536)
    }

    /// Mounted alternatives remain charged even when their index slots lose.
    pub fn sidecar_bytes(rules: usize) -> Result<usize, BudgetExceeded> {
        add(32, Self::aligned_bytes(mul(4, rules)?)?)
    }

    /// Empty containers still consume quota: a pack costs 96 + T(id), and a
    /// profile costs 128 + T(id). Projection charges include their token storage.
    pub(crate) fn pack_bytes(id_bytes: usize) -> Result<usize, BudgetExceeded> {
        add(96, Self::text_bytes(id_bytes)?)
    }
    pub(crate) fn profile_bytes(id_bytes: usize) -> Result<usize, BudgetExceeded> {
        add(128, Self::text_bytes(id_bytes)?)
    }
}
