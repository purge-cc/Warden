//! Isolated operator-policy compiler and immutable query evaluator.
//!
//! Compilation consumes in-memory declared packs and profile mounts. It performs
//! no I/O and publishes nothing. Queries retain the compiled profile (and its
//! shared store) so tokens, grants and origins belong to the same snapshot.

mod admission;
mod ast;
mod compiler;
mod decision;
mod limits;
mod regex;

pub use admission::CompileAdmission;
pub use ast::{parse_rule_ast, AstError, OperatorPattern, OperatorRuleAst, RuleKey};
pub use compiler::{
    CompileError, CompiledOperatorRules, CompiledProfile, CompiledRuleStore, MatchProjection,
    PackSource, PackSummary, ProfileMounts, RuleExplanation, RuleOrigin, SourceRow,
};
pub use decision::{
    ExternalMatches, GrantTier, RequestGrant, RuleDecision, RuleHit, RuleTier, TargetDecision,
    Verdict,
};
pub use limits::{BudgetExceeded, CompiledCostV1, ProjectionCounts, RuleCompileLimits};

#[cfg(test)]
use decision::{AllowGrant, RankedHit};

#[cfg(test)]
fn compile_isolated(
    packs: &[PackSource<'_>],
    profiles: &[ProfileMounts<'_>],
    limits: RuleCompileLimits,
) -> Result<CompiledOperatorRules, CompileError> {
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total.max(1), 1).unwrap();
    CompiledOperatorRules::compile(packs, profiles, limits, &admission)
}

#[cfg(test)]
mod allocation_tests;
#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod tests;
