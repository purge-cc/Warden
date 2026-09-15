use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ahash::RandomState;
use compact_str::CompactString;
use sha2::{Digest, Sha256};

use super::admission::SnapshotLease;
use super::ast::check_record;
use super::decision::{best, reduce, AllowGrant, RankedHit, ReducedDecision, RuleTier, RuleToken};
use super::limits::{add, ensure};
use super::regex::RegexProgram;
use super::{
    parse_rule_ast, AstError, BudgetExceeded, CompileAdmission, CompiledCostV1, ExternalMatches,
    OperatorPattern, OperatorRuleAst, ProjectionCounts, RuleCompileLimits, RuleDecision, RuleHit,
    RuleKey, Verdict,
};
use crate::config::schema::id::Id;

/// Bytes of one declared UTF-8 pack, supplied by the caller's coherent reader.
#[derive(Debug, Clone, Copy)]
pub struct PackSource<'a> {
    pub list_id: &'a str,
    pub content: &'a str,
}

/// An explicit profile materialization; mounts carry no ordering authority.
#[derive(Debug, Clone, Copy)]
pub struct ProfileMounts<'a> {
    pub profile_id: &'a str,
    pub custom_lists: &'a [&'a str],
    pub block_all: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error(transparent)]
    BudgetExceeded(#[from] BudgetExceeded),
    #[error("invalid entity ID: {0}")]
    InvalidId(String),
    #[error("duplicate list declaration: {0}")]
    DuplicateList(Id),
    #[error("duplicate profile declaration: {0}")]
    DuplicateProfile(Id),
    #[error("profile {profile} mounts {list} more than once")]
    DuplicateMount { profile: Id, list: Id },
    #[error("profile {profile} mounts undeclared list {list}")]
    UnknownMount { profile: Id, list: Id },
    #[error("list {list}, row {row}: {source}")]
    InvalidRule {
        list: Id,
        row: u32,
        #[source]
        source: AstError,
    },
    #[error("list {list}, row {row}: regex compilation failed: {detail}")]
    InvalidRegex { list: Id, row: u32, detail: String },
    #[error("list {list}, row {row}: regex automaton construction failed: {detail}")]
    RegexConstruction { list: Id, row: u32, detail: String },
    #[error("list {list}, row {row}: regex {stage} budget exceeded: {source}")]
    RegexBudgetExceeded {
        list: Id,
        row: u32,
        stage: &'static str,
        #[source]
        source: BudgetExceeded,
    },
}

/// One occurrence in the exact source pack. Offsets and lengths include the
/// physical line terminator, and the digest covers those same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRow {
    pub line: u32,
    pub byte_offset: u32,
    pub byte_len: u32,
    pub digest: [u8; 32],
}

/// Immutable occurrence sidecar for one semantic rule within one list.
#[derive(Debug)]
pub struct RuleOrigin {
    list_id: Id,
    rule_key: RuleKey,
    pack_revision: [u8; 32],
    source_rows: Box<[SourceRow]>,
}

impl RuleOrigin {
    pub fn list_id(&self) -> &Id {
        &self.list_id
    }
    pub fn rule_key(&self) -> RuleKey {
        self.rule_key
    }
    pub fn pack_revision(&self) -> [u8; 32] {
        self.pack_revision
    }
    pub fn source_rows(&self) -> &[SourceRow] {
        &self.source_rows
    }
}

#[derive(Debug)]
pub struct PackSummary {
    revision: [u8; 32],
    source_bytes: usize,
    source_rule_rows: usize,
    tokens: Box<[RuleToken]>,
    counts: ProjectionCounts,
    projection_bytes: usize,
}

impl PackSummary {
    pub fn revision(&self) -> [u8; 32] {
        self.revision
    }
    pub fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    pub fn source_rule_rows(&self) -> usize {
        self.source_rule_rows
    }
    #[cfg(test)]
    pub(super) fn tokens(&self) -> &[RuleToken] {
        &self.tokens
    }
    pub fn counts(&self) -> ProjectionCounts {
        self.counts
    }
}

#[derive(Debug)]
struct StoredRule {
    ast: OperatorRuleAst,
    origin: RuleOrigin,
    program: Option<Arc<RegexProgram>>,
}

/// All declared packs and normalized rules, including unmounted policy.
#[derive(Debug)]
pub struct CompiledRuleStore {
    rules: Box<[StoredRule]>,
    packs: Box<[(Id, PackSummary)]>,
}

impl CompiledRuleStore {
    pub(super) fn origin(&self, token: RuleToken) -> Option<&RuleOrigin> {
        self.rules.get(token.index()).map(|rule| &rule.origin)
    }
    pub(super) fn ast(&self, token: RuleToken) -> Option<&OperatorRuleAst> {
        self.rules.get(token.index()).map(|rule| &rule.ast)
    }
    pub fn packs(&self) -> &[(Id, PackSummary)] {
        &self.packs
    }
    pub fn pack(&self, id: &Id) -> Option<&PackSummary> {
        self.packs
            .binary_search_by(|(key, _)| key.cmp(id))
            .ok()
            .map(|i| &self.packs[i].1)
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    pub fn rules(&self) -> impl ExactSizeIterator<Item = RuleHit<'_>> {
        self.rules.iter().enumerate().map(move |(rank, rule)| {
            RuleHit::new(
                self,
                RankedHit {
                    tier: rule.ast.tier(),
                    token: RuleToken(rank as u32),
                },
            )
        })
    }
}

#[derive(Debug)]
enum AdvancedPattern {
    Wildcard(CompactString),
    Regex(Arc<RegexProgram>),
}

#[derive(Debug)]
struct AdvancedRule {
    pattern: AdvancedPattern,
    hit: RankedHit,
}

pub(super) type ExactSlots = [u32; 4];
type ExactIndex = HashMap<CompactString, ExactSlots, RandomState>;

const EMPTY_TOKEN: u32 = u32::MAX;

const _: () = assert!(
    RuleCompileLimits::HARD_CEILINGS.max_store_indexed_rules
        + RuleCompileLimits::HARD_CEILINGS.max_store_advanced_rules
        < u32::MAX as usize
);

#[inline(always)]
pub(super) fn indexed_winner(slots: &ExactSlots) -> Option<RankedHit> {
    const ORDINARY_DENY: usize = RuleTier::OrdinaryDeny as usize;
    const ORDINARY_ALLOW: usize = RuleTier::OrdinaryAllow as usize;
    const IMPORTANT_DENY: usize = RuleTier::ImportantDeny as usize;
    const IMPORTANT_ALLOW: usize = RuleTier::ImportantAllow as usize;

    let (tier, token) = if slots[IMPORTANT_ALLOW] != EMPTY_TOKEN {
        (RuleTier::ImportantAllow, slots[IMPORTANT_ALLOW])
    } else if slots[IMPORTANT_DENY] != EMPTY_TOKEN {
        (RuleTier::ImportantDeny, slots[IMPORTANT_DENY])
    } else if slots[ORDINARY_ALLOW] != EMPTY_TOKEN {
        (RuleTier::OrdinaryAllow, slots[ORDINARY_ALLOW])
    } else if slots[ORDINARY_DENY] != EMPTY_TOKEN {
        (RuleTier::OrdinaryDeny, slots[ORDINARY_DENY])
    } else {
        return None;
    };
    Some(RankedHit {
        tier,
        token: RuleToken(token),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchProjection {
    Exact,
    WildcardApex,
    WildcardDescendant,
    Regex,
}

/// One matching mounted alternative, including its losing or duplicate origins.
#[derive(Debug, Clone, Copy)]
pub struct RuleExplanation<'a> {
    pub rule: RuleHit<'a>,
    pub projection: MatchProjection,
}

/// Immutable profile index and advanced programs, owning the issuing sidecar.
#[derive(Debug)]
pub struct CompiledProfile {
    store: Arc<CompiledRuleStore>,
    index: ExactIndex,
    advanced: Box<[AdvancedRule]>,
    mounted: Box<[RuleToken]>,
    counts: ProjectionCounts,
    compiled_bytes: usize,
    owned_bytes: usize,
    block_all: bool,
    min_indexed_len: u8,
}

impl CompiledProfile {
    pub fn store(&self) -> &CompiledRuleStore {
        &self.store
    }
    pub fn counts(&self) -> ProjectionCounts {
        self.counts
    }
    pub fn compiled_bytes(&self) -> usize {
        self.compiled_bytes
    }
    pub fn owned_bytes(&self) -> usize {
        self.owned_bytes
    }
    pub fn indexed_domains(&self) -> usize {
        self.index.len()
    }
    pub fn advanced_len(&self) -> usize {
        self.advanced.len()
    }

    /// Input is the normalized lowercase QNAME without a trailing root dot.
    /// Exact rules match the name and descendants through a byte-offset walk.
    #[inline]
    pub fn lookup(&self, domain: &str) -> Option<RuleHit<'_>> {
        self.lookup_hit(domain)
            .map(|hit| RuleHit::new(&self.store, hit))
    }

    #[inline(always)]
    fn lookup_hit(&self, domain: &str) -> Option<RankedHit> {
        debug_assert!(!domain.bytes().any(|b| b.is_ascii_uppercase()));
        let mut winner = None;
        if !self.index.is_empty() {
            if let Some(slots) = self.index.get(domain) {
                winner = indexed_winner(slots);
            } else {
                for (i, &byte) in domain.as_bytes().iter().enumerate() {
                    if byte != b'.' {
                        continue;
                    }
                    // Every later suffix is shorter, so none can reach an indexed key.
                    if domain.len() - (i + 1) < usize::from(self.min_indexed_len) {
                        break;
                    }
                    if let Some(slots) = self.index.get(&domain[i + 1..]) {
                        winner = indexed_winner(slots);
                        break;
                    }
                }
            }
        }
        for rule in &self.advanced {
            if best(winner, Some(rule.hit)) == winner {
                continue;
            }
            let matches = match &rule.pattern {
                AdvancedPattern::Wildcard(suffix) => {
                    domain.len() > suffix.len()
                        && domain.ends_with(suffix.as_str())
                        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
                }
                AdvancedPattern::Regex(program) => program.is_match(domain),
            };
            if matches {
                winner = best(winner, Some(rule.hit));
            }
        }
        winner
    }

    /// Attributed request decision. This is the source of the QNAME grant;
    /// response record owners must never be used to reconstruct that grant.
    #[inline(always)]
    pub fn evaluate_attributed(&self, domain: &str, external: ExternalMatches) -> RuleDecision<'_> {
        RuleDecision::new(
            self,
            reduce(self.lookup_hit(domain), None, self.block_all, external),
        )
    }

    #[inline(always)]
    pub fn evaluate(&self, domain: &str, external: ExternalMatches) -> Verdict {
        match self.lookup_hit(domain) {
            Some(hit) if hit.tier.is_allow() => Verdict::Forward,
            Some(_) => Verdict::Block,
            None if self.block_all || external == ExternalMatches::Deny => Verdict::Block,
            None => Verdict::Forward,
        }
    }

    pub(super) fn reduce_target(
        &self,
        domain: &str,
        grant: Option<AllowGrant>,
        external: ExternalMatches,
    ) -> ReducedDecision {
        reduce(self.lookup_hit(domain), grant, self.block_all, external)
    }

    pub(super) fn attribution(&self, token: Option<RuleToken>) -> Option<RuleHit<'_>> {
        token.map(|token| {
            RuleHit::new(
                &self.store,
                RankedHit {
                    tier: self.store.rules[token.index()].ast.tier(),
                    token,
                },
            )
        })
    }

    /// All mounted semantic rules in attribution order. Duplicate source rows
    /// are preserved in each origin; unmounted packs are absent.
    pub fn mounted_rules(&self) -> impl ExactSizeIterator<Item = RuleHit<'_>> {
        self.mounted
            .iter()
            .map(move |&token| self.attribution(Some(token)).unwrap())
    }

    /// Enumerate every matching mounted alternative outside the winner-only
    /// query index. A wildcard contributes one origin, even when both its apex
    /// projection and its descendant matcher apply.
    pub fn explain<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Iterator<Item = RuleExplanation<'a>> + 'a {
        self.mounted_rules().filter_map(move |rule| {
            let stored = &self.store.rules[rule.token.index()];
            let descendant = |suffix: &str| {
                domain.len() > suffix.len()
                    && domain.ends_with(suffix)
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            };
            let projection = match stored.ast.pattern() {
                OperatorPattern::Exact(suffix)
                    if domain == suffix.as_str() || descendant(suffix) =>
                {
                    MatchProjection::Exact
                }
                OperatorPattern::Wildcard(suffix)
                    if domain == suffix.as_str() && !stored.ast.noapex() =>
                {
                    MatchProjection::WildcardApex
                }
                OperatorPattern::Wildcard(suffix) if descendant(suffix) => {
                    MatchProjection::WildcardDescendant
                }
                OperatorPattern::Regex { .. }
                    if stored.program.as_ref().unwrap().is_match(domain) =>
                {
                    MatchProjection::Regex
                }
                _ => return None,
            };
            Some(RuleExplanation { rule, projection })
        })
    }
}

/// One fully validated offline candidate. No partial store/profile is returned.
#[derive(Debug)]
pub struct CompiledOperatorRules {
    store: Arc<CompiledRuleStore>,
    profiles: Box<[(Id, CompiledProfile)]>,
    cost: CompiledCostV1,
    // Released after profile/store fields, including all their shared programs.
    _lease: SnapshotLease,
}

impl CompiledOperatorRules {
    pub fn store(&self) -> &CompiledRuleStore {
        &self.store
    }
    pub fn profiles(&self) -> &[(Id, CompiledProfile)] {
        &self.profiles
    }
    /// Resolve a profile id once during resolver-map construction.
    /// The returned index is valid for the lifetime of this immutable
    /// snapshot and can therefore be retained by a runtime binding.
    #[inline]
    pub fn profile_index(&self, id: &Id) -> Option<usize> {
        self.profiles.binary_search_by(|(key, _)| key.cmp(id)).ok()
    }
    /// Direct profile access for a previously checked snapshot-local index.
    #[inline(always)]
    pub fn profile_at(&self, index: usize) -> Option<&CompiledProfile> {
        self.profiles.get(index).map(|(_, profile)| profile)
    }
    pub fn profile(&self, id: &Id) -> Option<&CompiledProfile> {
        self.profile_index(id)
            .and_then(|index| self.profile_at(index))
    }
    pub fn cost(&self) -> CompiledCostV1 {
        self.cost
    }

    /// Preflight all source, projection and materialization quotas before any
    /// regex compilation. Regex programs share only within this immutable build.
    /// Admission first reserves the candidate's full byte ceiling, then shrinks
    /// it to the computed charge before building automata. The returned snapshot
    /// retains that lease until its final owner drops it.
    pub fn compile(
        packs: &[PackSource<'_>],
        profiles: &[ProfileMounts<'_>],
        limits: RuleCompileLimits,
        admission: &CompileAdmission,
    ) -> Result<Self, CompileError> {
        limits.validate()?;
        let mut lease = admission.begin(limits.max_compiled_bytes_total)?;
        let sources = preflight_sources(packs, &limits)?;
        let (mut store, mut cost) = parse_store(sources, &limits)?;
        let plans = plan_profiles(&store, profiles, &limits, &mut cost)?;
        lease.charge(cost.snapshot_bytes);
        compile_programs(&mut store, &limits)?;
        let store = Arc::new(store);
        let mut profiles: Vec<_> = plans
            .into_iter()
            .map(|plan| {
                let mut index =
                    ExactIndex::with_capacity_and_hasher(plan.counts.indexed, RandomState::new());
                let mut advanced = Vec::with_capacity(plan.counts.advanced);
                let mut min_indexed_len = u8::MAX;
                for &token in &plan.tokens {
                    let rule = &store.rules[token.index()];
                    let hit = RankedHit {
                        tier: rule.ast.tier(),
                        token,
                    };
                    if let Some(domain) = rule.ast.indexed_domain() {
                        min_indexed_len =
                            min_indexed_len.min(u8::try_from(domain.len()).unwrap_or(u8::MAX));
                        let slots = index.entry(domain.clone()).or_insert([EMPTY_TOKEN; 4]);
                        slots[hit.tier as usize] = slots[hit.tier as usize].min(hit.token.0);
                    }
                    let pattern = match rule.ast.pattern() {
                        OperatorPattern::Exact(_) => continue,
                        OperatorPattern::Wildcard(suffix) => {
                            AdvancedPattern::Wildcard(suffix.clone())
                        }
                        OperatorPattern::Regex { .. } => AdvancedPattern::Regex(Arc::clone(
                            rule.program
                                .as_ref()
                                .expect("preflight compiles every regex"),
                        )),
                    };
                    advanced.push(AdvancedRule { pattern, hit });
                }
                for &token in &plan.tokens {
                    let Some(domain) = store.rules[token.index()].ast.indexed_domain() else {
                        continue;
                    };
                    let mut ancestor_winners = [EMPTY_TOKEN; 4];
                    let mut offset = 0;
                    while let Some(relative) = domain[offset..].find('.') {
                        offset += relative + 1;
                        if let Some(slots) = index.get(&domain[offset..]) {
                            for (winner, token) in ancestor_winners.iter_mut().zip(slots) {
                                *winner = (*winner).min(*token);
                            }
                        }
                    }
                    let slots = index
                        .get_mut(domain)
                        .expect("indexed rule creates its domain entry");
                    for (slot, ancestor) in slots.iter_mut().zip(ancestor_winners) {
                        *slot = (*slot).min(ancestor);
                    }
                }
                (
                    plan.id,
                    CompiledProfile {
                        store: Arc::clone(&store),
                        index,
                        advanced: advanced.into_boxed_slice(),
                        mounted: plan.tokens.into_boxed_slice(),
                        counts: plan.counts,
                        compiled_bytes: plan.compiled_bytes,
                        owned_bytes: plan.owned_bytes,
                        block_all: plan.block_all,
                        min_indexed_len,
                    },
                )
            })
            .collect();
        profiles.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(Self {
            store,
            profiles: profiles.into_boxed_slice(),
            cost,
            _lease: lease.finish(),
        })
    }
}

fn id(raw: &str) -> Result<Id, CompileError> {
    Id::new(raw).map_err(|error| CompileError::InvalidId(error.to_string()))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn row_number(n: usize) -> Result<u32, BudgetExceeded> {
    u32::try_from(n).map_err(|_| BudgetExceeded {
        limit: "source_row",
        actual: Some(n),
        maximum: u32::MAX as usize,
    })
}

// A pack accepts LF and CRLF physical terminators. Raw single-rule input has no
// terminator, and rejects CR/LF before trim. Digests retain the physical bytes.
fn row_text(raw: &str) -> &str {
    match raw.strip_suffix('\n') {
        Some(line) => line.strip_suffix('\r').unwrap_or(line),
        None => raw,
    }
}

fn is_rule(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && !text.starts_with('#')
}

fn preflight_sources<'a>(
    packs: &[PackSource<'a>],
    limits: &RuleCompileLimits,
) -> Result<BTreeMap<Id, &'a str>, CompileError> {
    ensure("max_lists", packs.len(), limits.max_lists)?;
    let mut sources = BTreeMap::new();
    let mut total_bytes = 0;
    // All byte limits precede line parsing, hashing and owned AST construction.
    for pack in packs {
        ensure("max_file_bytes", pack.content.len(), limits.max_file_bytes)?;
        total_bytes = add(total_bytes, pack.content.len())?;
        ensure("max_total_bytes", total_bytes, limits.max_total_bytes)?;
        let list = id(pack.list_id)?;
        if sources.insert(list.clone(), pack.content).is_some() {
            return Err(CompileError::DuplicateList(list));
        }
    }
    for (list, content) in &sources {
        let mut rows = 0;
        for (index, raw) in content.split_inclusive('\n').enumerate() {
            let text = row_text(raw);
            let row = row_number(add(index, 1)?)?;
            check_record(text).map_err(|source| CompileError::InvalidRule {
                list: list.clone(),
                row,
                source,
            })?;
            if is_rule(text) {
                rows = add(rows, 1)?;
                ensure("max_rules_per_list", rows, limits.max_rules_per_list)?;
                ensure("max_rule_bytes", text.len(), limits.max_rule_bytes)?;
            }
        }
    }
    Ok(sources)
}

fn projections(ast: &OperatorRuleAst) -> ProjectionCounts {
    ProjectionCounts {
        indexed: usize::from(ast.indexed_domain().is_some()),
        advanced: usize::from(!matches!(ast.pattern(), OperatorPattern::Exact(_))),
        regex: usize::from(matches!(ast.pattern(), OperatorPattern::Regex { .. })),
    }
}

fn projection_bytes(ast: &OperatorRuleAst) -> Result<usize, BudgetExceeded> {
    let mut bytes = 0;
    if let Some(domain) = ast.indexed_domain() {
        bytes = CompiledCostV1::indexed_bytes(domain.len())?;
    }
    if !matches!(ast.pattern(), OperatorPattern::Exact(_)) {
        bytes = add(bytes, CompiledCostV1::advanced_bytes(ast.text().len())?)?;
    }
    Ok(bytes)
}

/// Compiler policy version identifies the builder options, independently of
/// semantic rule identity. Cache sharing never crosses a candidate or binary.
const REGEX_COMPILER_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegexKey<'a> {
    source: &'a str,
    case_insensitive: bool,
    compiler_version: u32,
    limit: usize,
}

fn regex_key<'a>(ast: &'a OperatorRuleAst, limits: &RuleCompileLimits) -> Option<RegexKey<'a>> {
    match ast.pattern() {
        OperatorPattern::Regex {
            source,
            case_insensitive,
        } => Some(RegexKey {
            source,
            case_insensitive: *case_insensitive,
            compiler_version: REGEX_COMPILER_VERSION,
            limit: limits.max_regex_program_bytes,
        }),
        _ => None,
    }
}

fn parse_store(
    sources: BTreeMap<Id, &str>,
    limits: &RuleCompileLimits,
) -> Result<(CompiledRuleStore, CompiledCostV1), CompileError> {
    // Sorted list IDs and semantic keys assign dense attribution ranks.
    // Duplicate occurrences share one origin; its first row is the minimum
    // source row, so no source-order tie remains between distinct tokens.
    let mut rules = Vec::new();
    let mut packs = BTreeMap::new();
    let mut cost = CompiledCostV1 {
        store_bytes: CompiledCostV1::STORE_BASE_BYTES,
        ..Default::default()
    };
    for (list, content) in sources {
        let revision = digest(content.as_bytes());
        let mut entries: BTreeMap<RuleKey, (OperatorRuleAst, Vec<SourceRow>)> = BTreeMap::new();
        let mut source_rule_rows = 0;
        let mut offset = 0;
        for (index, raw) in content.split_inclusive('\n').enumerate() {
            let text = row_text(raw);
            if is_rule(text) {
                source_rule_rows = add(source_rule_rows, 1)?;
                let row = row_number(add(index, 1)?)?;
                let ast = parse_rule_ast(text).map_err(|source| CompileError::InvalidRule {
                    list: list.clone(),
                    row,
                    source,
                })?;
                let occurrence = SourceRow {
                    line: row,
                    byte_offset: row_number(offset)?,
                    byte_len: row_number(raw.len())?,
                    digest: digest(raw.as_bytes()),
                };
                entries
                    .entry(ast.rule_key())
                    .or_insert_with(|| (ast, Vec::new()))
                    .1
                    .push(occurrence);
            }
            offset = add(offset, raw.len())?;
        }
        cost.store_bytes = add(
            cost.store_bytes,
            CompiledCostV1::pack_bytes(list.as_str().len())?,
        )?;
        let mut summary = PackSummary {
            revision,
            source_bytes: content.len(),
            source_rule_rows,
            tokens: Box::new([]),
            counts: ProjectionCounts::default(),
            projection_bytes: 0,
        };
        let mut tokens = Vec::with_capacity(entries.len());
        for (key, (ast, rows)) in entries {
            let token = RuleToken(row_number(rules.len())?);
            let counts = projections(&ast);
            summary.counts = summary.counts.checked_add(counts)?;
            cost.store_counts = cost.store_counts.checked_add(counts)?;
            limits.check_store_counts(cost.store_counts)?;
            let bytes = projection_bytes(&ast)?;
            summary.projection_bytes = add(summary.projection_bytes, bytes)?;
            cost.store_bytes = add(cost.store_bytes, bytes)?;
            cost.store_bytes = add(
                cost.store_bytes,
                CompiledCostV1::ast_bytes(ast.text().len())?,
            )?;
            cost.store_bytes = add(
                cost.store_bytes,
                CompiledCostV1::origin_bytes(list.as_str().len(), rows.len())?,
            )?;
            ensure(
                "max_store_compiled_bytes",
                cost.store_bytes,
                limits.max_store_compiled_bytes,
            )?;
            tokens.push(token);
            rules.push(StoredRule {
                ast,
                origin: RuleOrigin {
                    list_id: list.clone(),
                    rule_key: key,
                    pack_revision: revision,
                    source_rows: rows.into_boxed_slice(),
                },
                program: None,
            });
        }
        summary.tokens = tokens.into_boxed_slice();
        packs.insert(list, summary);
    }
    let keys: BTreeSet<_> = rules
        .iter()
        .filter_map(|rule| regex_key(&rule.ast, limits))
        .collect();
    cost.regex_programs = keys.len();
    for _ in keys {
        cost.store_bytes = add(
            cost.store_bytes,
            CompiledCostV1::regex_bytes(limits.max_regex_program_bytes)?,
        )?;
    }
    ensure(
        "max_store_compiled_bytes",
        cost.store_bytes,
        limits.max_store_compiled_bytes,
    )?;
    cost.snapshot_bytes = cost.store_bytes;
    ensure(
        "max_compiled_bytes_total",
        cost.snapshot_bytes,
        limits.max_compiled_bytes_total,
    )?;
    Ok((
        CompiledRuleStore {
            rules: rules.into_boxed_slice(),
            packs: packs.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        },
        cost,
    ))
}

struct ProfilePlan {
    id: Id,
    tokens: Vec<RuleToken>,
    counts: ProjectionCounts,
    compiled_bytes: usize,
    owned_bytes: usize,
    block_all: bool,
}

fn plan_profiles(
    store: &CompiledRuleStore,
    profiles: &[ProfileMounts<'_>],
    limits: &RuleCompileLimits,
    cost: &mut CompiledCostV1,
) -> Result<Vec<ProfilePlan>, CompileError> {
    let mut plans = Vec::new();
    let mut seen = BTreeSet::new();
    for profile in profiles {
        let profile_id = id(profile.profile_id)?;
        if !seen.insert(profile_id.clone()) {
            return Err(CompileError::DuplicateProfile(profile_id));
        }
        let mut mounts = BTreeSet::new();
        let mut tokens = Vec::new();
        let mut counts = ProjectionCounts::default();
        let mut owned = CompiledCostV1::profile_bytes(profile_id.as_str().len())?;
        let mut keys = BTreeSet::new();
        for raw in profile.custom_lists {
            let list = id(raw)?;
            if !mounts.insert(list.clone()) {
                return Err(CompileError::DuplicateMount {
                    profile: profile_id,
                    list,
                });
            }
            let pack = store
                .pack(&list)
                .ok_or_else(|| CompileError::UnknownMount {
                    profile: profile_id.clone(),
                    list,
                })?;
            counts = counts.checked_add(pack.counts)?;
            limits.check_profile_counts(counts)?;
            owned = add(owned, pack.projection_bytes)?;
            ensure(
                "max_compiled_bytes_per_profile",
                owned,
                limits.max_compiled_bytes_per_profile,
            )?;
            for token in &pack.tokens {
                if let Some(key) = regex_key(&store.rules[token.index()].ast, limits) {
                    keys.insert(key);
                }
                tokens.push(*token);
            }
        }
        tokens.sort_unstable();
        owned = add(owned, CompiledCostV1::sidecar_bytes(tokens.len())?)?;
        let mut compiled = owned;
        for _ in keys {
            compiled = add(
                compiled,
                CompiledCostV1::regex_bytes(limits.max_regex_program_bytes)?,
            )?;
        }
        ensure(
            "max_compiled_bytes_per_profile",
            compiled,
            limits.max_compiled_bytes_per_profile,
        )?;
        cost.profile_counts_total = cost.profile_counts_total.checked_add(counts)?;
        limits.check_total_counts(cost.profile_counts_total)?;
        cost.profile_bytes_total = add(cost.profile_bytes_total, compiled)?;
        cost.profile_owned_bytes_total = add(cost.profile_owned_bytes_total, owned)?;
        cost.snapshot_bytes = add(cost.store_bytes, cost.profile_owned_bytes_total)?;
        ensure(
            "max_compiled_bytes_total",
            cost.snapshot_bytes,
            limits.max_compiled_bytes_total,
        )?;
        plans.push(ProfilePlan {
            id: profile_id,
            tokens,
            counts,
            compiled_bytes: compiled,
            owned_bytes: owned,
            block_all: profile.block_all,
        });
    }
    Ok(plans)
}

fn compile_programs(
    store: &mut CompiledRuleStore,
    limits: &RuleCompileLimits,
) -> Result<(), CompileError> {
    let mut programs = BTreeMap::new();
    for rule in &mut store.rules {
        if let Some(key) = regex_key(&rule.ast, limits) {
            let program = if let Some(program) = programs.get(&key) {
                Arc::clone(program)
            } else {
                let compiled = RegexProgram::compile(key.source, key.case_insensitive, key.limit)
                    .map_err(|error| {
                    error.context(
                        rule.origin.list_id.clone(),
                        rule.origin.source_rows[0].line,
                        key.limit,
                    )
                })?;
                let program = Arc::new(compiled);
                programs.insert(key, Arc::clone(&program));
                program
            };
            rule.program = Some(program);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_program_arcs_share_across_actions_lists_and_profiles() {
        let c = super::super::compile_isolated(
            &[
                PackSource {
                    list_id: "a",
                    content: "/example/\n@@/example/",
                },
                PackSource {
                    list_id: "b",
                    content: "/example/",
                },
            ],
            &[
                ProfileMounts {
                    profile_id: "one",
                    custom_lists: &["a", "b"],
                    block_all: false,
                },
                ProfileMounts {
                    profile_id: "two",
                    custom_lists: &["a"],
                    block_all: false,
                },
            ],
            RuleCompileLimits::default(),
        )
        .unwrap();
        let shared = c.store.rules[0].program.as_ref().unwrap();
        for rule in &c.store.rules {
            assert!(Arc::ptr_eq(shared, rule.program.as_ref().unwrap()));
        }
        for (_, profile) in &c.profiles {
            for rule in &profile.advanced {
                match &rule.pattern {
                    AdvancedPattern::Regex(program) => assert!(Arc::ptr_eq(shared, program)),
                    AdvancedPattern::Wildcard(_) => panic!("unexpected wildcard"),
                }
            }
        }
    }
}
