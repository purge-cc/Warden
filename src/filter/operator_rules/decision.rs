use super::{CompiledProfile, CompiledRuleStore, OperatorRuleAst, RuleOrigin};

/// Dense attribution rank used only inside the owning snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct RuleToken(pub(super) u32);

impl RuleToken {
    pub(super) fn index(self) -> usize {
        self.0 as usize
    }
}

/// Increasing authority. Specificity and source order cannot change this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RuleTier {
    OrdinaryDeny,
    OrdinaryAllow,
    ImportantDeny,
    ImportantAllow,
}

impl RuleTier {
    pub(crate) fn from_flags(allow: bool, important: bool) -> Self {
        match (allow, important) {
            (false, false) => Self::OrdinaryDeny,
            (true, false) => Self::OrdinaryAllow,
            (false, true) => Self::ImportantDeny,
            (true, true) => Self::ImportantAllow,
        }
    }
    pub fn is_allow(self) -> bool {
        matches!(self, Self::OrdinaryAllow | Self::ImportantAllow)
    }
    pub fn is_important(self) -> bool {
        matches!(self, Self::ImportantDeny | Self::ImportantAllow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RankedHit {
    pub tier: RuleTier,
    pub token: RuleToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantTier {
    Ordinary,
    Important,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AllowGrant {
    pub tier: GrantTier,
    token: RuleToken,
    origin: GrantOrigin,
}

/// Attribution provenance for an allow grant.
///
/// A grant copied out of an original-QNAME decision has no target-local rule
/// behind it.  Keeping that case distinct prevents a response target from
/// claiming an arbitrary rule in the store as its winner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantOrigin {
    Rule,
    Request,
}

impl AllowGrant {
    fn rule_tier(self) -> RuleTier {
        match self.tier {
            GrantTier::Ordinary => RuleTier::OrdinaryAllow,
            GrantTier::Important => RuleTier::ImportantAllow,
        }
    }
}

/// An original-QNAME allow authority carried across an asynchronous request.
///
/// The value owns the compact grant payload while borrowing the exact compiled
/// profile that issued it.  Both the rule token and that issuer are retained:
/// a matching tier by itself is never response authority.  Consumers borrow
/// this value and validate the issuer before applying it.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct RequestGrant<'a> {
    issuer: &'a CompiledProfile,
    grant: AllowGrant,
}

impl<'a> RequestGrant<'a> {
    pub fn tier(&self) -> GrantTier {
        self.grant.tier
    }

    /// The original-QNAME rule that issued this authority.
    pub fn granting_rule(&self) -> RuleHit<'a> {
        let GrantOrigin::Rule = self.grant.origin else {
            unreachable!("request grants originate from an operator rule")
        };
        self.issuer
            .attribution(Some(self.grant.token))
            .expect("issuing profile owns request-grant token")
    }

    /// Whether this grant was issued by this exact immutable profile.
    ///
    /// Pointer identity is intentional: profiles from distinct snapshots may
    /// have identical rules and token numbers, but grants must not cross a
    /// reload boundary or a profile boundary.
    pub fn is_issued_by(&self, profile: &CompiledProfile) -> bool {
        std::ptr::eq(self.issuer, profile)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    Block,
}

/// Already-resolved external matches, after the caller's trust, direction and
/// subscription gates. Disabled represents a typed external-layer bypass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ExternalMatches {
    #[default]
    None,
    Disabled,
    Allow,
    Deny,
    AllowAndDeny,
}

/// Read-only attribution bound to the store that issued it. No public API
/// accepts a rank or hit as evaluation authority.
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::{RuleHit, RuleTier};
/// let forged = RuleHit { tier: RuleTier::ImportantAllow, token: 0 };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RuleHit<'a> {
    pub(super) tier: RuleTier,
    pub(super) token: RuleToken,
    store: &'a CompiledRuleStore,
}

impl PartialEq for RuleHit<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.store, other.store)
            && self.tier == other.tier
            && self.token == other.token
    }
}

impl Eq for RuleHit<'_> {}

impl<'a> RuleHit<'a> {
    pub(super) fn new(store: &'a CompiledRuleStore, hit: RankedHit) -> Self {
        Self {
            store,
            tier: hit.tier,
            token: hit.token,
        }
    }
    pub fn tier(self) -> RuleTier {
        self.tier
    }
    pub fn origin(self) -> &'a RuleOrigin {
        self.store
            .origin(self.token)
            .expect("issuing store owns rank")
    }
    pub fn ast(self) -> &'a OperatorRuleAst {
        self.store.ast(self.token).expect("issuing store owns rank")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReducedDecision {
    pub verdict: Verdict,
    pub winning_token: Option<RuleToken>,
    pub allow_grant: Option<AllowGrant>,
}

impl ReducedDecision {
    pub(super) const BLOCK: Self = Self {
        verdict: Verdict::Block,
        winning_token: None,
        allow_grant: None,
    };
}

/// Original-query evaluation and response authority, borrowed from its profile.
/// Target evaluations can only be issued through this value; they cannot be
/// replayed into another profile or substituted for the original query.
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::{RuleDecision, Verdict};
/// let forged = RuleDecision { verdict: Verdict::Forward };
/// ```
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::{CompiledOperatorRules, ExternalMatches, RuleDecision};
/// fn escape(snapshot: CompiledOperatorRules) -> RuleDecision<'static> {
///     snapshot.profiles()[0].1.evaluate_attributed("query.test", ExternalMatches::None)
/// }
/// ```
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::{CompiledProfile, ExternalMatches, RuleDecision};
/// fn replay(other: &CompiledProfile, request: RuleDecision<'_>) {
///     other.evaluate_target("target.test", request, ExternalMatches::None, true);
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct RuleDecision<'a> {
    profile: &'a CompiledProfile,
    decision: ReducedDecision,
}

impl<'a> RuleDecision<'a> {
    pub(super) fn new(profile: &'a CompiledProfile, decision: ReducedDecision) -> Self {
        Self { profile, decision }
    }

    pub fn verdict(&self) -> Verdict {
        self.decision.verdict
    }

    pub fn winning_rule(&self) -> Option<RuleHit<'a>> {
        self.profile.attribution(self.decision.winning_token)
    }

    pub fn grant_tier(&self) -> Option<GrantTier> {
        self.decision.allow_grant.map(|grant| grant.tier)
    }

    /// Capture the original-QNAME authority for response checks.
    ///
    /// It retains the winning rule token and borrows this immutable profile,
    /// so it cannot be forged from a tier or replayed into another profile.
    pub fn grant(&self) -> Option<RequestGrant<'a>> {
        let grant = self.decision.allow_grant?;
        match grant.origin {
            GrantOrigin::Rule => Some(RequestGrant {
                issuer: self.profile,
                grant,
            }),
            GrantOrigin::Request => None,
        }
    }

    /// Evaluate a validated target using only this request's original grant.
    pub fn evaluate_target(
        &self,
        domain: &str,
        external: ExternalMatches,
        structurally_valid: bool,
    ) -> TargetDecision<'a> {
        let decision = if !structurally_valid {
            ReducedDecision::BLOCK
        } else if self.verdict() == Verdict::Block {
            self.decision
        } else {
            self.profile
                .reduce_target(domain, self.decision.allow_grant, external)
        };
        TargetDecision {
            profile: self.profile,
            decision,
        }
    }

    /// Apply external response-IP policy to the original request decision.
    /// Structural validation precedes all grants; blocked requests stay blocked.
    pub fn response_ip_verdict(&self, external_deny: bool, structurally_valid: bool) -> Verdict {
        if !structurally_valid
            || self.verdict() == Verdict::Block
            || (external_deny && self.decision.allow_grant.is_none())
        {
            Verdict::Block
        } else {
            Verdict::Forward
        }
    }
}

impl CompiledProfile {
    /// Evaluate a response target using a grant captured from this same
    /// profile's original-QNAME decision.  This is the async-friendly form of
    /// `RuleDecision::evaluate_target`: no allocation, and the issuing
    /// profile is checked before a request grant can take effect.
    #[inline(always)]
    pub fn evaluate_target_with_grant(
        &self,
        domain: &str,
        grant: Option<&RequestGrant<'_>>,
        external: ExternalMatches,
        structurally_valid: bool,
    ) -> TargetDecision<'_> {
        let inherited = grant.and_then(|grant| {
            grant.is_issued_by(self).then_some(AllowGrant {
                tier: grant.tier(),
                token: grant.grant.token,
                origin: GrantOrigin::Request,
            })
        });
        let decision = if structurally_valid {
            self.reduce_target(domain, inherited, external)
        } else {
            ReducedDecision::BLOCK
        };
        TargetDecision {
            profile: self,
            decision,
        }
    }
}

/// One target's result. It exposes attribution, but grants no response authority.
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::TargetDecision;
/// fn replay(target: TargetDecision<'_>) {
///     target.response_ip_verdict(true, true);
/// }
/// ```
///
/// ```compile_fail
/// use purge_warden::filter::operator_rules::{ExternalMatches, TargetDecision};
/// fn replay(target: TargetDecision<'_>) {
///     target.evaluate_target("second.test", ExternalMatches::None, true);
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct TargetDecision<'a> {
    profile: &'a CompiledProfile,
    decision: ReducedDecision,
}

impl<'a> TargetDecision<'a> {
    pub fn verdict(&self) -> Verdict {
        self.decision.verdict
    }
    pub fn winning_rule(&self) -> Option<RuleHit<'a>> {
        self.profile.attribution(self.decision.winning_token)
    }

    /// The original-QNAME rule whose request authority won this target.
    ///
    /// This is distinct from [`Self::winning_rule`]: inherited authority is
    /// not a target-local rule, but its original attribution remains intact.
    pub fn inherited_granting_rule(&self) -> Option<RuleHit<'a>> {
        match self.decision.allow_grant.map(|grant| grant.origin) {
            Some(GrantOrigin::Request) => self.profile.attribution(Some(
                self.decision
                    .allow_grant
                    .expect("request origin has a grant")
                    .token,
            )),
            Some(GrantOrigin::Rule) | None => None,
        }
    }
}

#[inline(always)]
pub(super) fn best(a: Option<RankedHit>, b: Option<RankedHit>) -> Option<RankedHit> {
    match (a, b) {
        (Some(a), Some(b)) => Some(
            if b.tier > a.tier || (b.tier == a.tier && b.token < a.token) {
                b
            } else {
                a
            },
        ),
        (a, b) => a.or(b),
    }
}

#[inline(always)]
pub(super) fn reduce(
    hit: Option<RankedHit>,
    inherited: Option<AllowGrant>,
    block_all: bool,
    external: ExternalMatches,
) -> ReducedDecision {
    match best_with_grant(hit, inherited) {
        Some(GrantWinner::Rule(hit)) => {
            return ReducedDecision {
                verdict: if hit.tier.is_allow() {
                    Verdict::Forward
                } else {
                    Verdict::Block
                },
                winning_token: Some(hit.token),
                allow_grant: hit.tier.is_allow().then_some(AllowGrant {
                    tier: if hit.tier.is_important() {
                        GrantTier::Important
                    } else {
                        GrantTier::Ordinary
                    },
                    origin: GrantOrigin::Rule,
                    token: hit.token,
                }),
            };
        }
        Some(GrantWinner::Inherited(grant)) => {
            return ReducedDecision {
                verdict: Verdict::Forward,
                winning_token: None,
                allow_grant: Some(grant),
            };
        }
        None => {}
    }
    ReducedDecision {
        verdict: if block_all || external == ExternalMatches::Deny {
            Verdict::Block
        } else {
            Verdict::Forward
        },
        winning_token: None,
        allow_grant: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantWinner {
    Rule(RankedHit),
    Inherited(AllowGrant),
}

/// Resolve a target-local rule against an original-QNAME allow grant.
///
/// A request grant has an original-QNAME token but is not target-local. On an
/// equal tier it wins deliberately; target attribution stays distinct while
/// the original rule remains available through `inherited_granting_rule`.
#[inline(always)]
fn best_with_grant(hit: Option<RankedHit>, grant: Option<AllowGrant>) -> Option<GrantWinner> {
    match (hit, grant) {
        (
            Some(hit),
            Some(
                grant @ AllowGrant {
                    origin: GrantOrigin::Rule,
                    ..
                },
            ),
        ) => {
            let grant_hit = RankedHit {
                tier: grant.rule_tier(),
                token: grant.token,
            };
            match best(Some(hit), Some(grant_hit)) {
                Some(winner) if winner == hit => Some(GrantWinner::Rule(hit)),
                Some(_) => Some(GrantWinner::Inherited(grant)),
                None => unreachable!("two candidates always produce a winner"),
            }
        }
        (
            Some(hit),
            Some(
                grant @ AllowGrant {
                    origin: GrantOrigin::Request,
                    ..
                },
            ),
        ) => {
            if hit.tier > grant.rule_tier() {
                Some(GrantWinner::Rule(hit))
            } else {
                Some(GrantWinner::Inherited(grant))
            }
        }
        (Some(hit), None) => Some(GrantWinner::Rule(hit)),
        (None, Some(grant)) => Some(GrantWinner::Inherited(grant)),
        (None, None) => None,
    }
}
