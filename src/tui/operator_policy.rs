//! Typed TUI boundary for the daemon-owned operator policy workflow.
//!
//! Policy reads and mutations only speak the versioned IPC protocol; the sole
//! local filesystem exception is the private recovery journal used to retain
//! exact submitted requests across TUI restarts.

mod adapter;
mod controller;
mod recovery;
mod render;
mod workflow;

pub(crate) use adapter::AdapterError;
#[cfg(test)]
pub(crate) use adapter::{register_test_token, OperatorPolicyAdapter, RetainedPlan};
pub(crate) use controller::{
    handle_key, open, open_profile_after, read_catalog, read_rule_counts, read_rules,
    spawn_startup_resume, PolicyCatalog, PolicyChange, PolicyDialog, PolicyOrigin,
    PolicyRuleCounts, PolicyRules,
};
pub(crate) use recovery::ProfilePrefix;
pub(crate) use render::render;
#[cfg(test)]
pub(crate) use workflow::{
    OperatorPolicyWorkflow, RecoveryAction, RecoveryState, WorkflowState, WorkflowTicket,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod e2e_tests;
