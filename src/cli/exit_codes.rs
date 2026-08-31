//! The `warden` CLI exit-code contract — one definition, every verb.
//!
//! Exit codes are the scripting API. A monitoring probe, a systemd
//! `ExecStartPre=`, or an installer's `if warden … ; then` reads the code
//! and nothing else; anything a script must learn by grepping stdout makes
//! every wording change a breaking change. Before this module each handler
//! invented its own convention — `lists refresh` returned `Ok(())` on the
//! same config-load failure that `resolve` exited [`CONFIG`] for and
//! `main.rs` exited [`FAILURE`] for.
//!
//! # The contract
//!
//! | Code | Meaning |
//! |------|---------|
//! | [`SUCCESS`] (0) | the operation succeeded |
//! | [`FAILURE`] (1) | the operation failed |
//! | [`CONFIG`]  (2) | the configuration could not be loaded, or is invalid |
//! | [`NEGATIVE`] (3) | "the answer is no" — the diagnostic verbs only |
//!
//! [`NEGATIVE`] is the one that earns its keep. `warden query <domain>`
//! answering BLOCKED and `warden resolve <ip>` answering REFUSED are not
//! failures — the command did exactly its job — but a script needs to
//! branch on the answer. Before this, the only way to ask "is this domain
//! blocked?" was to grep stdout for the word `BLOCKED`.
//!
//! # Which verbs may return [`NEGATIVE`]
//!
//! Only the read-only diagnostic verbs, and only for the specific verdict
//! documented on the verb:
//!
//! | Verb | [`NEGATIVE`] means |
//! |------|--------------------|
//! | `query <domain>` | BLOCKED |
//! | `resolve <ip>` | REFUSED |
//! | `config diff <other>` | the two configs differ |
//!
//! A mutating verb must never return 3; "the change did not happen" is a
//! [`FAILURE`], not an answer.
//!
//! `config diff` joined the list because it had the exact defect the code
//! was created to remove: it returned [`FAILURE`] when it found
//! differences, so `warden config diff live backup.toml` could not tell a
//! script "these differ" apart from "the comparison itself broke" — and
//! the second is the one that must abort a restore. Finding a difference
//! is the verb succeeding.
//!
//! # Collision with clap: usage errors are also 2
//!
//! `clap` exits **2** on a usage error (unknown flag, missing required
//! argument, bad value) before any handler runs. That overlaps [`CONFIG`],
//! and it cannot be changed without overriding clap's error path for all
//! ~138 command paths. The two are distinguishable on stderr — a usage
//! error always carries clap's `Usage:` block, a config error never does —
//! and they are adjacent in meaning ("the input to this program was
//! unusable"), so the collision is documented rather than fixed.
//!
//! **This matters to the exit-code fence** (`tests/cli_exit_code_fence.rs`):
//! asserting a non-zero exit proves nothing if the verb died in the parser.
//! The fence therefore builds arg vectors that parse cleanly and asserts
//! stderr is free of clap's usage markers.

/// The operation succeeded.
pub const SUCCESS: i32 = 0;

/// The operation failed: the daemon was unreachable, a write was refused,
/// a download did not complete. The thing the operator asked for did not
/// happen.
pub const FAILURE: i32 = 1;

/// The configuration could not be loaded, or is invalid.
///
/// Distinct from [`FAILURE`] because the remedy is different: the operator
/// must fix a file, not retry the command or start the daemon. Note the
/// clap collision documented in the module docs — `clap` also exits 2 on a
/// usage error.
pub const CONFIG: i32 = 2;

/// "The answer is no." Reserved for the read-only diagnostic verbs so a
/// script can branch on the verdict without parsing stdout:
/// `warden query` says BLOCKED, `warden resolve` says REFUSED,
/// `warden config diff` says the two configs differ.
///
/// Never returned by a mutating verb.
pub const NEGATIVE: i32 = 3;

/// One-line summary of the contract, for a `--help` epilogue or an error
/// hint. Kept next to the constants so the prose cannot drift from them.
pub const CONTRACT_SUMMARY: &str =
    "exit codes: 0 success · 1 failed · 2 config invalid · 3 negative answer (query BLOCKED, resolve REFUSED, config diff DIFFERS)";

/// Exit the process with `code`, skipping the `std::process::exit` call
/// entirely when the code is [`SUCCESS`].
///
/// Exists so call-sites in `main.rs` read as one line instead of the
/// `if code != 0 { std::process::exit(code) }` that was copy-pasted at
/// five dispatch arms, each an opportunity to forget the check.
///
/// # Panics
///
/// Never returns when `code != SUCCESS`.
pub fn exit_with(code: i32) {
    if code != SUCCESS {
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four codes must stay distinct — a duplicate would silently
    /// merge two operator-visible states into one, which is the exact
    /// defect this module exists to remove.
    #[test]
    fn the_four_codes_are_distinct() {
        let all = [SUCCESS, FAILURE, CONFIG, NEGATIVE];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two contract codes collided");
            }
        }
    }

    /// Success must be 0 — the shell's definition, not ours.
    #[test]
    fn success_is_zero_and_the_rest_are_not() {
        assert_eq!(SUCCESS, 0);
        for code in [FAILURE, CONFIG, NEGATIVE] {
            assert_ne!(code, 0, "a failure code that is 0 is the original bug");
        }
    }

    /// The summary string is what an operator reads; if a code is ever
    /// renumbered, this catches the prose going stale.
    #[test]
    fn contract_summary_names_every_code() {
        for code in [SUCCESS, FAILURE, CONFIG, NEGATIVE] {
            assert!(
                CONTRACT_SUMMARY.contains(&code.to_string()),
                "CONTRACT_SUMMARY does not mention code {code}: {CONTRACT_SUMMARY}"
            );
        }
    }
}
