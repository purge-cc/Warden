//! Frozen operator-facing strings introduced by the Sprint A CLI
//! hardening tail.
//!
//! # Why pin them
//!
//! Every string here is read by an operator, and several are read by a
//! *script* — an exit-code explanation is worthless if the wording under
//! it drifts into something a runbook no longer matches. Pinning them
//! byte-for-byte means a reword has to be deliberate: the test goes red,
//! and whoever changes the string changes this file in the same commit,
//! having thought about who else is reading it.
//!
//! # What this file does NOT do
//!
//! It does not pin a string with no emitter. `RULE_DANGLING_REF` was
//! exactly that — pinned in `frozen_strings_s43.rs`, recommending a flag
//! the binary rejected, describing a refusal that could not fire — and it
//! was retired in this sprint rather than reworded. A frozen suite is
//! only as trustworthy as its weakest pin; one guarding unreachable text
//! teaches the reader that the others might be decorative too.

use purge_warden::cli::commands::config::lint::STRICT_WARNINGS_ARE_FATAL;
use purge_warden::cli::commands::init::INIT_STDIN_CLOSED;
use purge_warden::cli::exit_codes::CONTRACT_SUMMARY;

// ── init, on a closed stdin ──────────────────────────────────────────

/// `warden init` without `--yes` is an interview; with stdin closed
/// there is nobody to interview.
///
/// The three prompts used to read `Ok(0)` (end of stream) and, because
/// `read_line` leaves the buffer empty either way, treat it as "the
/// operator pressed Enter" — so `warden init < /dev/null` silently
/// accepted every default. Benign only while every default happens to be
/// safe.
#[test]
fn init_stdin_closed_byte_for_byte() {
    assert_eq!(
        INIT_STDIN_CLOSED,
        "stdin closed before this question was answered. Re-run `warden init --yes` to accept the defaults non-interactively."
    );
}

/// It must name the escape hatch. A refusal that does not say how to
/// proceed non-interactively just moves the operator's problem.
#[test]
fn init_stdin_closed_points_at_the_non_interactive_flag() {
    assert!(
        INIT_STDIN_CLOSED.contains("--yes"),
        "the refusal must name the flag that makes init non-interactive: \
         {INIT_STDIN_CLOSED}"
    );
}

// ── config lint --strict ─────────────────────────────────────────────

/// The line that distinguishes the two ways `config lint` reaches exit 2.
///
/// Without it, "your config is broken" and "your config is fine but you
/// asked me to be strict" are the same observable event: same code, same
/// silence. The operator's next action differs completely between them.
#[test]
fn strict_warnings_are_fatal_byte_for_byte() {
    assert_eq!(
        STRICT_WARNINGS_ARE_FATAL,
        "--strict: the configuration is valid but has warnings, which --strict treats as failure."
    );
}

/// It must name the flag that caused it. A script author reading this on
/// stderr has to be able to tell that removing `--strict` makes the
/// failure go away — that is the entire content of the message.
#[test]
fn strict_warnings_message_names_the_flag_that_caused_it() {
    assert!(
        STRICT_WARNINGS_ARE_FATAL.contains("--strict"),
        "the message must name --strict, or it reads as an unexplained \
         failure: {STRICT_WARNINGS_ARE_FATAL}"
    );
}

// ── the exit-code contract summary ───────────────────────────────────

/// `config diff` joined the set of verbs that may answer with code 3, so
/// the rendered contract has to say so.
///
/// This is the half that rots silently: the constant is a summary of a
/// rule enforced elsewhere, so nothing breaks when the rule grows and the
/// summary does not. It ends up describing an older CLI than the one the
/// operator is holding.
#[test]
fn contract_summary_lists_every_verb_that_can_answer_negative() {
    for verb in ["query", "resolve", "config diff"] {
        assert!(
            CONTRACT_SUMMARY.contains(verb),
            "`{verb}` can exit 3 but the rendered contract does not mention \
             it — a script author reading this line would treat that 3 as \
             undefined behaviour:\n  {CONTRACT_SUMMARY}"
        );
    }
}

#[test]
fn contract_summary_byte_for_byte() {
    assert_eq!(
        CONTRACT_SUMMARY,
        "exit codes: 0 success · 1 failed · 2 config invalid · 3 negative answer (query BLOCKED, resolve REFUSED, config diff DIFFERS)"
    );
}
