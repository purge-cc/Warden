//! The one wording every retired tag surface refuses with.
//!
//! # What this module was
//!
//! The entity tag write path: `warden profile|subnet|group tag add|remove`,
//! plus the shared `apply_tags_inner` primitive the TUI submit forms used
//! and the `TagEntity` / `TagsWriteReport` / `ENTITY_TAG_*` machinery
//! around it. Three sprints took it apart in order, and the order was the
//! point:
//!
//! - `plp-s3` refused the writes. A tag write after the cutover would have
//!   succeeded, printed a success line, and changed no verdict — defect E2,
//!   the silent acceptance-and-discard this workstream exists to repair,
//!   reintroduced by the repair.
//! - `plp-s5c` removed the six CLI verbs from the clap tree.
//! - `plp-s5a` (here) removed the `tags` field itself, so the primitives
//!   had nothing left to write into. The previous header said *"removing
//!   the last of it is wave B's job, once the TUI and IPC tag editors are
//!   gone"* — this is wave B, they are gone, and `apply_tags_inner` had no
//!   production caller left.
//!
//! `plp-s5f` then retired the four `ENTITY_TAG_*` strings themselves --
//! the last of the machinery. They were the success and no-op lines of
//! those six verbs, standing declared-and-unemitted with a byte-pin still
//! holding them. A frozen contract on a string nothing prints reads to the
//! next person as proof the verb still exists.
//!
//! # Why the constant outlives all of it
//!
//! Five sites still refuse a tag the operator typed, and they reference
//! this constant rather than restating it: `main.rs` (the `warden tags`
//! verb and the `device set tags` arm), `ipc/socket_server.rs` (the device
//! and profile update patches), and `cli/commands/devices.rs`. One message,
//! N call sites — two copies of one refusal drifting apart is the class
//! this workstream is unwinding.
//!
//! The verb surface is deliberately kept too: `warden tags <anything>`
//! reaches this wording instead of clap's `unrecognized subcommand`. An
//! operator with the old muscle memory needs to be told what replaced it,
//! and a generic parse error is silence with extra steps.

/// What every retired tag surface says now.
///
/// **Names the config key, not a verb.** The operator-facing verb for the
/// new model (`warden profile list-policy`) landed in S4; pointing an error
/// at a command that did not exist yet would have been the phantom-verb
/// defect this repo has a gate for (`scripts/check_phantom_verbs.sh`).
/// `profiles.<id>.lists` is real and is what
/// [`effective_direction`](crate::config::schema::effective_direction)
/// actually reads, so the remedy is something the operator can act on.
pub const TAGS_RETIRED: &str = "tags are retired: they no longer decide which lists apply to anyone, so writing one would silently change nothing. Set the direction on the profile instead — `profiles.<id>.lists = { <list-id> = \"deny\" | \"allow\" | \"ignore\" }` in the config.";

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-pinned: five surfaces quote this constant, and an operator who
    /// hits one of them is mid-way through an action that just failed. The
    /// two halves it must keep are the *reason* (writing a tag would change
    /// nothing) and the *replacement* (`profiles.<id>.lists`) — a refusal
    /// that gives only the first leaves them nowhere to go.
    #[test]
    fn tags_retired_is_byte_pinned() {
        assert_eq!(
            TAGS_RETIRED,
            "tags are retired: they no longer decide which lists apply to anyone, so writing one would silently change nothing. Set the direction on the profile instead — `profiles.<id>.lists = { <list-id> = \"deny\" | \"allow\" | \"ignore\" }` in the config."
        );
    }

    /// The phantom-verb rule, as an assertion rather than a comment: this
    /// message must not name a `warden` command. It named none when it was
    /// written because `list-policy` had not shipped; it must keep naming
    /// none, because the config key is the remedy that cannot go stale.
    #[test]
    fn tags_retired_points_at_a_config_key_not_a_verb() {
        assert!(
            !TAGS_RETIRED.contains("warden "),
            "the refusal must name the config key, not a CLI verb: {TAGS_RETIRED}"
        );
        assert!(
            TAGS_RETIRED.contains("profiles.<id>.lists"),
            "and it must name the replacement: {TAGS_RETIRED}"
        );
    }
}
