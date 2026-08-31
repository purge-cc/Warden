//! **This file is a CODE-SHAPE pin, not a behavioural test.**
//!
//! It reads `src/dns/handler.rs` as a string and counts call sites. It asserts
//! nothing about DNS responses and cannot catch a wrong name on the wire. Read
//! it as "the refactor that deduped these two branches is still deduped" and
//! nothing more.
//!
//! ## The property being pinned
//!
//! §4.30 disc-1 / handler-07: the rewrite-aware upstream-`Name` reconstruction
//! lives in ONE shared helper (`fwd_name_for`), called from both the
//! prefetch-spawn and cache-miss forward paths.
//!
//! Pre-§4.30 the handler unconditionally rebuilt the forward name via
//! `Name::from_ascii(format!("{domain}."))` on every cache miss (and prefetch
//! refresh), even when no rewrite rule had fired — a fresh `String` allocation
//! plus a full `from_ascii` parse per query on a path that already paid for an
//! upstream RTT. §4.30 disc-1 branched the construction on the `rewrote_from`
//! sentinel. handler-07 (rev-2606) then deduped the two byte-identical branch
//! copies into a single helper, because copy-paste is exactly how the §4.12
//! upstream-qname leak drifted in. One definition, two callers ⇒ the two paths
//! cannot drift apart again.
//!
//! "Two copies have not reappeared" is a statement about how the code is
//! *arranged*, and source text is a fair proxy for it — there is no runtime
//! observation that distinguishes one shared helper from two identical inlined
//! copies. That is what makes this pin legitimate where a source-grep guard for
//! a *wire* property is not: a rearrangement that keeps behaviour identical
//! should fail this test, and that is the intent.
//!
//! ## What actually guards the behaviour
//!
//! - the helper produces the right name: `fwd_name_for_rewrite_vs_passthrough`
//!   unit test in `src/dns/handler.rs`
//! - the client-facing answer shape of a rewritten query:
//!   `tests/rewrite_client_answer_shape.rs`
//! - the answer owner of a rewritten-then-blocked query:
//!   `tests/integration_rewrite_post_fetch_block.rs`
//! - local-record answers on both `send_local` call sites:
//!   `tests/local_wire_owner_shape.rs`
//!
//! If this pin fails, check those first. A failure here on its own means
//! someone rearranged the code, not that warden is answering wrongly.

#[test]
fn s430_disc1_handler07_single_fwd_name_helper_at_both_sites_code_shape_pin() {
    let handler_src = include_str!("../src/dns/handler.rs");

    // handler-07: BOTH the prefetch-spawn and cache-miss forward paths must
    // call the one shared helper with the identical argument shape. Exactly 2
    // call sites — re-inlining the branch reintroduces the copy-paste the
    // §4.30 disc-1 / §4.12 drift came from.
    let call_occurrences = handler_src
        .matches("fwd_name_for(domain, rewrote_from.is_some(), name)")
        .count();
    assert_eq!(
        call_occurrences, 2,
        "handler-07 code-shape pin: handler.rs must call the shared \
         `fwd_name_for` helper at EXACTLY 2 sites (prefetch path + cache-miss \
         forward path). Found {call_occurrences}. Re-inlining or diverging the \
         call reopens the copy-paste drift surface. This says nothing about \
         whether the name on the wire is correct — see the module doc for the \
         tests that do.",
    );

    // The helper signature must keep its exact shape (the disc-1 pin tracks it).
    assert!(
        handler_src
            .contains("fn fwd_name_for(domain: &str, rewrote: bool, name: &LowerName) -> Name"),
        "handler-07 code-shape pin: the `fwd_name_for` helper signature changed \
         or vanished — update this pin deliberately if the helper was \
         intentionally reshaped.",
    );

    // The no-rewrite arm must still reuse the parsed `Name` directly — verify
    // the cheap §4.30 branch hasn't been silently replaced by another
    // `format!` + `from_ascii` on every non-rewritten cache miss. This is a
    // performance-shape pin; no wire behaviour changes if it regresses.
    assert!(
        handler_src.contains("Name::from(name.clone())"),
        "handler-07 / §4.30 disc-1 code-shape pin: the no-rewrite arm of \
         `fwd_name_for` must reuse `Name::from(name.clone())`; its disappearance \
         means the helper always pays the String alloc + from_ascii parse cost.",
    );
}
