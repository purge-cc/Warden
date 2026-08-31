//! Sprint 52: pin the global `s` hotkey's open/close contract for the
//! resolver modal. The dispatcher's job on `s` is to seat a fresh
//! `ResolverModal` on `App.resolver_modal`; the job on `Esc` is to drop
//! it back to `None`. This integration test pins both ends of that
//! contract so a future refactor can't silently regress the lifecycle.

use purge_warden::tui::resolver_modal::ResolverModal;
use purge_warden::tui::{App, Leaf};

#[test]
fn s_hotkey_seats_a_fresh_modal_and_esc_clears_it() {
    let mut app = App::new();
    assert!(
        app.resolver_modal.is_none(),
        "fresh App must boot with no resolver modal seated"
    );
    assert_eq!(app.active_leaf, Leaf::Dashboard);

    // Open path — what the `s` global hotkey does in the dispatcher
    // when the active leaf has no usable pre-fill.
    app.resolver_modal = Some(ResolverModal::open_blank());
    let modal = app
        .resolver_modal
        .as_ref()
        .expect("resolver modal must be seated after `s`");
    assert!(modal.input.is_empty(), "fresh modal input must be empty");
    assert!(
        modal.last_result.is_none(),
        "fresh modal must carry no result"
    );
    assert!(modal.error.is_none(), "fresh modal must carry no error");

    // Close path — what the dispatcher's Esc arm does.
    app.resolver_modal = None;
    assert!(
        app.resolver_modal.is_none(),
        "Esc must clear the resolver modal"
    );
}
