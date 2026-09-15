//! Public-state lifecycle coverage for the resolver modal. Global hotkey
//! routing is private to the TUI dispatcher and is covered by an in-module
//! interaction test; this integration test verifies the public state shape
//! without claiming that direct assignments exercise keyboard dispatch.

use purge_warden::tui::resolver_modal::ResolverModal;
use purge_warden::tui::{App, Leaf};

#[test]
fn resolver_modal_public_state_supports_open_and_close_lifecycle() {
    let mut app = App::new();
    assert!(
        app.resolver_modal.is_none(),
        "fresh App must boot with no resolver modal seated"
    );
    assert_eq!(app.active_leaf, Leaf::Dashboard);

    // The blank constructor is the state used when no active leaf supplies a
    // source-IP prefill.
    app.resolver_modal = Some(ResolverModal::open_blank());
    let modal = app
        .resolver_modal
        .as_ref()
        .expect("resolver modal must be seated after opening");
    assert!(modal.input.is_empty(), "fresh modal input must be empty");
    assert!(
        modal.last_result.is_none(),
        "fresh modal must carry no result"
    );
    assert!(modal.error.is_none(), "fresh modal must carry no error");

    // Closing releases the modal state.
    app.resolver_modal = None;
    assert!(
        app.resolver_modal.is_none(),
        "closing must clear the resolver modal"
    );
}
