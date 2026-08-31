use super::*;
use crate::cli::commands::local_dns::LocalRecordScope;
use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
use crate::tui::app::App;
use crate::tui::local_dns_modal::{ConfirmTier, LocalDnsModal, Stage};
use ratatui::layout::Rect;

fn k(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A poller pointed at a socket that cannot exist. A **mismatched**
/// Enter must return before `submit_local_dns_modal`, so this dead
/// path is itself part of the assertion: if the gate ever let a wrong
/// phrase through, the removal would try IPC here.
fn poller() -> IpcPoller {
    IpcPoller::new(Path::new("/nonexistent/purge-warden-localdns-confirm.sock"))
}

fn cfg() -> &'static Path {
    Path::new("/nonexistent/purge-warden-localdns-confirm.toml")
}

/// A `*.global` wildcard — the only shape that reaches
/// [`ConfirmTier::TypedPhrase`].
fn wildcard_modal() -> LocalDnsModal {
    let record = LocalDnsRecord {
        domain: "wild.home".into(),
        record_type: LocalDnsRecordType::A,
        value: "10.9.9.9".into(),
        match_subdomains: true,
        ttl_secs: None,
    };
    let modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &record);
    match &modal.stage {
        Stage::ConfirmingRemove(rc) => assert_eq!(
            rc.tier,
            ConfirmTier::TypedPhrase,
            "fixture must reach the typed-phrase tier or it tests nothing"
        ),
        other => panic!("expected ConfirmingRemove, got {other:?}"),
    }
    modal
}

/// Draw the modal the way the tab does and reconstruct the screen.
///
/// A `TestBackend` buffer holds a per-cell `Style`, never interleaved
/// escapes, so this is plain text by construction — no ANSI stripping
/// is possible or needed. The 80×24 floor with the tab-content anchor
/// is the tightest real geometry.
fn dump(modal: &LocalDnsModal) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| local_dns_modal::render_overlay(f, Rect::new(0, 9, 80, 14), modal))
        .unwrap();
    let buf = term.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Everything from the `⚠` marker onward, rows joined and whitespace
/// squeezed.
///
/// `⚠` is the discriminator: `hint_or_error_rows` is the only producer
/// of it in this stage, so a needle found here cannot have come from
/// the record row or the typed-buffer row — both of which already
/// carry the domain on the *broken* code and would give a false green
/// to a whole-screen `contains`.
///
/// The join is required, not cosmetic: the note region is
/// `HINT_ROWS` = 2 rows and wraps on word boundaries, so a message
/// long enough to be useful straddles them and no single-row
/// `contains` can see it whole.
fn refusal(dump: &str) -> Option<String> {
    let start = dump.find('\u{26a0}')?;
    let joined = dump[start..]
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ");
    Some(joined.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[tokio::test]
async fn wrong_phrase_renders_a_refusal_naming_typed_and_expected() {
    let mut app = App::new();
    app.local_dns.modal = Some(wildcard_modal());

    for c in "wild.hom".chars() {
        handle_local_dns_modal_key(&mut app, k(KeyCode::Char(c)), &poller(), cfg()).await;
    }
    handle_local_dns_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;

    let modal = app
        .local_dns
        .modal
        .as_ref()
        .expect("a refused Enter must leave the modal open");
    let screen = dump(modal);
    let refusal = refusal(&screen)
        .unwrap_or_else(|| panic!("Enter on a wrong phrase drew no refusal at all:\n{screen}"));

    assert!(
        refusal.contains("wild.hom'"),
        "the refusal does not name what was typed:\n{refusal}\n\n{screen}"
    );
    assert!(
        refusal.contains("wild.home"),
        "the refusal does not name what was expected:\n{refusal}\n\n{screen}"
    );
}

/// A key-masher or a paste must not cost the operator the one value
/// they need.
///
/// `hint_or_error_rows` fills at most `HINT_ROWS` = 2 rows and
/// ellipsises the **last** one (`modal_form.rs`), and `push_char`
/// caps nothing — so whichever half of the message is written last is
/// the half a long buffer destroys. The expected domain is the
/// invariant and the echo of what was typed is disposable, so the
/// domain goes first. This test is what pins that ordering; without
/// it the message reads just as well reversed, and reversed it is
/// broken for every buffer past roughly 80 characters.
#[tokio::test]
async fn a_long_wrong_phrase_still_names_the_expected_domain() {
    let mut app = App::new();
    app.local_dns.modal = Some(wildcard_modal());

    for _ in 0..120 {
        handle_local_dns_modal_key(&mut app, k(KeyCode::Char('z')), &poller(), cfg()).await;
    }
    handle_local_dns_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;

    let screen = dump(
        app.local_dns
            .modal
            .as_ref()
            .expect("a refused Enter must leave the modal open"),
    );
    let refusal = refusal(&screen)
        .unwrap_or_else(|| panic!("Enter on a long wrong phrase drew no refusal:\n{screen}"));

    assert!(
        refusal.contains("wild.home"),
        "a long typed buffer pushed the expected domain out of the refusal \u{2014} \
             the operator is told they are wrong and not what right looks \
             like:\n{refusal}\n\n{screen}"
    );
}

/// The retraction, through the handler rather than the state: a
/// refusal names one buffer, so the next keystroke must take it off
/// the screen. Covers both edit keys, since each mutates the buffer
/// on its own arm.
#[tokio::test]
async fn editing_after_a_refusal_takes_it_off_the_screen() {
    for edit in [KeyCode::Char('e'), KeyCode::Backspace] {
        let mut app = App::new();
        app.local_dns.modal = Some(wildcard_modal());

        for c in "wild.hom".chars() {
            handle_local_dns_modal_key(&mut app, k(KeyCode::Char(c)), &poller(), cfg()).await;
        }
        handle_local_dns_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;
        let refused = dump(app.local_dns.modal.as_ref().unwrap());
        assert!(
            refusal(&refused).is_some(),
            "fixture must start refused, else the retraction proves nothing:\n{refused}"
        );

        handle_local_dns_modal_key(&mut app, k(edit), &poller(), cfg()).await;
        let after = dump(app.local_dns.modal.as_ref().unwrap());
        assert!(
            refusal(&after).is_none(),
            "{edit:?} left a refusal describing a buffer that is gone:\n{after}"
        );
    }
}

/// Enter with nothing typed stays quiet. The operator has not
/// attempted the phrase, and the prompt row is already on screen
/// saying what to do — a rejection there would be scolding someone
/// for a mistake they have not made yet.
#[tokio::test]
async fn enter_on_an_empty_phrase_says_nothing() {
    let mut app = App::new();
    app.local_dns.modal = Some(wildcard_modal());

    handle_local_dns_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;

    let screen = dump(
        app.local_dns
            .modal
            .as_ref()
            .expect("an empty phrase must not submit or close"),
    );
    assert!(
        refusal(&screen).is_none(),
        "nothing was typed, so there was nothing to reject:\n{screen}"
    );
    assert!(
        screen.contains("type the domain to confirm:"),
        "the prompt that carries this stage's instruction is gone:\n{screen}"
    );
}

/// The gate itself still holds: the refusal is a message, not a
/// relaxation. A correct phrase leaves the confirm stage; a wrong one
/// never does.
#[tokio::test]
async fn a_refusal_does_not_loosen_the_gate() {
    let mut app = App::new();
    app.local_dns.modal = Some(wildcard_modal());

    for c in "wild.hom".chars() {
        handle_local_dns_modal_key(&mut app, k(KeyCode::Char(c)), &poller(), cfg()).await;
    }
    for _ in 0..3 {
        handle_local_dns_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;
    }

    let modal = app
        .local_dns
        .modal
        .as_ref()
        .expect("a wrong phrase must never submit, however often it is retried");
    assert!(
        matches!(modal.stage, Stage::ConfirmingRemove(_)),
        "a wrong phrase left the confirm stage"
    );
}
