use super::retired_tags_worth_reporting;

/// Pins all three states. A mutation to `is_some()` turns the middle row
/// red; a mutation to `false` turns the last row red. Without the middle
/// row the predicate could be `is_some()` and still pass.
#[test]
fn only_a_non_empty_retired_tags_key_is_reported() {
    assert!(
        !retired_tags_worth_reporting(None),
        "absent key: the client never sent it"
    );
    assert!(
        !retired_tags_worth_reporting(Some(&vec![])),
        "empty list: an older client round-tripping a device that has no \
         tags — presence is not intent, and warning here is noise"
    );
    assert!(
        retired_tags_worth_reporting(Some(&vec!["kids".to_string()])),
        "non-empty: the closest reachable approximation of intent"
    );
}
