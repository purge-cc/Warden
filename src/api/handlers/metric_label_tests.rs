use super::escape_metric_label;

/// A blocklist source is an operator-supplied URL, and the exposition
/// format has no quoting beyond backslash escapes — so an unescaped
/// value can close its own label and append forged samples. This is the
/// injection, spelled out: without escaping, the rendered line would
/// carry a second metric a scraper would happily ingest.
#[test]
fn label_escaping_defeats_series_injection() {
    let hostile = r#"evil" } 1
purge_warden_domains_loaded{x=""#;
    let escaped = escape_metric_label(hostile);

    assert!(
        !escaped.contains('\n'),
        "a raw newline ends the sample and starts an attacker-controlled one"
    );
    for (i, c) in escaped.char_indices() {
        if c == '"' {
            assert!(
                i > 0 && escaped.as_bytes()[i - 1] == b'\\',
                "every quote must be backslash-escaped or the label closes early"
            );
        }
    }

    // Control: ordinary sources must pass through untouched, otherwise
    // the test above would also pass on a function that mangles input.
    assert_eq!(
        escape_metric_label("https://lists.purge.cc/privacy/ads.txt"),
        "https://lists.purge.cc/privacy/ads.txt"
    );
    assert_eq!(escape_metric_label("privacy/ads"), "privacy/ads");
}

#[test]
fn backslash_is_escaped_before_it_can_eat_a_quote() {
    // `foo\` + `"` would otherwise render as `foo\"` — an escaped
    // quote — letting the value swallow its own terminator.
    assert_eq!(escape_metric_label(r"foo\"), r"foo\\");
}
