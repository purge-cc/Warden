//! The one seat that turns a mutated config tree back into TOML text.
//!
//! # What was wrong
//!
//! Four independent writers round-tripped config through
//! `toml::Value` → `toml::to_string_pretty`: `target.rs` (every entity
//! mutation), `token.rs` (token generate / regenerate), and `cluster.rs`
//! twice (cluster token, cluster join). `toml::to_string_pretty` has no
//! representation for a comment and emits keys in its own order, so each
//! of those writes silently deleted every comment in the file it touched
//! and could reorder it.
//!
//! Three of the four rewrite the **master** — `/etc/purge-warden/config.toml`
//! on a real install, and the most comment-dense file an operator owns.
//!
//! The part worth pausing on is that `token.rs` and `cluster.rs` both
//! *documented* the opposite. `token.rs` promised that every other
//! top-level section "is preserved **byte-for-byte** through the
//! round-trip"; `cluster.rs` said "Every other section survives
//! byte-for-byte". Neither was true, and the claim is why nobody
//! checked: a reader looking for this defect would have read those lines
//! and moved on. Both are corrected in the same commit as this module.
//!
//! # What this does instead
//!
//! [`toml_edit`] parses TOML into a document that retains formatting,
//! comments and key order, and lets you mutate it in place. This module
//! reconciles a mutated [`toml::Value`] against the original document
//! text, so the callers keep building a plain `Value` — no rewrite of
//! forty mutation sites — while the bytes that land on disk keep the
//! operator's file intact.
//!
//! Deliberately NOT a change to the write pipeline underneath. The
//! staged-then-validated promotion in `target.rs` takes a `String`; this
//! module only changes how that `String` is produced, so the guarantee
//! that a tree the loader would reject never gets renamed into place is
//! untouched.
//!
//! # The merge rule, and why it is a full three-way reconcile
//!
//! Every caller reads the *whole* file into a `Value`, mutates it, and
//! hands the whole thing back — `read_or_empty` returns the complete
//! parsed file, and the master writers parse the master themselves. So
//! the incoming `Value` is a complete description of the intended final
//! state, not a patch, and the reconcile has to honour deletions:
//!
//! - key in both → recurse if both are tables, otherwise overwrite the
//!   value and keep the key's own decor (its comment and spacing)
//! - key only in the incoming value → insert it
//! - key only in the document → **remove it**
//!
//! That last rule is load-bearing. `remove_id_keyed` deletes an entity by
//! dropping it from the `Value`; a merge that only added and updated
//! would resurrect every removed row and silently turn `warden device
//! remove` into a no-op.

use anyhow::Context;
use toml_edit::{DocumentMut, Item, Table};

/// Serialise `value` as the new content of a file whose current text is
/// `original`, preserving `original`'s comments and key order wherever
/// the two still agree.
///
/// Falls back to a plain pretty-print when `original` is empty or does
/// not parse — a file we cannot read as TOML has no formatting worth
/// preserving, and refusing here would turn a recoverable state into a
/// dead end.
pub fn render_preserving(original: &str, value: &toml::Value) -> anyhow::Result<String> {
    if original.trim().is_empty() {
        return render_plain(value);
    }
    let Ok(mut doc) = original.parse::<DocumentMut>() else {
        return render_plain(value);
    };
    let mut incoming = to_document(value)?;
    normalise_shape(incoming.as_item_mut());
    merge_table(doc.as_table_mut(), incoming.as_table());
    Ok(doc.to_string())
}

/// Rewrite an incoming document into the *shape* a hand-written config
/// uses: standard `[table]` headers and `[[array of tables]]`, not the
/// inline `{ … }` / `[{ … }]` forms.
///
/// `toml_edit`'s serialiser emits everything inline, because from a
/// `toml::Value` there is no information about which form the author
/// chose. Without this pass the merge below never sees a table-to-table
/// pair: `Item::Value(InlineTable)` is not `Item::Table`, so every
/// section fell into the overwrite arm and the whole `[upstream]` block
/// — comments and all — was replaced by `upstream = { … }` on one line.
/// The result still reparsed to the same value, which is exactly why
/// this needed a test that reads the *text* and not just the semantics.
fn normalise_shape(item: &mut Item) {
    if item.is_inline_table() {
        let taken = std::mem::replace(item, Item::None);
        match taken.into_table() {
            Ok(table) => *item = Item::Table(table),
            // Unreachable while the `is_inline_table` guard above holds.
            // Put it back anyway: the conversion CONSUMES the item, so an
            // early return here would leave `Item::None` behind and delete
            // the section outright. That is the exact failure this module
            // exists to prevent, and it would arrive silently the day the
            // guard and the conversion stop agreeing.
            Err(original) => *item = original,
        }
    }

    // An array whose every element is a table is `[[section]]` in a
    // hand-written file. An array of scalars (`includes`, `cidrs`,
    // `servers`) is a value and must stay one.
    if item
        .as_array()
        .is_some_and(|a| !a.is_empty() && a.iter().all(|v| v.is_inline_table()))
    {
        let taken = std::mem::replace(item, Item::None);
        match taken.into_array_of_tables() {
            Ok(aot) => *item = Item::ArrayOfTables(aot),
            // Same reasoning as the inline-table arm above: restore rather
            // than leave `Item::None`, or a guard that stops matching the
            // conversion deletes every `[[section]]` it touches.
            Err(original) => *item = original,
        }
    }

    match item {
        Item::Table(t) => {
            for (_, v) in t.iter_mut() {
                normalise_shape(v);
            }
        }
        Item::ArrayOfTables(aot) => {
            for t in aot.iter_mut() {
                for (_, v) in t.iter_mut() {
                    normalise_shape(v);
                }
            }
        }
        _ => {}
    }
}

/// Pretty-print with no document to preserve — a brand-new file.
fn render_plain(value: &toml::Value) -> anyhow::Result<String> {
    toml::to_string_pretty(value).context("serialise config value as TOML")
}

/// Convert a [`toml::Value`] into an undecorated [`DocumentMut`].
///
/// Goes through `toml_edit`'s own serialiser rather than a hand-written
/// `Value` → `Item` converter: a hand-written one has to enumerate every
/// TOML type, and the one it forgets (datetimes, in practice) fails at
/// runtime on an operator's config rather than at compile time here.
fn to_document(value: &toml::Value) -> anyhow::Result<DocumentMut> {
    toml_edit::ser::to_document(value).context("convert config value to a TOML document")
}

/// Reconcile `incoming` into `target`, preserving `target`'s decor.
///
/// Recursive on tables so a comment deep inside `[profiles.kids]`
/// survives a change to a sibling key.
fn merge_table(target: &mut Table, incoming: &Table) {
    // Remove first: keys the caller dropped from the value are keys the
    // operator asked to delete. Collected before mutating, because
    // removing while iterating borrows `target` twice.
    let doomed: Vec<String> = target
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| !incoming.contains_key(k))
        .collect();
    for key in doomed {
        target.remove(&key);
    }

    for (key, new_item) in incoming.iter() {
        match target.get_mut(key) {
            // Both sides are tables: recurse, so only the keys that
            // actually changed lose their formatting.
            Some(Item::Table(existing)) => match new_item {
                Item::Table(new_table) => merge_table(existing, new_table),
                other => overwrite(target, key, other),
            },
            // Both sides are arrays of tables: merge element-wise by
            // position, so editing device 7 does not reformat devices
            // 1-6. Callers mutate these in place (`upsert_id_keyed`
            // replaces a row, `remove_id_keyed` drops one), so position
            // is a meaningful correspondence.
            Some(Item::ArrayOfTables(existing)) => match new_item {
                Item::ArrayOfTables(incoming_aot) => {
                    while existing.len() > incoming_aot.len() {
                        existing.remove(existing.len() - 1);
                    }
                    for (i, new_row) in incoming_aot.iter().enumerate() {
                        match existing.get_mut(i) {
                            Some(row) => merge_table(row, new_row),
                            None => existing.push(new_row.clone()),
                        }
                    }
                }
                other => overwrite(target, key, other),
            },
            // Present, but not a same-shape pair. Overwrite the value
            // and put the old key's decor back, so a trailing
            // `# comment` on that line survives a value change.
            Some(_) => overwrite(target, key, new_item),
            // New key: nothing to preserve.
            None => {
                target.insert(key, new_item.clone());
            }
        }
    }
}

/// Replace `key` in `target`, carrying the old entry's decor across so no
/// comment attached to that key is lost with the value.
///
/// **There are two decors, and carrying only one is a real defect.**
///
/// ```toml
/// # Locked down until homework is done.      <- the KEY's leaf decor
/// display_name = "Kids"   # trailing note    <- the VALUE's decor
/// ```
///
/// A comment on its own line above a key belongs to the **key**, not to the
/// value it precedes. Restoring only the value's decor keeps `# trailing
/// note` and silently drops the line above it — which is how an edit to one
/// `[profiles.*]` table stripped a sibling's comment.
fn overwrite(target: &mut Table, key: &str, new_item: &Item) {
    let old_value_decor = target
        .get(key)
        .and_then(Item::as_value)
        .map(|v| v.decor().clone());
    let old_key_decor = target.key(key).map(|k| k.leaf_decor().clone());

    target.insert(key, new_item.clone());

    if let (Some(decor), Some(v)) = (
        old_value_decor,
        target.get_mut(key).and_then(Item::as_value_mut),
    ) {
        *v.decor_mut() = decor;
    }
    if let (Some(decor), Some(mut k)) = (old_key_decor, target.key_mut(key)) {
        *k.leaf_decor_mut() = decor;
    }
}

/// Read `path`, apply `mutate` to it as a formatting-preserving
/// document, and hand back the rendered text.
///
/// This is the seat the three master-table writers share (`token.rs`
/// once, `cluster.rs` twice). Each previously carried its own
/// parse-mutate-serialise block, and all three carried the same
/// comment-destroying serialiser; one of them growing a fix that the
/// other two did not is exactly how the four writers diverged in the
/// first place.
pub fn edit_document<F>(path: &std::path::Path, mutate: F) -> anyhow::Result<String>
where
    F: FnOnce(&mut DocumentMut) -> anyhow::Result<()>,
{
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("cannot parse {} as TOML", path.display()))?;
    mutate(&mut doc)?;
    Ok(doc.to_string())
}

/// Convert a single [`toml::Value`] into a [`toml_edit::Item`] suitable
/// for insertion into a document.
///
/// The bridge for callers that already hold `toml::Value`s (the cluster
/// field table is built as one) and only need to place them. Goes
/// through `toml_edit`'s serialiser for the same reason [`to_document`]
/// does: a hand-written type match is a list of TOML types someone has
/// to keep complete.
pub fn value_to_item(value: &toml::Value) -> anyhow::Result<Item> {
    toml_edit::ser::to_document(&toml::toml! { v = (value.clone()) })
        .context("convert value for insertion")?
        .remove("v")
        .ok_or_else(|| anyhow::anyhow!("converted document lost its only key"))
}

/// Borrow (creating if absent) a top-level table inside `doc`.
///
/// Errors when the key exists and is not a table, which is the same
/// refusal the three hand-written writers each spelled for themselves.
pub fn table_mut<'a>(doc: &'a mut DocumentMut, key: &str) -> anyhow::Result<&'a mut Table> {
    if doc.get(key).is_none() {
        // `implicit` keeps `[api]` from being emitted as a bare header
        // when it ends up empty.
        doc.insert(key, Item::Table(Table::new()));
    }
    doc.get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| anyhow::anyhow!("`[{key}]` must be a TOML table"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A master shaped like a real one: comments above sections, a
    /// trailing comment on a value, and keys in an order no serialiser
    /// would choose.
    const COMMENTED: &str = r#"schema_version = 3

# The upstream resolvers this household uses.
# Changed 2026-03-01 after the old pair started timing out.
[upstream]
servers = ["192.0.2.1:53"]
timeout_ms = 2000   # raised from 800, flaky link

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[profiles.default]
display_name = "Default"
"#;

    fn parse(src: &str) -> toml::Value {
        src.parse().expect("fixture must be valid TOML")
    }

    /// The headline guarantee: a comment written into the master
    /// survives a mutation of an unrelated key.
    #[test]
    fn comments_survive_a_mutation_elsewhere_in_the_file() {
        let mut value = parse(COMMENTED);
        value
            .as_table_mut()
            .unwrap()
            .entry("api".to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .unwrap()
            .insert("token_hash".to_string(), toml::Value::String("abc".into()));

        let out = render_preserving(COMMENTED, &value).unwrap();

        assert!(
            out.contains("# The upstream resolvers this household uses."),
            "the operator's section comment was deleted:\n{out}"
        );
        assert!(
            out.contains("# Changed 2026-03-01 after the old pair started timing out."),
            "a second line of the same comment block was deleted:\n{out}"
        );
        assert!(
            out.contains("# raised from 800, flaky link"),
            "the trailing comment on a value was deleted:\n{out}"
        );
        assert!(
            out.contains("token_hash"),
            "the mutation itself did not land:\n{out}"
        );
    }

    /// The control arm, and the reason this module exists. Without it,
    /// the test above could pass against a `render_preserving` that
    /// simply returned `original` unchanged.
    #[test]
    fn the_old_serialiser_really_did_destroy_those_comments() {
        let value = parse(COMMENTED);
        let old = toml::to_string_pretty(&value).unwrap();
        assert!(
            !old.contains("# The upstream resolvers"),
            "if toml::to_string_pretty preserves comments, this module is \
             unnecessary and the test above proves nothing:\n{old}"
        );
    }

    /// Top-level key order is preserved across a mutation.
    ///
    /// Asserted as a sequence, not as "schema_version is still first":
    /// the defect is re-sorting, and a single-position check passes on a
    /// file whose first key happens to sort first anyway.
    #[test]
    fn top_level_key_order_is_preserved() {
        let order = |s: &str| -> Vec<String> {
            s.parse::<DocumentMut>()
                .unwrap()
                .as_table()
                .iter()
                .map(|(k, _)| k.to_string())
                .collect()
        };

        let before = order(COMMENTED);
        let mut value = parse(COMMENTED);
        value.as_table_mut().unwrap()["server"]
            .as_table_mut()
            .unwrap()
            .insert("tcp_timeout_secs".to_string(), toml::Value::Integer(9));

        let after = order(&render_preserving(COMMENTED, &value).unwrap());

        assert_eq!(
            before, after,
            "top-level key order changed across a CLI mutation"
        );
        // Guard the guard: `upstream` really is out of alphabetical
        // order in the fixture, so this test can actually fail.
        assert!(
            before.iter().position(|k| k == "upstream") < before.iter().position(|k| k == "server"),
            "the fixture no longer has out-of-order keys, so a sorting \
             serialiser would pass this test: {before:?}"
        );
    }

    /// Deletion must propagate. A merge that only added and updated
    /// would turn every `remove` verb into a no-op while reporting
    /// success.
    #[test]
    fn a_key_dropped_from_the_value_is_dropped_from_the_document() {
        let mut value = parse(COMMENTED);
        value.as_table_mut().unwrap().remove("profiles");

        let out = render_preserving(COMMENTED, &value).unwrap();

        assert!(
            !out.contains("[profiles.default]"),
            "a section the caller deleted survived the round-trip — every \
             `warden <entity> remove` would silently do nothing:\n{out}"
        );
        assert!(
            out.contains("[server]"),
            "the deletion took an unrelated section with it:\n{out}"
        );
    }

    /// Nested tables recurse, so an edit to one profile does not strip
    /// the comments of its sibling.
    #[test]
    fn a_comment_inside_a_nested_table_survives_a_sibling_edit() {
        const SRC: &str = r#"[profiles.kids]
# Locked down until homework is done.
display_name = "Kids"

[profiles.adults]
display_name = "Adults"
"#;
        let mut value = parse(SRC);
        value.as_table_mut().unwrap()["profiles"]
            .as_table_mut()
            .unwrap()["adults"]
            .as_table_mut()
            .unwrap()
            .insert("block_all".to_string(), toml::Value::Boolean(true));

        let out = render_preserving(SRC, &value).unwrap();
        assert!(
            out.contains("# Locked down until homework is done."),
            "editing `adults` stripped the comment inside `kids`:\n{out}"
        );
        assert!(out.contains("block_all"), "the edit did not land:\n{out}");
    }

    /// A new file has no formatting to keep; the seat must still work.
    #[test]
    fn an_empty_original_falls_back_to_a_plain_render() {
        let value = parse("[server]\nlisten = \"127.0.0.1:15353\"\n");
        let out = render_preserving("", &value).unwrap();
        assert!(out.contains("listen"), "{out}");
    }

    /// An unparseable original must not brick the write. The mutation
    /// still has to land — the alternative is a CLI that cannot repair
    /// a file precisely when the file needs repairing.
    #[test]
    fn an_unparseable_original_falls_back_instead_of_failing() {
        let value = parse("[server]\nlisten = \"127.0.0.1:15353\"\n");
        let out = render_preserving("this is not { valid TOML", &value).unwrap();
        assert!(out.contains("listen"), "{out}");
    }

    /// Whatever comes out must parse back to exactly the value that went
    /// in. Formatting preservation is worthless if it costs semantics.
    #[test]
    fn the_rendered_text_reparses_to_the_input_value() {
        let mut value = parse(COMMENTED);
        value.as_table_mut().unwrap()["server"]
            .as_table_mut()
            .unwrap()
            .insert("log_level".to_string(), toml::Value::String("debug".into()));

        let out = render_preserving(COMMENTED, &value).unwrap();
        let round_tripped: toml::Value = out.parse().expect("output must be valid TOML");
        assert_eq!(
            round_tripped, value,
            "preserving the operator's formatting must not change what the \
             file MEANS:\n{out}"
        );
    }

    #[test]
    fn table_mut_creates_a_missing_table_and_refuses_a_non_table() {
        let mut doc = "schema_version = 3\n".parse::<DocumentMut>().unwrap();
        table_mut(&mut doc, "api")
            .unwrap()
            .insert("enabled", toml_edit::value(true));
        assert!(doc.to_string().contains("[api]"), "{doc}");

        let mut bad = "api = 3\n".parse::<DocumentMut>().unwrap();
        assert!(
            table_mut(&mut bad, "api").is_err(),
            "a scalar named `api` must be refused, not silently replaced"
        );
    }
}
