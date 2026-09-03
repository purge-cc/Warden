//! List subscription management — add/remove/list/catalog sources in config.toml.

use std::collections::BTreeMap;
use std::path::Path;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::format_config_errors;
use super::target::{read_or_empty, remove_id_keyed, write_value_validated, EntityClass};
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::loader::load_config;
use crate::config::schema::Blocklist;
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;
use crate::lists::catalog::{Catalog, CatalogEntry};
use crate::lists::manager::merge_sources_with_blocklists;
use crate::lists::source_key::{canonical_url_key, is_url_source};

/// Turn one operator-typed argument into the `(id, url)` pair a
/// subscription entry needs.
///
/// A list can only ever filter as a `[[blocklists]]` entry, and an entry
/// needs both a stable id and a fetch URL. The operator types one of two
/// things, so this resolves both into the same shape:
///
/// * a catalog slug (`privacy/ads`) — the id is the slug with its slash
///   turned into a dash, the URL comes from the catalog. This is exactly
///   what `warden init` writes for its bundled lists, so a list added
///   later is indistinguishable from one that shipped with the config.
/// * a URL — the id is derived from the host and the file name, which is
///   the closest thing to a name the operator has given us.
///
/// The catalog consulted is the built-in one, so this stays offline and
/// gives the same answer on every run. A slug that is not in it is an
/// error rather than a warning: without a URL there is nothing to
/// subscribe to, and the old behaviour of recording the slug anyway
/// produced an entry that could never download or filter.
///
/// **The cost of that choice, recorded.** `warden lists catalog`
/// renders the *live* index, so the two verbs consult different sources
/// and the built-in table can fall behind — it did, by
/// `services/resolvers`, and the operator's report was "the catalog
/// shows it and `add` says it does not exist". Staying offline is still
/// right: `add` mutates the config, so a live fetch would let a
/// purge.cc outage change what the operator can do and a poisoned index
/// write a URL into their config. The obligations that follow are (a)
/// `FALLBACK_ENTRIES` tracks the published index — detector:
/// `lists::catalog::tests::fallback_entries_track_the_live_catalog` —
/// (b) the catalog display marks rows this binary cannot resolve, and
/// (c) the error below says which catalog it means. None of those is a
/// reason to reach for the network here.
fn derive_subscription(source: &str) -> anyhow::Result<(String, String)> {
    if is_url_source(source) {
        let id = id_from_url(source)?;
        return Ok((id, source.to_string()));
    }

    let catalog = Catalog::fallback();
    let url = catalog.resolve(source).ok_or_else(|| {
        anyhow::anyhow!(
            "\"{source}\" is not in this binary's built-in catalog. `warden lists add` \
             resolves slugs offline, so a list published after this build is unknown here \
             even when `warden lists catalog` — which fetches the live index — shows it. \
             Those rows are marked [newer than this build] and print the URL to use; \
             passing a URL directly works for any list."
        )
    })?;
    let id = sanitize_id(&source.replace('/', "-")).ok_or_else(|| {
        anyhow::anyhow!("cannot build a list id from \"{source}\" — pass the URL instead")
    })?;
    Ok((id, url))
}

/// Build an id for a URL subscription from its host and file name, e.g.
/// `https://lists.example.org/ads.txt` becomes `lists-example-org-ads`.
///
/// Both parts are kept because either alone collides too easily — one
/// host serves many lists, and `ads.txt` is the file name on half the
/// list providers in existence.
fn id_from_url(url: &str) -> anyhow::Result<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = match after_scheme.split_once('/') {
        Some((a, p)) => (a, p),
        None => (after_scheme, ""),
    };
    // Drop any port and userinfo — neither names the list.
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);

    let file = path
        .rsplit('/')
        .find(|seg| !seg.is_empty())
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let stem = file.split('.').next().unwrap_or(file);

    let candidate = if stem.is_empty() {
        host.to_string()
    } else {
        format!("{host}-{stem}")
    };
    sanitize_id(&candidate).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot build a list id from \"{url}\" — add it with `warden blocklist add \
             <id> --url {url}` and choose the id yourself"
        )
    })
}

/// Coerce a string into the id charset (lowercase letters, digits and
/// dashes), or `None` if nothing usable survives.
///
/// Runs of rejected characters collapse into one dash so
/// `127.0.0.1:18080` reads as `127-0-0-1` rather than `127-0-0-1-`.
fn sanitize_id(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    // Ids are capped at 64 bytes; truncating can re-expose a trailing
    // dash, so trim again after the cut.
    let capped = if trimmed.len() > 64 {
        trimmed[..64].trim_end_matches('-')
    } else {
        trimmed
    };
    if capped.is_empty() {
        None
    } else {
        Some(capped.to_string())
    }
}

/// What `warden lists add` says about the corpus ceiling before it
/// writes, or `None` when there is nothing worth saying.
///
/// Three inputs, each of which can be missing, and the reason has to
/// reach the operator because they imply different next steps: the
/// config carries the ceiling, the daemon carries what is installed
/// (config cannot know it — the corpus is the deduplicated union), and
/// the on-disk catalog carries the list's own size.
///
/// The catalog read is the *persisted* one rather than a fetch: `add`
/// mutates the config, and letting a purge.cc outage change what it
/// prints would make the verb's output depend on the network. A cache
/// miss is `Unknown`, which is honest and costs one line.
async fn projection_note(
    config_path: &Path,
    socket_path: &Path,
    loaded: Option<&crate::config::loader::LoadedConfig>,
    url: &str,
) -> Option<String> {
    use super::lists_knobs::{corpus_projection, fetch_live_corpus, Projection};

    let Some(loaded) = loaded else {
        return Some(unknown_note("config not readable"));
    };
    let ceiling = loaded.config.lists.max_total_domains as u64;
    // Mirrors `corpus_projection`'s own precedence: with the guard off
    // there is no question to answer, so neither the daemon nor the
    // catalog is worth consulting — and neither is worth reporting.
    if ceiling == 0 {
        return None;
    }
    // Bounded like the banner's probe: a daemon that accepts and then
    // says nothing must not hold `add` for the full IPC timeout.
    let Ok(Ok(live)) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        fetch_live_corpus(socket_path),
    )
    .await
    else {
        return Some(unknown_note("daemon not reachable"));
    };
    let installed = live.unique_installed;

    // Matched the way every other URL comparison in this file matches:
    // the persisted catalog and the operator's argument may differ in
    // scheme case or an explicit port and still name one list.
    let wanted = canonical_url_key(url);
    let entries =
        Catalog::load_from_disk(&super::start::lists_cache_dir(config_path, &loaded.config))
            .and_then(|c| {
                c.entries()
                    .iter()
                    .find(|e| canonical_url_key(&e.url) == wanted)
                    .map(|e| e.entries)
            });

    match corpus_projection(installed, ceiling, entries) {
        // `MayCross` is only reachable with a known size, so the addend is
        // the list's own count; `upper_bound` saturates on overflow and
        // would otherwise print the difference as 0 exactly there.
        Projection::MayCross { upper_bound } => Some(format!(
            "note: this list may push the corpus past max_total_domains: {installed} \
             installed + up to {} = up to {upper_bound} > {ceiling}. If it does, the next \
             refresh is refused and filtering FREEZES at today's corpus. Raise the ceiling \
             first: warden lists set max_total_domains <n>",
            entries.unwrap_or(0),
        )),
        Projection::Unknown { reason } => Some(unknown_note(reason)),
        // A list that fits, or a ceiling nobody enforces: the operator
        // asked to add a list, not to read about one.
        Projection::Fits | Projection::Disabled => None,
    }
}

/// The unprojectable case. One renderer for all three causes so the
/// remedy stays attached to every one of them — the operator's next step
/// is the same measurement whichever input was missing.
fn unknown_note(reason: &str) -> String {
    format!(
        "note: cannot project this list's size ({reason}); the first refresh after adding \
         it measures the corpus — check: warden lists show"
    )
}

/// Subscribe to a list.
///
/// The entry written is a `[[blocklists]]` one, because that is the only
/// shape the filter engine can act on. The older `[lists].sources` array
/// this verb used to append to still parses and still downloads, but
/// nothing it contains can ever reach a profile — a list added that way
/// filtered nothing, quietly, forever.
///
/// What a profile does with a list is
/// [`effective_direction`](crate::config::schema::effective_direction) —
/// the profile's `profiles.<id>.lists` entry for that list if it has
/// one, else the list's own `base`. Tags play no part in it.
///
/// The entry itself is built by [`super::blocklists::run_add_silent`]
/// rather than by a second writer here, so a list added with `lists add`
/// and one added with `blocklist add` are the same object with the same
/// validation, the same duplicate-URL rule, and the same audit record.
/// The common case starts filtering with no further steps, and the
/// reason is `base`: it defaults to `deny`, and a profile with no
/// override inherits that.
///
/// The reachability probe `blocklist add` runs is deliberately skipped:
/// that verb offers `--skip-head-check` for a list whose server happens
/// to be down, and this one has no such escape hatch, so enforcing it
/// here would make a transient outage block the subscription outright.
pub async fn run_add(config_path: &Path, socket_path: &Path, source: &str) -> anyhow::Result<()> {
    let (id, url) = derive_subscription(source)?;
    // First, before the duplicate checks: an idempotent provisioning script
    // re-adds every list it already has, and that is the run on which an
    // operator must still be told the corpus is frozen.
    super::lists_knobs::warn_if_frozen(socket_path).await;

    // Adding a list twice is not an error — it is a script being re-run.
    // Both channels are checked: an entry may predate this verb writing
    // entities, and a legacy leftover still downloads, so re-adding it
    // would put the same body behind two sources.
    // Held past the duplicate checks: the ceiling this list is projected
    // against comes from the same load, so the projection cannot answer
    // from a different config than the checks just used.
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).ok();
    if let Some(loaded) = &loaded {
        let canonical = canonical_url_key(&url);
        if let Some(existing) = loaded
            .config
            .blocklists
            .iter()
            .find(|b| canonical_url_key(&b.url) == canonical)
        {
            println!("already subscribed: {source} (list \"{}\")", existing.id);
            return Ok(());
        }
        // Same derived id, different URL. Two lists can genuinely reduce
        // to one id — `/ads/list.txt` and `/trackers/list.txt` on one
        // host both derive `<host>-list`. Treating that as "already
        // subscribed" would report success and leave the second list
        // never added, which is the failure this verb exists to end. So
        // it is refused, and the operator is given the way to name it.
        if let Some(existing) = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
        {
            anyhow::bail!(
                "\"{source}\" would be named \"{id}\", which is already taken by a \
                 different list ({}). Add it with a name of your own:\n  \
                 warden blocklist add <name> --url {url}",
                existing.url
            );
        }
        if loaded
            .config
            .lists
            .sources
            .iter()
            .any(|s| s == source || canonical_url_key(s) == canonical)
        {
            println!("already subscribed: {source}");
            println!(
                "It is recorded in the older `[lists].sources` form, which downloads but \
                 never filters. Run `warden lists remove {source}` and add it again to \
                 convert it."
            );
            return Ok(());
        }
    }

    // Before the write, not after. Past this point the list is
    // subscribed and the next refresh either installs it or refuses the
    // whole cycle; an operator told afterwards has already paid for the
    // answer. The banner is separate because a corpus that is ALREADY
    // frozen makes the projection moot — nothing installs either way.
    if let Some(note) = projection_note(config_path, socket_path, loaded.as_ref(), &url).await {
        println!("{note}");
    }

    // A slug is a name worth keeping — it is what the operator typed and
    // what the catalog calls the list. A URL is not: it would print
    // beside the identical `url=` field on every listing row, so those
    // fall back to the id, which already carries the host and file name.
    let display_name = if is_url_source(source) {
        None
    } else {
        Some(source)
    };

    let outcome = super::blocklists::run_add_silent(
        config_path,
        socket_path,
        &id,
        display_name,
        &url,
        None,
        None,
        None,
        None,
        None,
        true, // reachability probe: see the doc comment above
        None,
    )
    .await?;

    for warn in &outcome.warnings {
        eprintln!("warning: {warn}");
    }
    println!("added: {source} (list \"{id}\")");
    println!("run `warden blocklist show {id}` to check what it filters for");
    super::ipc_reload::report_reload_outcome(&outcome.reload_outcome);
    Ok(())
}

/// Unsubscribe from a list.
///
/// Covers both places a subscription can live: the `[[blocklists]]`
/// entry this verb now writes, and any leftover `[lists].sources` string
/// from before it did. An operator who types what they typed to add the
/// list gets it removed wherever it ended up, and so does one who types
/// the list id shown by `warden lists list`.
///
/// Removing something that is not there is not an error — re-running a
/// teardown script should be quiet, not fatal.
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    source: &str,
) -> anyhow::Result<()> {
    super::lists_knobs::warn_if_frozen(socket_path).await;

    // The id `run_add` would have chosen for this argument, so removing
    // by URL finds the entry that URL created. Unresolvable arguments
    // (an id typed directly, a slug not in the catalog) are not an error
    // here — they simply contribute no id to match on.
    let derived = derive_subscription(source).ok();
    let derived_id = derived.as_ref().map(|(id, _)| id.clone());
    let canonical = derived
        .as_ref()
        .map(|(_, url)| canonical_url_key(url))
        .unwrap_or_else(|| canonical_url_key(source));

    // Which entry does this argument name? Matched by id, by the id the
    // argument would derive to, or by URL.
    let now = time::OffsetDateTime::now_utc();
    let entity_id = load_config(config_path, now).ok().and_then(|loaded| {
        loaded
            .config
            .blocklists
            .iter()
            .find(|b| {
                b.id.as_str() == source
                    || derived_id.as_deref() == Some(b.id.as_str())
                    || canonical_url_key(&b.url) == canonical
            })
            .map(|b| b.id.as_str().to_string())
    });

    // Where the entry lives. On a single-file config this is the master
    // itself, which is the case worth being careful about: the same
    // source can be recorded in both shapes at once, and removing it
    // then means two edits. Doing them as two writes would leave the
    // config half-converted if the second were rejected — entry gone,
    // legacy string still there, list filtering nothing. So when both
    // land in one file they are staged on one document and written once.
    let entity_target = match &entity_id {
        Some(id) => Some(super::target::resolve_existing_target_file(
            config_path,
            EntityClass::Blocklists,
            id,
            None,
        )?),
        None => None,
    };
    let one_file = entity_target.as_deref() == Some(config_path);

    let mut removed_from: Vec<String> = Vec::new();

    // Master document, carrying the legacy edit and — when they share a
    // file — the entry removal too.
    let (mut master, _) = read_or_empty(config_path)?;

    let removed_entity = match (entity_id.as_deref(), entity_target.as_deref()) {
        (Some(id), Some(_)) if one_file => {
            remove_id_keyed(&mut master, EntityClass::Blocklists.toml_key(), id)?
        }
        (Some(id), Some(target)) => {
            // Separate file: nothing to stage together, so this is its
            // own write and its own validation.
            let (mut doc, _) = read_or_empty(target)?;
            let hit = remove_id_keyed(&mut doc, EntityClass::Blocklists.toml_key(), id)?;
            if hit {
                write_value_validated(config_path, target, &doc)?;
            }
            hit
        }
        _ => false,
    };

    // Legacy leftovers, matched byte-exactly and by URL so a trailing
    // slash cannot strand one.
    let removed_legacy = {
        let table = master
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
        match table
            .get_mut("lists")
            .and_then(|l| l.as_table_mut())
            .and_then(|t| t.get_mut("sources"))
        {
            Some(sources) => {
                let arr = sources
                    .as_array_mut()
                    .ok_or_else(|| anyhow::anyhow!("`lists.sources` must be an array"))?;
                let before = arr.len();
                arr.retain(|v| match v.as_str() {
                    Some(s) => s != source && canonical_url_key(s) != canonical,
                    None => true,
                });
                arr.len() != before
            }
            None => false,
        }
    };

    // One write covering whatever was staged on the master.
    if removed_legacy || (one_file && removed_entity) {
        write_value_validated(config_path, config_path, &master)?;
    }

    if removed_entity {
        let id_for_audit = entity_id.clone().unwrap_or_default();
        let target_for_audit = entity_target.clone().unwrap_or_else(|| config_path.into());
        persist_cli_mutation_audit(config_path, move || {
            AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_uid(current_uid())
                .with_action("lists.remove")
                .with_scope("blocklist")
                .with_target_id(id_for_audit)
                .with_files([config_path, target_for_audit.as_path()])
        });
        removed_from.push(format!("list \"{}\"", entity_id.as_deref().unwrap_or("")));
    }
    if removed_legacy {
        let source_for_audit = source.to_string();
        persist_cli_mutation_audit(config_path, move || {
            AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_uid(current_uid())
                .with_action("lists.remove")
                .with_scope("global")
                .with_record_value(source_for_audit)
                .with_files([config_path])
        });
        removed_from.push("[lists].sources".to_string());
    }

    if removed_from.is_empty() {
        // Remove of an absent source is idempotent (exit 0).
        println!("source not found: {source} — nothing to remove");
        return Ok(());
    }

    println!("removed: {source} (from {})", removed_from.join(" and "));
    println!("run `warden lists refresh` or send SIGHUP to the daemon to reload");
    Ok(())
}

/// Show every subscribed list.
///
/// Both storage shapes are printed, and they are not printed the same
/// way on purpose. Entries under `[lists].sources` download on schedule
/// and filter nothing — that is not visible from the entry itself, so
/// the output says it.
pub async fn run_list(config_path: &Path, socket_path: &Path) -> anyhow::Result<()> {
    super::lists_knobs::warn_if_frozen(socket_path).await;

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let lists = &loaded.config.lists;
    let blocklists = &loaded.config.blocklists;

    if lists.sources.is_empty() && blocklists.is_empty() {
        println!("no list sources configured");
        println!("subscribe to one with: warden lists add <list-id|url>");
        return Ok(());
    }

    if !blocklists.is_empty() {
        println!("subscribed lists:");
        for b in blocklists {
            let state = if b.enabled { "" } else { "  (disabled)" };
            println!("  - {} → {}{}", b.id.as_str(), b.url, state);
        }
    }

    if !lists.sources.is_empty() {
        if !blocklists.is_empty() {
            println!();
        }
        println!("inactive entries in [lists].sources:");
        for source in &lists.sources {
            println!("  - {source}");
        }
        println!(
            "\nThese download on schedule and filter nothing — no profile can reach them.\n\
             Convert one with: warden lists remove <entry> && warden lists add <entry>"
        );
    }

    println!("\nupdate interval: {}s", lists.update_interval_secs);
    Ok(())
}

/// Every subscription the config carries, on the axes a catalog row can
/// be recognised by.
///
/// A subscription lives in one of two storage shapes — the
/// `[[blocklists]]` entities, or the legacy `[lists].sources` array — and
/// the array holds either a URL or a slash-form catalog slug. Reading one
/// axis marks nothing: a pure-v1 config leaves the array empty by
/// construction, and a slug never equals a URL.
#[derive(Debug, Default)]
struct ActiveSources {
    /// Canonical keys of every configured source that is a URL.
    urls: Vec<String>,
    /// Slash-form catalog slugs, which only the legacy array can carry.
    slugs: Vec<String>,
    /// `[[blocklists]]` ids. Not a duplicate of the URL axis: a slug
    /// subscription stores the URL the *built-in* catalog gave it, and
    /// this display renders the live one, so the two can disagree about
    /// the same list.
    ids: Vec<String>,
}

impl ActiveSources {
    /// Reads both storage shapes through the function that already
    /// unifies them, so this display cannot answer "what is configured?"
    /// differently from the daemon that acts on the answer.
    fn collect(legacy: &[String], blocklists: &[Blocklist]) -> Self {
        let (merged, _trust) = merge_sources_with_blocklists(legacy, blocklists);
        let mut urls = Vec::with_capacity(merged.len());
        let mut slugs = Vec::new();
        for source in &merged {
            if is_url_source(source) {
                urls.push(canonical_url_key(source));
            } else {
                slugs.push(source.clone());
            }
        }
        // A disabled row is still *configured*, and that is the question
        // being asked here: the merge drops it because the manager must
        // not fetch it, but an operator browsing the catalog needs to
        // know they already have it — `add` will refuse the id either way.
        let mut ids = Vec::with_capacity(blocklists.len());
        for b in blocklists {
            ids.push(b.id.as_str().to_string());
            let key = canonical_url_key(&b.url);
            if !urls.contains(&key) {
                urls.push(key);
            }
        }
        Self { urls, slugs, ids }
    }

    /// Whether the catalog row rendered under `id` is one of them.
    ///
    /// Any axis matching is enough. The URL is the strong one — every
    /// verb here writes it — and the other two catch the legacy array's
    /// slug form and a slug subscription whose stored URL has since
    /// drifted from the published one.
    fn contains(&self, entry: &CatalogEntry, id: &str) -> bool {
        let derived_id = id.replace('/', "-");
        self.urls.contains(&canonical_url_key(&entry.url))
            || self.slugs.iter().any(|s| s == id)
            || self.ids.iter().any(|i| i == &derived_id)
    }
}

/// Browse available purge.cc lists, grouped by scope.
pub async fn run_catalog(
    config_path: &Path,
    socket_path: &Path,
    scope_filter: Option<&str>,
) -> anyhow::Result<()> {
    super::lists_knobs::warn_if_frozen(socket_path).await;

    // Best-effort: catalog browsing must keep working when the config is
    // absent or not yet a valid v1 master, so every load error collapses
    // to "nothing configured" rather than aborting.
    let now = time::OffsetDateTime::now_utc();
    let active = load_config(config_path, now)
        .map(|loaded| {
            ActiveSources::collect(&loaded.config.lists.sources, &loaded.config.blocklists)
        })
        .unwrap_or_default();

    // Fetch live catalog, fall back to hardcoded entries on failure
    let (catalog, offline) = fetch_catalog_for_display().await;
    let entries = catalog.entries();

    // Filter by scope if requested
    let filtered: Vec<&CatalogEntry> = entries
        .iter()
        .filter(|e| scope_filter.is_none_or(|s| e.scope == s))
        .collect();

    if filtered.is_empty() {
        if let Some(scope) = scope_filter {
            let scopes: Vec<&str> = collect_scopes(entries);
            eprintln!(
                "no lists found for scope '{scope}'\navailable scopes: {}",
                scopes.join(", ")
            );
        } else {
            println!("no lists available");
        }
        return Ok(());
    }

    // Group by scope
    let mut groups: BTreeMap<&str, Vec<&CatalogEntry>> = BTreeMap::new();
    for entry in &filtered {
        groups.entry(entry.scope.as_str()).or_default().push(entry);
    }

    // Header
    if offline {
        println!(
            "purge.cc list catalog ({} lists, offline — using built-in data)\n",
            filtered.len()
        );
    } else {
        println!("purge.cc list catalog ({} lists)\n", filtered.len());
    }

    // This display renders the LIVE catalog while `warden lists
    // add <slug>` resolves against the built-in one (see
    // `derive_subscription`). A list published after this binary was
    // built therefore shows up here and is refused there, with a
    // "not a known list" error naming a slug the operator just read on
    // screen. That drift is structural — lists.purge.cc ships
    // independently of releases — so an operator on an older binary will
    // always eventually hit it, and no amount of updating
    // FALLBACK_ENTRIES reaches the binary already in the field. Name the
    // entries `add` will refuse and give them the form that does work.
    //
    // Only meaningful when online: offline, this display IS the built-in
    // catalog, so nothing can diverge from it.
    let builtin = Catalog::fallback();
    let mut unaddable_by_slug = 0usize;

    // Print groups
    for (scope, group) in &groups {
        println!("{scope} ({} lists):", group.len());
        for entry in group {
            let id = entry.id();
            let count = if offline || entry.entries == 0 {
                String::new()
            } else {
                format!("{} domains", format_count(entry.entries))
            };
            let active_marker = if active.contains(entry, &id) {
                "  [active]"
            } else {
                ""
            };
            let slug_unknown = slug_newer_than_this_build(&builtin, &id, offline);
            let marker = if slug_unknown {
                "  [newer than this build]"
            } else {
                ""
            };
            println!("  {id:<24}{:<16}{count}{active_marker}{marker}", entry.name);
            if slug_unknown {
                unaddable_by_slug += 1;
                println!("      add with: warden lists add {}", entry.url);
            }
        }
        println!();
    }

    println!("usage: warden lists add <list-id>");
    if unaddable_by_slug > 0 {
        println!(
            "note: {unaddable_by_slug} list(s) above are newer than this binary's built-in \
             catalog. `warden lists add` resolves slugs offline, so it does not know them yet — \
             add those by URL as shown."
        );
    }
    Ok(())
}

/// Whether the catalog row for `id` names a list this binary cannot
/// subscribe to by slug — i.e. `warden lists add <id>` would refuse it.
///
/// `builtin` is [`Catalog::fallback`], the table `derive_subscription`
/// actually resolves against. When `offline` the displayed catalog *is*
/// that table, so nothing can diverge and the answer is always false.
///
/// Split out of the render loop so the marker is testable: with
/// `FALLBACK_ENTRIES` in step with the published index the condition
/// never fires in practice, and an inline expression that cannot be
/// driven to `true` is indistinguishable from one that is broken.
fn slug_newer_than_this_build(builtin: &Catalog, id: &str, offline: bool) -> bool {
    !offline && builtin.resolve(id).is_none()
}

/// Fetch catalog from remote, fall back to hardcoded on error.
/// Returns (catalog, is_offline).
async fn fetch_catalog_for_display() -> (Catalog, bool) {
    let client =
        match crate::lists::http_client::build_list_client(std::time::Duration::from_secs(10)) {
            Ok(c) => c,
            Err(_) => return (Catalog::fallback(), true),
        };

    match Catalog::fetch(&client).await {
        Ok(c) => (c, false),
        Err(_) => (Catalog::fallback(), true),
    }
}

/// Collect unique scopes from catalog entries, sorted.
fn collect_scopes(entries: &[CatalogEntry]) -> Vec<&str> {
    let mut scopes: Vec<&str> = entries.iter().map(|e| e.scope.as_str()).collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Format a domain count for display: 5916174 → "5.9M", 204000 → "204K", 109 → "109".
fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        format!("{m:.1}M")
    } else if n >= 1_000 {
        let k = n as f64 / 1_000.0;
        if k >= 10.0 {
            format!("{k:.0}K")
        } else {
            format!("{k:.1}K")
        }
    } else {
        n.to_string()
    }
}

/// Forget a list source's cached data via IPC.
///
/// Sends [`IpcCommand::ForgetList`] over the authenticated socket;
/// the daemon's list manager drops the in-memory cache entry and
/// unlinks `<stem>.cache` + `<stem>.meta` from the lists directory.
/// The next refresh cycle re-downloads from upstream.
///
/// Idempotent — forgetting an unknown source prints `(was cached:
/// false)` and exits cleanly. Does NOT touch the configuration: the
/// source stays subscribed; only its cached body is dropped. Use
/// `warden lists remove` to also unsubscribe.
pub async fn run_forget(socket_path: &Path, source: &str) -> anyhow::Result<()> {
    super::lists_knobs::warn_if_frozen(socket_path).await;

    // Token is auto-attached by `socket_client::send_command` from
    // `~/.config/purge-warden/token`. ForgetList is `Mutating`, so a
    // missing or stale token surfaces as a daemon-side rejection.
    let cmd = IpcCommand::ForgetList {
        id: source.to_string(),
        token: None,
    };

    match socket_client::send_command(socket_path, &cmd).await {
        Ok(IpcResponse::ListForgotten { id, was_cached }) => {
            println!("forgot {id} (was cached: {was_cached})");
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("daemon refused list forget: {message}");
        }
        Ok(_) => {
            anyhow::bail!("unexpected response from daemon");
        }
        Err(e) => {
            anyhow::bail!(
                "could not reach the daemon over IPC: {e}\n\n\
                 `warden lists forget` goes through the authenticated IPC socket. Check:\n  \
                 • the daemon is running (`warden status`)\n  \
                 • the socket path matches your config\n  \
                 • you have a valid token (`warden token generate` if not)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    // ── a displayed slug must be an addable slug ────────────────

    /// The operator-visible half of the catalog gap: this is the exact
    /// call `warden lists add services/resolvers` makes, and it returned
    /// "is not a known list" while `warden lists catalog` was printing
    /// the row on the same binary.
    #[test]
    fn n1_services_resolvers_resolves_the_way_the_operator_types_it() {
        let (id, url) = derive_subscription("services/resolvers")
            .expect("a slug the catalog displays must resolve");
        assert_eq!(id, "services-resolvers");
        assert_eq!(url, "https://lists.purge.cc/resolvers.txt");
    }

    // ── the [active] marker ─────────────────────────────────────────

    fn mk_entry(scope: &str, topic: &str, url: &str) -> CatalogEntry {
        CatalogEntry {
            scope: scope.to_string(),
            topic: Some(topic.to_string()),
            name: topic.to_string(),
            url: url.to_string(),
            entries: 0,
            updated_at: String::new(),
            format: crate::config::schema::BlocklistFormat::Domains,
        }
    }

    fn mk_blocklist(id: &str, url: &str, enabled: bool) -> Blocklist {
        Blocklist {
            id: crate::config::schema::Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: crate::config::schema::BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Deny,
            trust: crate::config::schema::BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    /// The shape every install has: subscriptions in `[[blocklists]]`,
    /// the legacy array empty.
    ///
    /// This is what `warden lists add` writes, so it is not one config
    /// among several — it is the only one the verbs here produce. Reading
    /// the legacy array alone answered "you are subscribed to nothing" on
    /// every one of them.
    #[test]
    fn catalog_marks_a_v1_subscription_active() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/ads.txt");
        let active = ActiveSources::collect(
            &[],
            &[mk_blocklist(
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
                true,
            )],
        );
        assert!(
            active.contains(&entry, &entry.id()),
            "a [[blocklists]] row pointing at this catalog URL is a subscription to it"
        );
    }

    /// The marker has to be able to say no, or every row wearing it
    /// carries no information at all.
    #[test]
    fn catalog_marks_nothing_when_nothing_is_configured() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/ads.txt");
        assert!(!ActiveSources::default().contains(&entry, &entry.id()));

        let unrelated = ActiveSources::collect(
            &["security/malicious".to_string()],
            &[mk_blocklist(
                "corp",
                "https://lists.example.org/corp.txt",
                true,
            )],
        );
        assert!(
            !unrelated.contains(&entry, &entry.id()),
            "a config full of other lists must not mark this one"
        );
    }

    /// Both shapes the legacy array is allowed to hold. The slug form
    /// worked before; the URL form did not, and it is the one `init`
    /// scaffolds and an operator hand-edits.
    #[test]
    fn catalog_marks_either_legacy_array_shape_active() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/ads.txt");

        let by_slug = ActiveSources::collect(&["privacy/ads".to_string()], &[]);
        assert!(by_slug.contains(&entry, &entry.id()), "slash-form slug");

        let by_url = ActiveSources::collect(&["https://lists.purge.cc/ads.txt".to_string()], &[]);
        assert!(by_url.contains(&entry, &entry.id()), "URL form");
    }

    /// A slug subscription stores the URL the *built-in* catalog gave it,
    /// and this display renders the live one. When the two disagree the
    /// id is the axis that still recognises the list — which is exactly
    /// the drift that makes the id worth carrying.
    #[test]
    fn catalog_marks_a_slug_subscription_whose_url_has_drifted() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/v2/ads.txt");
        let active = ActiveSources::collect(
            &[],
            &[mk_blocklist(
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
                true,
            )],
        );
        assert!(
            active.contains(&entry, &entry.id()),
            "derive_subscription writes this id for this slug; the URL moved, the id did not"
        );
    }

    /// Two URLs HTTP considers the same list are the same list here.
    #[test]
    fn catalog_marker_compares_on_the_canonical_url_key() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/ads.txt");
        let active = ActiveSources::collect(
            &[],
            &[mk_blocklist(
                "mine",
                "HTTPS://lists.purge.cc/ads.txt/",
                true,
            )],
        );
        assert!(active.contains(&entry, &entry.id()));
    }

    /// A paused list is still one the operator has. The merge drops it
    /// because the manager must not fetch it, and that is the right
    /// answer to a different question than this display asks — `add`
    /// refuses the id either way, so an unmarked row would send the
    /// operator at a command that cannot work.
    #[test]
    fn catalog_marks_a_disabled_subscription_active() {
        let entry = mk_entry("privacy", "ads", "https://lists.purge.cc/ads.txt");
        let active = ActiveSources::collect(
            &[],
            &[mk_blocklist(
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
                false,
            )],
        );
        assert!(active.contains(&entry, &entry.id()));
    }

    /// The catalog display marks rows `add` will refuse, and the marker
    /// has to be provably reachable: `FALLBACK_ENTRIES` is in step with
    /// the index today, so on a live fetch nothing trips it, and an
    /// always-false branch reads exactly like a working one.
    ///
    /// The condition is not going away — lists.purge.cc publishes
    /// independently of releases, and a binary already deployed can
    /// never gain an entry — so this is the field behaviour of every
    /// older install, not a hypothetical.
    #[test]
    fn n1_catalog_display_marks_a_slug_this_build_cannot_add() {
        let builtin = Catalog::fallback();
        assert!(
            slug_newer_than_this_build(&builtin, "services/published-after-this-build", false),
            "a live row absent from the built-in table is one `add` refuses"
        );
        assert!(
            !slug_newer_than_this_build(&builtin, "privacy/ads", false),
            "a row this build can resolve must not be marked"
        );
        assert!(
            !slug_newer_than_this_build(&builtin, "services/published-after-this-build", true),
            "offline, the display IS the built-in table — nothing can diverge from it"
        );
    }

    /// A genuinely unknown slug still fails — the fix is one entry, not
    /// a loosened lookup. The message must name *which* catalog it
    /// means: sending the operator to `warden lists catalog` full stop
    /// is what made the old text absurd, since that is precisely where
    /// they had just read the slug.
    #[test]
    fn n1_unknown_slug_still_fails_and_says_which_catalog() {
        let err = derive_subscription("services/no-such-list")
            .expect_err("an unknown slug has no URL to subscribe to");
        let msg = err.to_string();
        assert!(msg.contains("built-in catalog"), "{msg}");
        assert!(
            msg.contains("live index"),
            "the operator must learn the two verbs read different sources: {msg}"
        );
    }

    fn temp_config(content: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/tmp/purge-warden-test-config-{}-{n}.toml",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Minimal valid v1 master — the proven-good shape from the
    /// `blocklists` test module. `run_add` / `run_remove` end in
    /// `validate_or_revert` (the full v1 loader), and `run_list` reads
    /// via `load_config`, so every config-touching test fixture must
    /// carry `schema_version` + a resolvable `default_profile`.
    const MINIMAL_V1: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn format_count_millions() {
        assert_eq!(format_count(3_880_771), "3.9M");
        assert_eq!(format_count(5_919_174), "5.9M");
        assert_eq!(format_count(1_000_000), "1.0M");
    }

    #[test]
    fn format_count_thousands() {
        assert_eq!(format_count(203_986), "204K");
        assert_eq!(format_count(33_475), "33K");
        assert_eq!(format_count(3_896), "3.9K");
        assert_eq!(format_count(1_000), "1.0K");
    }

    #[test]
    fn format_count_small() {
        assert_eq!(format_count(109), "109");
        assert_eq!(format_count(0), "0");
    }

    #[test]
    fn collect_scopes_deduplicates() {
        let entries = vec![
            CatalogEntry {
                scope: "privacy".into(),
                topic: Some("ads".into()),
                name: "Ads".into(),
                url: String::new(),
                entries: 0,
                updated_at: String::new(),
                format: Default::default(),
            },
            CatalogEntry {
                scope: "privacy".into(),
                topic: Some("tracking".into()),
                name: "Tracking".into(),
                url: String::new(),
                entries: 0,
                updated_at: String::new(),
                format: Default::default(),
            },
            CatalogEntry {
                scope: "security".into(),
                topic: Some("malicious".into()),
                name: "Malicious".into(),
                url: String::new(),
                entries: 0,
                updated_at: String::new(),
                format: Default::default(),
            },
        ];
        let scopes = collect_scopes(&entries);
        assert_eq!(scopes, vec!["privacy", "security"]);
    }

    /// No daemon runs during these tests; the reload attempt fails and
    /// is reported, which is not what any of them assert on.
    fn no_socket() -> PathBuf {
        PathBuf::from("/nonexistent/purge-warden-test.sock")
    }

    #[tokio::test]
    async fn add_creates_a_list_that_can_filter() {
        // The whole point of the verb: what it writes must be able to
        // filter, and only a `[[blocklists]]` entry ever can.
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(
            loaded.config.blocklists.len(),
            1,
            "a subscription must be a list entry, not a bare source string"
        );
        let b = &loaded.config.blocklists[0];
        assert_eq!(b.id.as_str(), "privacy-ads");
        assert_eq!(
            b.url,
            Catalog::fallback().resolve("privacy/ads").unwrap(),
            "the URL must come from the catalog, never be assembled by hand"
        );
        assert!(
            loaded.config.lists.sources.is_empty(),
            "nothing may be written to the channel that cannot filter"
        );
        // The LOADER still auto-promotes an untagged deny-list to
        // `uncategorized`, so this assertion holds — but it is a fact
        // about storage, not about reach. Tags decide nothing about
        // reach; what makes a fresh subscription filter is `base = deny`,
        // proven by `a_freshly_added_list_is_reached_by_the_default_profile`
        // below.
        std::fs::remove_file(&path).ok();
    }

    /// One level below the `dig`: the default profile must actually
    /// resolve to the list that was just added. This calls the same
    /// predicate the daemon uses to
    /// build a profile's subscription mask, so a list it does not return
    /// is a list that cannot filter — which is exactly what the previous
    /// implementation produced, silently, every time.
    #[tokio::test]
    async fn a_freshly_added_list_is_reached_by_the_default_profile() {
        use crate::profiles::profile::resolve_profile_blocklist_ids;

        // A default profile shaped the way `warden init` writes it —
        // no `tags` key. The scaffold used to write
        // `tags = ["uncategorized"]`; it stopped, since that value
        // decides nothing.
        //
        // Removing it strengthens the test rather than weakening it: the
        // predicate below, `resolve_profile_blocklist_ids`, filters on
        // `effective_direction(profile, list) != Ignore` and never reads
        // a tag, so the tag was inert here too — and the shape now under
        // test is the one an operator is actually handed.
        let path = temp_config(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        let profile = loaded.config.profiles.get("default").unwrap();
        let reached = resolve_profile_blocklist_ids(profile, &loaded.config.blocklists);
        let reached: Vec<&str> = reached.iter().map(|id| id.as_str()).collect();
        assert_eq!(
            reached,
            vec!["privacy-ads"],
            "the default profile must reach the list that was just subscribed"
        );
        std::fs::remove_file(&path).ok();
    }

    /// The same check stated the way an operator sees it: `blocklist
    /// list` and `blocklist show` mark a list that reaches nobody, and a
    /// freshly added one must not carry that mark.
    ///
    /// The marker's exact text is pinned here because the end-to-end
    /// acceptance script greps for that literal. If the const changed,
    /// the script would stop finding it and would report every list as
    /// fine — a check that cannot fail, which is worse than no check.
    #[tokio::test]
    async fn a_freshly_added_list_is_not_reported_as_unenforced() {
        use crate::profiles::profile::resolve_profile_blocklist_ids;

        assert_eq!(
            super::super::blocklists::NOT_ENFORCED,
            "NOT ENFORCED",
            "the acceptance script greps for this literal"
        );

        let path = temp_config(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        let profile = loaded.config.profiles.get("default").unwrap();
        let reached = resolve_profile_blocklist_ids(profile, &loaded.config.blocklists);
        assert!(
            !reached.is_empty(),
            "a list reached by no profile is what `{}` marks",
            super::super::blocklists::NOT_ENFORCED
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_url_derives_an_id_from_host_and_file_name() {
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "https://lists.example.org/ads.txt")
            .await
            .unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        let b = &loaded.config.blocklists[0];
        assert_eq!(b.id.as_str(), "lists-example-org-ads");
        assert_eq!(b.url, "https://lists.example.org/ads.txt");
        assert!(loaded.config.lists.sources.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_twice_is_idempotent() {
        // Re-running a provisioning script must not fail, and must not
        // subscribe the same body twice under two ids.
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_matches_an_existing_url_that_differs_only_by_trailing_slash() {
        // Two spellings of one URL share a cache file, so treating them
        // as different lists lets one silently overwrite the other's
        // body. The dedup is on the canonical form for that reason.
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "https://lists.example.org/ads.txt")
            .await
            .unwrap();
        run_add(&path, &no_socket(), "https://lists.example.org/ads.txt/")
            .await
            .unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_refuses_a_slug_with_no_known_url() {
        // Recording a slug we cannot resolve used to "succeed" and
        // produce something that could never download or filter.
        let path = temp_config(MINIMAL_V1);
        let err = run_add(&path, &no_socket(), "bogus/list")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("warden lists catalog"),
            "the refusal must say how to find a real list, got: {err}"
        );

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.blocklists.is_empty());
        assert!(loaded.config.lists.sources.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn remove_drops_the_list_the_argument_names() {
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();
        run_add(&path, &no_socket(), "security/malicious")
            .await
            .unwrap();

        // Removing by the same argument used to add it.
        run_remove(&path, &no_socket(), "privacy/ads")
            .await
            .unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        let ids: Vec<&str> = loaded
            .config
            .blocklists
            .iter()
            .map(|b| b.id.as_str())
            .collect();
        assert_eq!(ids, vec!["security-malicious"]);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn remove_clears_a_legacy_entry_left_by_an_older_release() {
        // Configs written before subscriptions became list entries still
        // hold these, and they are exactly the entries an operator needs
        // to be able to clear.
        let path = temp_config(&format!(
            "{MINIMAL_V1}\n[lists]\nsources = [\"privacy/ads\", \"security/malicious\"]\n"
        ));
        run_remove(&path, &no_socket(), "privacy/ads")
            .await
            .unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.lists.sources, vec!["security/malicious"]);
        std::fs::remove_file(&path).ok();
    }

    /// The state the add-path message tells operators to fix: one source
    /// recorded in both shapes. Removing it has to clear both, in one
    /// write — leaving half of it behind is how a config ends up with an
    /// entry that downloads and no entry that filters.
    #[tokio::test]
    async fn remove_clears_both_shapes_of_the_same_source() {
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "privacy/ads").await.unwrap();

        // Put the same source back in the legacy array by hand, which is
        // what an older release would have left behind.
        let body = std::fs::read_to_string(&path).unwrap();
        let mut doc: toml::Value = toml::from_str(&body).unwrap();
        doc.as_table_mut()
            .unwrap()
            .entry("lists".to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .unwrap()
            .insert(
                "sources".to_string(),
                toml::Value::Array(vec![toml::Value::String("privacy/ads".to_string())]),
            );
        std::fs::write(&path, toml::to_string(&doc).unwrap()).unwrap();

        let before = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(before.config.blocklists.len(), 1, "fixture: entry present");
        assert_eq!(before.config.lists.sources.len(), 1, "fixture: legacy too");

        run_remove(&path, &no_socket(), "privacy/ads")
            .await
            .unwrap();

        let after = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert!(
            after.config.blocklists.is_empty(),
            "the entry must be gone: {:?}",
            after.config.blocklists
        );
        assert!(
            after.config.lists.sources.is_empty(),
            "the legacy string must be gone too: {:?}",
            after.config.lists.sources
        );
        std::fs::remove_file(&path).ok();
    }

    /// Two different lists can reduce to one derived name. Reporting the
    /// second as "already subscribed" would be the same silent failure
    /// this verb was changed to end, so it is refused instead.
    #[tokio::test]
    async fn add_refuses_when_the_derived_name_is_taken_by_another_list() {
        let path = temp_config(MINIMAL_V1);
        run_add(&path, &no_socket(), "https://example.org/ads/list.txt")
            .await
            .unwrap();
        let err = run_add(&path, &no_socket(), "https://example.org/trackers/list.txt")
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("already taken"),
            "a name clash must be refused, not reported as a duplicate: {err}"
        );
        assert!(
            err.contains("warden blocklist add"),
            "the refusal must say how to name it: {err}"
        );

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn remove_of_something_absent_is_not_an_error() {
        let path = temp_config(&format!(
            "{MINIMAL_V1}\n[lists]\nsources = [\"privacy/ads\"]\n"
        ));
        assert!(run_remove(&path, &no_socket(), "nonexistent/list")
            .await
            .is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_leaves_every_other_section_untouched() {
        let path = temp_config(
            r#"schema_version = 3

[server]
default_profile = "default"
listen = "0.0.0.0:53"
log_level = "debug"
allow_from = ["10.0.0.0/8"]

[upstream]
servers = ["8.8.8.8:53"]

[lists]
update_interval_secs = 1800

[cache]
max_entries = 50000

[profiles.default]
display_name = "Default"
"#,
        );
        run_add(&path, &no_socket(), "security/malicious")
            .await
            .unwrap();

        let loaded = load_config(&path, time::OffsetDateTime::now_utc()).unwrap();
        let cfg = &loaded.config;
        assert_eq!(cfg.server.listen, "0.0.0.0:53".parse().unwrap());
        assert_eq!(cfg.server.log_level, "debug");
        assert_eq!(cfg.upstream.servers[0], "8.8.8.8:53");
        assert_eq!(cfg.lists.update_interval_secs, 1800);
        assert_eq!(cfg.cache.max_entries, 50_000);
        assert_eq!(cfg.blocklists.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn derived_ids_are_accepted_by_the_id_charset() {
        // The id goes through the same validation as a hand-typed one,
        // so anything derived here has to survive it — including from a
        // URL full of dots and a port number.
        use crate::config::schema::Id;
        for url in [
            "http://127.0.0.1:18080/sentinel.txt",
            "https://lists.example.org/ads.txt",
            "https://EXAMPLE.com/Hosts.TXT",
            "https://example.com",
            "https://example.com/",
            "https://user:pw@example.com/list.txt?v=2",
        ] {
            let id = id_from_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            Id::new(id.clone()).unwrap_or_else(|e| panic!("{url} produced {id:?}: {e}"));
        }
    }

    #[test]
    fn id_from_url_uses_host_and_file_name() {
        assert_eq!(
            id_from_url("http://127.0.0.1:18080/sentinel.txt").unwrap(),
            "127-0-0-1-sentinel"
        );
        assert_eq!(
            id_from_url("https://lists.example.org/ads.txt").unwrap(),
            "lists-example-org-ads"
        );
        // Credentials name the operator, not the list, so they are dropped.
        assert_eq!(
            id_from_url("https://user:pw@example.com/list.txt").unwrap(),
            "example-com-list"
        );
        // No file name to borrow — the host has to carry it alone.
        assert_eq!(id_from_url("https://example.com/").unwrap(), "example-com");
    }

    #[test]
    fn sanitize_id_collapses_runs_and_trims() {
        assert_eq!(sanitize_id("privacy-ads").unwrap(), "privacy-ads");
        assert_eq!(sanitize_id("Foo..Bar").unwrap(), "foo-bar");
        assert_eq!(sanitize_id("--lead-and-trail--").unwrap(), "lead-and-trail");
        assert_eq!(sanitize_id("///"), None);
        assert_eq!(sanitize_id(""), None);
        // Over-length input is cut to the id limit without leaving the
        // trailing dash the cut can expose.
        let long = sanitize_id(&format!("{}-x", "a".repeat(70))).unwrap();
        assert_eq!(long.len(), 64);
        assert!(!long.ends_with('-'));
    }
}
