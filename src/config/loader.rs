//! Multi-file v1 configuration loader (Sprint 29).
//!
//! Consumes a master `config.toml` and every file reachable via its
//! `includes` globs, producing a single [`LoadedConfig`] that packages
//! the merged [`ConfigV1`] together with a sidecar provenance map for
//! downstream error enrichment.
//!
//! Design source of truth: `_docs/features/config_architecture.md` §7 + §13-Sprint-29.
//!
//! Behaviours implemented here:
//!
//! - **Single-file fast-path.** When `config.includes` is empty, the
//!   loader short-circuits to [`super::schema::load::load_from_str`] with
//!   zero glob / merge / provenance overhead.
//! - **Deterministic glob ordering.** Globs are resolved with a
//!   byte-wise sort so two operators on two hosts see the same load
//!   order regardless of filesystem traversal quirks.
//! - **Merge rules per §7.3.** Array-of-tables sections are concatenated
//!   (validator enforces `id` uniqueness after merge); `[profiles.<id>]`
//!   is merged by sub-key with duplicate-key detection; every other
//!   table is treated as a singleton (duplicate across files → error
//!   with both file:line citations).
//! - **Path security per §7.4 (N12).** Include patterns must be relative
//!   and free of `..`. Resolved paths are canonicalised with the
//!   parent-dir + leaf trick so freshly-created-but-missing files still
//!   surface a precise error. Symlink targets that escape the config
//!   root are rejected.
//! - **Load limits per §7.5 (N11).** 1000 files, 50 MB aggregate bytes;
//!   either cap is a hard error carrying the count / size.
//! - **Cycle detection per §7.2.** Visited-set on canonical paths +
//!   max depth 4; the error reports the full include chain.
//! - **Provenance map.** A [`ProvenanceMap`] records the (file, line)
//!   for every top-level key + named-map sub-key + array-of-tables
//!   entity seen during the parse. Validator errors produced from the
//!   merged [`ConfigV1`] are enriched via this map so downstream CLI
//!   tooling can point the operator at the offending source file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use super::error::{ConfigError, ErrorContext};
use super::schema::{
    load::load_from_str_collect,
    validator::{validate_collect, AuditWarnings},
    ConfigV1,
};

/// Hard cap on the number of files reachable via `includes`. Design
/// doc N11.
pub const MAX_INCLUDE_FILES: usize = 1000;

/// Hard cap on the aggregate size in bytes of every file loaded via
/// `includes`. Design doc N11.
pub const MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum include depth (a master at depth 0, its includes at depth 1,
/// etc.). Any file at depth > 4 is rejected. Design doc §7.2.
pub const MAX_INCLUDE_DEPTH: usize = 4;

/// Top-level keys recognised by [`ConfigV1`]. Per-file unknown-key
/// detection happens here (before merge) so the error carries the
/// exact (file, line) of the bad section instead of a coarse
/// "unknown field in merged config" after the fact.
const KNOWN_TOP_LEVEL: &[&str] = &[
    "schema_version",
    "includes",
    "server",
    "retired",
    "blocklists",
    // NOTE: `categories` was the S49 organisational-tag entity; it was
    // RETIRED in the v2-tags migration and is intentionally absent here
    // (rev-2606 loader-01). A config still carrying `[[categories]]` hits
    // the directed migration branch in `reject_unknown_top_level`.
    "profiles",
    "devices",
    "groups",
    "subnets",
    "schedules",
    "admin_rules",
    "custom_lists",
    // Singleton — ceilings for the custom-list file reader. Distinct name
    // from `custom_lists` because TOML cannot hold a table and an array of
    // tables under one name; keep it OUT of `ARRAY_OF_TABLES_KEYS`.
    "custom_list_limits",
    // §4.66 L1 — the `[[labels]]` vocabulary.
    "labels",
    // S30 pass-through sections — daemon-wide config the `ConfigV1`
    // struct now holds verbatim (reusing the legacy `config::settings`
    // types until S31-33 ports individual sections to fresh v1 shapes).
    "upstream",
    // §4.10 — DNSSEC validation section (opt-in, OFF by default).
    "dnssec",
    "cache",
    "tracking",
    "security",
    "anti_bypass",
    "socket",
    "api",
    "forwarding",
    "local_dns",
    "ip_blocklists",
    // DEPRECATED legacy alias for `ip_blocklists` — accepted at load time
    // with a `tracing::warn!`. Remove at schema_version = 3.
    "ip_denylists",
    "lists",
    // §4.13 — resource budget sampler section.
    "resource_budget",
    // `[backup]` — config-backup output dir (tooling-only; CLI + TUI read it).
    "backup",
    // §4.11 — primary/secondary cluster replication (node-local, inert in
    // §4.11-1). Singleton section, so NOT in ARRAY_OF_TABLES_KEYS / NAMED_MAP_KEYS.
    "cluster",
    // DEPRECATED (S42 T5) legacy alias for `[[devices]]` — accepted at load
    // time with a `tracing::warn!`. Remove at schema_version = 3.
    "clients",
];

/// Top-level keys that are arrays of tables — merged by concatenation.
const ARRAY_OF_TABLES_KEYS: &[&str] = &[
    "retired",
    "blocklists",
    "devices",
    "groups",
    "subnets",
    "schedules",
    "admin_rules",
    // Registering a new array-of-tables here is NOT optional and NOT
    // covered by `known_top_level_covers_configv1_serialized_keys`: that
    // test only proves the key is recognised. A key that is known but
    // absent here falls through to `merge_singleton`, so a second
    // `[[custom_lists]]` in a sibling include file is rejected as a
    // duplicate singleton.
    "custom_lists",
    // §4.66 L1. Same reasoning as the entry above — see its comment.
    "labels",
];

/// Top-level keys that are named-maps (e.g. `[profiles.<id>]`).
/// Merged by sub-key with duplicate-key detection.
const NAMED_MAP_KEYS: &[&str] = &["profiles"];

/// The sync-owned drop-in directory, a sibling of the master, resolved by a
/// secondary's `includes = ["cluster.d/*.toml"]` glob (§4.11).
///
/// Lives here, ungated, because it has **two** consumers on opposite sides of
/// the `cluster` feature flag: the writer (`cluster::apply`, gated OFF by
/// default) and the secondary-master guard in
/// [`crate::config::schema::validator`] (always compiled). Two independent
/// string literals would agree until one of them was edited, and the
/// disagreement would surface as a guard refusing every real secondary — on a
/// live node, in a build most developers never compile.
pub const CLUSTER_DROP_IN_DIR: &str = "cluster.d";

/// Is `file` a config slice the cluster sync installed, rather than something
/// the operator wrote?
///
/// Answered structurally — the file's parent directory is
/// [`CLUSTER_DROP_IN_DIR`] — so it holds for any config root and needs no
/// knowledge of where the master lives. `apply.rs` writes exactly
/// `<config_dir>/cluster.d/<bundle>`, one level deep, so the parent check is
/// exact rather than a prefix heuristic.
#[must_use]
pub fn is_cluster_drop_in(file: &Path) -> bool {
    file.parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == CLUSTER_DROP_IN_DIR)
}

/// Singleton sections that may be SPLIT across files and field-merged
/// (sub-key union) instead of rejected as a whole-section duplicate.
///
/// `[server]` is the only such section: a cluster secondary keeps its
/// node-local `server.listen` in the master while the synced policy bundle
/// (dropped into `cluster.d/`) supplies `server.default_profile` and the
/// other policy fields (§4.11-3 / `cluster_sync.md` §4.2). The merge is
/// field-level — a duplicate *sub-key* (the same `server.*` field defined
/// in two files) is still a hard `DuplicateId`, mirroring the named-map
/// rule. Every singleton NOT in this list still errors on a second
/// definition (the `merge_singleton` default path).
///
/// Gated on the `cluster` feature: only a cluster build ever runs as a
/// secondary (the sole producer of a split `[server]`), so the DEFAULT
/// build's merge behaviour — and lib test count — stays byte-identical.
#[cfg(feature = "cluster")]
const SPLIT_MERGE_SINGLETONS: &[&str] = &["server"];

/// Sidecar map `entity_path → (file, line)` populated during the
/// multi-file parse. Used by [`load_config`] to enrich validator errors
/// with the source file and line number of the offending entity.
///
/// Keys are dotted paths matching the `.entity` field produced by the
/// validator, e.g. `"devices.iphone"`, `"profiles.default"`, `"server"`,
/// `"schema_version"`.
pub type ProvenanceMap = BTreeMap<String, (PathBuf, usize)>;

/// Outcome of a successful multi-file config load.
#[derive(Debug)]
pub struct LoadedConfig {
    /// The fully merged + validated v1 configuration.
    pub config: ConfigV1,
    /// The canonical path of the master file that was loaded.
    pub master_path: PathBuf,
    /// Canonical paths of every file read during load (master first,
    /// then included files in glob-resolution order).
    pub files_loaded: Vec<PathBuf>,
    /// Aggregate byte size of every file read during load.
    pub total_bytes: u64,
    /// Sidecar map for post-hoc error enrichment. See [`ProvenanceMap`].
    pub provenance: ProvenanceMap,
    /// Every declared custom list, parsed. Built here, once per load, so
    /// profile compilation never touches the disk.
    pub custom_lists: crate::config::custom_list::CustomListStore,
}

/// A read-substitution + extra-member overlay for [`load_config_with_overlay`].
///
/// Lets a validating writer run the full multi-file load + validation against
/// STAGED bytes — the bytes a CLI/IPC mutation is about to promote — *before*
/// the rename, so a cross-reference-invalid tree is never the on-disk truth
/// even for an instant (rev2606 target-01). Cold path only: built per CLI/IPC
/// write, never consulted on the DNS query path.
///
/// - `substitutions`: when the loader would read a canonical path, it reads
///   these bytes instead. Used to validate the edited slice in place.
/// - `extra_members`: canonical paths to load as if a glob had matched them,
///   even when they are not yet on disk — brand-new include-slice creation.
///   Each also carries a substitution.
///
/// An empty overlay (or `None`) makes the loader byte-for-byte identical to
/// today; see [`load_config_with_overlay`].
#[derive(Debug, Default)]
pub struct LoaderOverlay {
    substitutions: BTreeMap<PathBuf, String>,
    extra_members: Vec<PathBuf>,
}

impl LoaderOverlay {
    /// Stage `bytes` to be read in place of `canonical`'s on-disk contents.
    /// `new_file` = the path is not yet on disk / not glob-visible, so also
    /// load it as an extra include member. `canonical` MUST be canonicalised
    /// with [`canonicalize_path`] (the same function the loader keys reads on)
    /// or the substitution will silently miss and the loader will read stale
    /// disk bytes.
    pub fn stage(&mut self, canonical: PathBuf, bytes: String, new_file: bool) {
        if new_file {
            self.extra_members.push(canonical.clone());
        }
        self.substitutions.insert(canonical, bytes);
    }

    /// Bytes to read in place of `canonical`, if staged.
    fn substitution(&self, canonical: &Path) -> Option<&str> {
        self.substitutions.get(canonical).map(String::as_str)
    }
}

/// Load and validate a v1 configuration starting from `master_path`.
///
/// - Resolves `includes` globs relative to each file's own directory.
/// - Enforces path security, load limits, and cycle detection
///   before deserialisation.
/// - Merges singleton / array-of-tables / named-map sections per
///   design doc §7.3.
/// - Runs [`validate_collect`] on the merged config; any
///   [`ConfigError::context`] whose `entity` matches a provenance key
///   is stamped with the corresponding `(file, line)`.
///
/// `now` is threaded through the validator so the N8 retired-id window
/// stays deterministic in tests.
pub fn load_config(
    master_path: &Path,
    now: OffsetDateTime,
) -> Result<LoadedConfig, Vec<ConfigError>> {
    load_config_with_overlay(master_path, now, None)
}

/// [`load_config`] that also hands back the validator's operator-facing
/// audit warnings as **data**.
///
/// This is `warden config lint`'s entry point
/// (`s-rev2606-lint-warn-fixture-flaky-parallel`). Lint used to obtain the
/// same list by installing a thread-scoped `tracing` subscriber around
/// `load_config` and reading the events back — i.e. using the
/// process-global tracing dispatcher as a data channel, which raced with
/// every other test thread touching that global. The warnings now travel
/// in-band; the daemon's `tracing::warn!(target: "audit", …)` lines are
/// untouched (see [`AuditWarnings`]).
///
/// Warnings are only collected on the success path: the sole caller
/// prints errors and exits `1` when the load fails, so a failed load's
/// partial warning list has no consumer. The returned `Vec` is empty for
/// every `Err`.
pub fn load_config_collect(
    master_path: &Path,
    now: OffsetDateTime,
) -> (Result<LoadedConfig, Vec<ConfigError>>, Vec<String>) {
    let mut warns = AuditWarnings::emitting();
    let result = load_config_inner(master_path, now, None, &mut warns);
    match result {
        Ok(loaded) => (Ok(loaded), warns.into_messages()),
        Err(errs) => (Err(errs), Vec::new()),
    }
}

/// Overlay-aware variant of [`load_config`].
///
/// `overlay` substitutes the bytes read for specific canonical paths (and can
/// inject brand-new include members not yet on disk), so the full multi-file
/// load + validation runs against STAGED bytes before they are promoted. The
/// CLI/IPC validating writers
/// ([`crate::cli::commands::target::write_value_validated`]) use this to refuse
/// a cross-reference-invalid mutation before the rename (rev2606 target-01).
///
/// With `overlay = None` this is byte-for-byte identical to the pre-overlay
/// [`load_config`]: every overlay branch short-circuits, the size guard uses
/// `metadata`, and no extra members load. The daemon, the Pi build, and the
/// `cluster` build always pass `None`.
pub fn load_config_with_overlay(
    master_path: &Path,
    now: OffsetDateTime,
    overlay: Option<&LoaderOverlay>,
) -> Result<LoadedConfig, Vec<ConfigError>> {
    load_config_inner(master_path, now, overlay, &mut AuditWarnings::emitting())
}

/// Shared body of [`load_config_with_overlay`] and [`load_config_collect`].
///
/// `warns` collects the validator's audit WARNs. Every production caller
/// passes an [`AuditWarnings::emitting`] collector and discards it, so
/// journald behaviour is exactly what it was before the collector existed.
fn load_config_inner(
    master_path: &Path,
    now: OffsetDateTime,
    overlay: Option<&LoaderOverlay>,
    warns: &mut AuditWarnings,
) -> Result<LoadedConfig, Vec<ConfigError>> {
    let canonical_master = canonicalize_path(master_path).map_err(|e| vec![e])?;
    let root = canonical_master
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            vec![ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "master config path has no parent directory: {}",
                    canonical_master.display(),
                ))
                .with_file(canonical_master.clone()),
            )]
        })?;

    let mut ctx = LoadCtx {
        root,
        master_schema_version: None,
        loaded: BTreeSet::new(),
        loading_stack: Vec::new(),
        files_loaded: Vec::new(),
        total_bytes: 0,
        merged: toml::Table::new(),
        provenance: ProvenanceMap::new(),
        master_src: None,
        deprecations: Vec::new(),
        overlay,
    };

    // Master file is loaded first; its directory is the config root.
    load_file(&canonical_master, &mut ctx, 0, now)?;

    // Overlay extra members: brand-new include slices a validating writer is
    // creating. Load each as if a glob had matched it (depth 1) so the merged
    // validation sees the post-rename file set. A non-empty list also forces
    // the multi-file merge path below (a new member means the tree is no
    // longer single-file). With `None` / empty this loop never runs, so the
    // fast-path decision and everything downstream stay byte-identical.
    if let Some(ov) = ctx.overlay {
        for member in &ov.extra_members {
            let canonical_member = canonicalize_path(member).map_err(|e| vec![e])?;
            ensure_inside_root(&canonical_member, &ctx.root, &canonical_master)?;
            load_file(&canonical_member, &mut ctx, 1, now)?;
        }
    }

    // config-lint-blind-to-loader-deprecations: hand the key-deprecation
    // notices to the caller's collector.
    //
    // Placed HERE, above the single-file fast-path branch, deliberately: it is
    // the one point both exits pass through. Draining inside the multi-file
    // arm would test green on a multi-file fixture and do nothing on the
    // shipped layout, which is single-file — the same asymmetry that made
    // `s1-followup-load-from-str-collect` a real defect rather than a
    // cosmetic one.
    for msg in std::mem::take(&mut ctx.deprecations) {
        warns.push(msg);
    }

    // s4 config-m4 — resolve `secrets.toml` so the validator can cross-check
    // `auth_token_ref` against the names that actually exist. Loaded here,
    // not inside the validator, so `validate_collect` stays a pure function
    // of (config, now) and its tests need no filesystem.
    //
    // An `Err` (absent is NOT an error — `load_secrets` returns an empty
    // table for a missing file; this is a symlinked, widened-mode, or
    // unreadable one) degrades to `None`, which skips only the cross-check.
    // Deliberate: the permission gate is enforced for real at daemon start
    // and on reload, and an unprivileged `warden config lint` that cannot
    // read a 0600 secrets file must still be able to lint everything else
    // rather than fail wholesale on a check it cannot perform.
    let secrets = crate::config::secrets::load_secrets(&crate::config::secrets::secrets_path_for(
        &canonical_master,
    ))
    .ok();

    // ── single-file fast-path ────────────────────────────────────
    //
    // When the master declared no includes (and none of its — absent
    // — sub-files did either), bypass the merge/deserialise pipeline
    // and reuse the single-file facade. This keeps the "one-file
    // deployment" case a one-parse fast-path with identical error
    // classification as Sprint 28.
    if ctx.files_loaded.len() == 1 {
        // config-m3: reuse the bytes `load_file` already read under the N11
        // guards. This used to be a second, uncapped `fs::read_to_string` of
        // the master — the only read in the loader with nothing in front of
        // it, and (on the shipped single-file layout) a second full copy of a
        // file already in memory.
        //
        // The overlay branch is gone rather than duplicated: `load_file`
        // resolves the substitution at its own read site, so `master_src`
        // already holds the staged bytes when a writer is validating. Two
        // sites consulting the overlay independently is how they drift.
        let src = ctx.master_src.take().ok_or_else(|| {
            vec![ConfigError::ValidationFailed(
                ErrorContext::new("internal: master source not captured during load".to_string())
                    .with_file(canonical_master.clone()),
            )]
        })?;
        // s1-followup-load-from-str-collect: ONE validating pass, into the
        // caller's collector, carrying the secrets table and the provenance
        // map. This used to be `load_from_str` (validating, emitting to
        // `tracing`, unable to take a collector) followed by a second
        // `validate_collect` in silent mode purely to harvest the same
        // messages as data — on the fast path, which is the shipped layout.
        let config = load_from_str_collect(
            &src,
            Some(&canonical_master),
            now,
            warns,
            secrets.as_ref(),
            Some(&ctx.provenance),
        )?;
        // The s4 config-m4 `auth_token_ref` cross-check is preserved: it rides
        // on the `secrets` argument above, which the single pass now carries.
        // That check fires on the shipped single-file layout or on nobody.
        let custom_lists = build_custom_list_store(&ctx.root, &config)?;
        return Ok(LoadedConfig {
            config,
            master_path: canonical_master,
            files_loaded: ctx.files_loaded,
            total_bytes: ctx.total_bytes,
            provenance: ctx.provenance,
            custom_lists,
        });
    }

    // ── multi-file merge + deserialise ──────────────────────────
    let merged_value = toml::Value::Table(ctx.merged.clone());
    let config: ConfigV1 = merged_value
        .try_into()
        .map_err(|err: toml::de::Error| vec![classify_merged_error(err, &ctx.provenance)])?;

    // Bound to a `let` rather than matched inline: `Some(&ctx.provenance)` is
    // a temporary whose lifetime would otherwise extend over the whole `match`,
    // and the `Ok` arm MOVES `ctx.provenance` into the returned `LoadedConfig`.
    let verdict = validate_collect(&config, now, warns, secrets.as_ref(), Some(&ctx.provenance));
    match verdict {
        Ok(()) => {
            let custom_lists = build_custom_list_store(&ctx.root, &config)?;
            Ok(LoadedConfig {
                config,
                master_path: canonical_master,
                files_loaded: ctx.files_loaded,
                total_bytes: ctx.total_bytes,
                provenance: ctx.provenance,
                custom_lists,
            })
        }
        Err(errs) => Err(errs
            .into_iter()
            .map(|e| enrich_with_provenance(e, &ctx.provenance))
            .collect()),
    }
}

/// Read the pack files once per load, against the master's own parent.
///
/// `root` is the one fence the whole include graph is confined to, so a
/// `[[custom_lists]]` declared in an included fragment still resolves under
/// the master's `packs/` — two readings of "the config parent" would each be
/// internally coherent and neither could report the other as wrong.
///
/// A failure fails the load. The caller's reload path already treats a
/// rejected config as "nothing changed", so preserving the previous policy
/// needs no branch of its own, and a cold start refuses rather than starting
/// with a policy quietly smaller than the file says.
fn build_custom_list_store(
    root: &Path,
    config: &ConfigV1,
) -> Result<crate::config::custom_list::CustomListStore, Vec<ConfigError>> {
    crate::config::custom_list::build_store(
        root,
        &config.custom_lists,
        config.custom_list_limits.max_file_bytes,
    )
    .map_err(|failures| {
        failures
            .into_iter()
            .map(|(id, e)| {
                ConfigError::ValidationFailed(
                    ErrorContext::new(format!("custom list \"{id}\": {e}"))
                        .with_entity(format!("custom_lists.{id}"))
                        .with_suggestion(e.remedy()),
                )
            })
            .collect()
    })
}

// ── internal state ──────────────────────────────────────────────────

struct LoadCtx<'o> {
    root: PathBuf,
    master_schema_version: Option<i64>,
    loaded: BTreeSet<PathBuf>,
    loading_stack: Vec<PathBuf>,
    files_loaded: Vec<PathBuf>,
    total_bytes: u64,
    merged: toml::Table,
    provenance: ProvenanceMap,
    /// The master file's source text, as `load_file` actually read it —
    /// after the overlay substitution and after the N11 size guards.
    ///
    /// `s-review-2605-config-m3`: the single-file fast path used to re-read
    /// the master with a bare `fs::read_to_string`, which was the one read in
    /// the loader with no cap in front of it. Handing the bytes over instead
    /// removes that read entirely rather than capping it — so there is no
    /// second allocation of a file already held in memory, and no window in
    /// which the fast path could parse different bytes than the ones the size
    /// guard measured.
    master_src: Option<String>,
    /// Key-deprecation notices raised while reading the include graph, in
    /// file order. Drained into the caller's [`AuditWarnings`] once every
    /// file is in, so `warden config lint` sees the same set the daemon logs
    /// at boot (`config-lint-blind-to-loader-deprecations`).
    deprecations: Vec<String>,
    /// Optional read-substitution + extra-member overlay. `None` on every
    /// daemon load; `Some` only under a validating writer (cold CLI/IPC path).
    overlay: Option<&'o LoaderOverlay>,
}

#[allow(clippy::only_used_in_recursion)]
fn load_file(
    canonical: &Path,
    ctx: &mut LoadCtx<'_>,
    depth: usize,
    // `now` is threaded to keep the same reference time across the
    // whole include graph (sub-files recurse with the caller's clock,
    // not a fresh one) even though this frame doesn't consume it.
    now: OffsetDateTime,
) -> Result<(), Vec<ConfigError>> {
    if depth > MAX_INCLUDE_DEPTH {
        let chain = include_chain(&ctx.loading_stack, canonical);
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "include depth limit exceeded ({} > {}). chain: {}",
                depth, MAX_INCLUDE_DEPTH, chain,
            ))
            .with_file(canonical.to_path_buf()),
        )]);
    }

    if ctx.loading_stack.iter().any(|p| p == canonical) {
        let chain = include_chain(&ctx.loading_stack, canonical);
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!("include cycle detected. chain: {chain}"))
                .with_file(canonical.to_path_buf()),
        )]);
    }

    if ctx.loaded.contains(canonical) {
        // Same file reachable via two different include paths — load
        // once, merge once. Cycle detection above excludes self-loops.
        return Ok(());
    }

    ctx.loading_stack.push(canonical.to_path_buf());

    // Per-file size guard (N11): stat BEFORE reading so a single oversized
    // include — malicious, a stray log redirect, or a glob that captured a
    // huge generated file — cannot be slurped fully into memory and OOM
    // the process before the aggregate cap (below) is ever consulted.
    // Reject when this file alone would bust the remaining budget; peak
    // memory then stays bounded by `MAX_TOTAL_BYTES`, not by the largest
    // single member.
    // When the overlay substitutes this path's bytes, account the staged
    // byte length and skip the on-disk stat — the file may not exist yet
    // (new-slice creation) or may differ in size from what will be loaded.
    let file_len = match ctx.overlay.and_then(|o| o.substitution(canonical)) {
        Some(bytes) => bytes.len() as u64,
        None => {
            let md = std::fs::metadata(canonical).map_err(|io_err| {
                vec![ConfigError::Parse(
                    ErrorContext::new(format!("cannot stat config: {io_err}"))
                        .with_file(canonical.to_path_buf()),
                )]
            })?;
            // loader-07: reject a non-regular file (FIFO, socket, device,
            // directory) BEFORE `read_to_string` below can block forever on
            // it. `metadata` follows symlinks (and never blocks — it's a
            // stat), so a glob symlink pointing at a FIFO inside the config
            // root is caught here too, covering both include branches.
            if !md.file_type().is_file() {
                return Err(vec![ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "include path is not a regular file: {}",
                        canonical.display()
                    ))
                    .with_file(canonical.to_path_buf())
                    .with_suggestion(
                        "includes must resolve to regular files (no FIFOs, sockets, or directories)",
                    ),
                )]);
            }
            md.len()
        }
    };
    if ctx.total_bytes.saturating_add(file_len) > MAX_TOTAL_BYTES {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "aggregate include size would exceed {} bytes (>{} MB cap reading {}, which is {} bytes)",
                MAX_TOTAL_BYTES,
                MAX_TOTAL_BYTES / 1024 / 1024,
                canonical.display(),
                file_len,
            ))
            .with_file(canonical.to_path_buf()),
        )]);
    }

    let src = match ctx.overlay.and_then(|o| o.substitution(canonical)) {
        Some(bytes) => bytes.to_string(),
        None => {
            // loader-08: bound the read by the REMAINING aggregate budget so a
            // file that grew past `file_len` in the stat->read TOCTOU window
            // can't be slurped unbounded (the post-read aggregate check only
            // fires AFTER allocation). `take(remaining + 1)` caps peak memory
            // and lets us detect the overrun.
            let remaining = MAX_TOTAL_BYTES.saturating_sub(ctx.total_bytes);
            read_to_string_capped(canonical, remaining)?
        }
    };

    ctx.total_bytes = ctx.total_bytes.saturating_add(src.len() as u64);
    if ctx.total_bytes > MAX_TOTAL_BYTES {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "aggregate include size exceeded {} bytes (>{} MB cap after loading {})",
                ctx.total_bytes,
                MAX_TOTAL_BYTES / 1024 / 1024,
                canonical.display(),
            ))
            .with_file(canonical.to_path_buf()),
        )]);
    }

    ctx.files_loaded.push(canonical.to_path_buf());
    if ctx.files_loaded.len() > MAX_INCLUDE_FILES {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "include file count exceeded {} (hard cap {})",
                ctx.files_loaded.len(),
                MAX_INCLUDE_FILES,
            ))
            .with_file(canonical.to_path_buf()),
        )]);
    }

    let parsed: toml::Value = toml::from_str(&src).map_err(|err| {
        let line = err.span().map(|s| line_of(&src, s.start));
        let mut c = ErrorContext::new(format!("toml parse error: {err}"))
            .with_file(canonical.to_path_buf());
        if let Some(l) = line {
            c = c.with_line(l);
        }
        vec![ConfigError::Parse(c)]
    })?;
    let mut table = match parsed {
        toml::Value::Table(t) => t,
        _ => {
            return Err(vec![ConfigError::Parse(
                ErrorContext::new("config file must be a TOML table at top level")
                    .with_file(canonical.to_path_buf()),
            )]);
        }
    };

    // Catch unknown top-level keys on the first hop (where we still
    // have precise file + line, unlike after the merge collapses
    // everything into one toml::Value).
    reject_unknown_top_level(&table, canonical, &src)?;

    // Terminology deprecation (S42 T2): `[ip_denylists]` is renamed
    // `[ip_blocklists]`. Accept both, but WARN once per file when the
    // legacy key is present AND normalise it to the canonical key name
    // before the merge/deserialise pipeline runs — so multi-file loads
    // mixing `ip_denylists` and `ip_blocklists` across files collapse
    // into a single section (duplicate → the same singleton conflict
    // path the merger uses for every other section). Remove at
    // schema_version = 3.
    normalise_deprecated_keys(&mut table, canonical, &src, &mut ctx.deprecations)?;

    // Per-file provenance: record each top-level key and (where
    // applicable) per-entity sub-paths.
    record_provenance(&table, canonical, &src, &mut ctx.provenance);

    // config-m3 — last use of `src` in this frame, so the master's bytes move
    // into the context instead of being dropped and re-read by the single-file
    // fast path. Set here rather than at the top of the function so it cannot
    // hold bytes for a file that failed a guard above; every path between here
    // and the end of the frame either returns `Err` (propagated) or leaves it
    // set, so the fast path's `take()` is total.
    if depth == 0 {
        ctx.master_src = Some(src);
    }

    // Take this file's schema_version out — the master dictates it;
    // sub-files may echo it if they want but must not disagree.
    if let Some(v) = table.remove("schema_version") {
        let this_version = v.as_integer().ok_or_else(|| {
            vec![ConfigError::Parse(
                ErrorContext::new("schema_version must be an integer")
                    .with_file(canonical.to_path_buf())
                    .with_entity("schema_version"),
            )]
        })?;
        // loader-06: `ConfigV1.schema_version` is a `u32` — reject a negative
        // or oversized value HERE, where we still have the precise file:line,
        // instead of losing provenance to the post-merge `try_into`.
        if this_version < 0 || this_version > i64::from(u32::MAX) {
            return Err(vec![ConfigError::Parse(
                ErrorContext::new(format!(
                    "schema_version must be a non-negative integer that fits u32 (got {this_version})"
                ))
                .with_file(canonical.to_path_buf())
                .with_entity("schema_version"),
            )]);
        }
        match ctx.master_schema_version {
            None if depth == 0 => {
                // The master (depth 0) is the authority — record + carry into
                // the merged tree.
                ctx.master_schema_version = Some(this_version);
                ctx.merged.insert(
                    "schema_version".to_string(),
                    toml::Value::Integer(this_version),
                );
            }
            None => {
                // loader-09: an INCLUDE declares schema_version but the master
                // did not. The previous code silently let the first include
                // supply it, then misattributed any later mismatch to "the
                // master's value". Require the master to be the authority.
                return Err(vec![ConfigError::ValidationFailed(
                    ErrorContext::new(
                        "schema_version is declared in an include but not in the master config; \
                         declare schema_version in the master",
                    )
                    .with_file(canonical.to_path_buf())
                    .with_entity("schema_version"),
                )]);
            }
            Some(master) if master == this_version => {
                // Echo; strip silently, already recorded above.
            }
            Some(master) => {
                return Err(vec![ConfigError::VersionMismatch(
                    ErrorContext::new(format!(
                        "schema_version = {this_version} disagrees with master's {master}",
                    ))
                    .with_file(canonical.to_path_buf())
                    .with_entity("schema_version"),
                )]);
            }
        }
    }

    // Extract + strip `includes`. Sub-file includes are resolved
    // relative to the sub-file's own directory; the final merged tree
    // carries only the master's declaration (so
    // `LoadedConfig.config.includes` reflects what the operator wrote,
    // not the recursively-flattened graph).
    let includes_raw = table.remove("includes");
    let is_master = depth == 0;
    let child_includes = if is_master {
        // Master: keep its declaration in the merged output AND resolve it below.
        if let Some(ref v) = includes_raw {
            ctx.merged.insert("includes".to_string(), v.clone());
        }
        parse_include_patterns(includes_raw, canonical)?
    } else {
        parse_include_patterns(includes_raw, canonical)?
    };

    // Merge every remaining top-level key into the accumulator.
    let other_file_source = canonical.to_path_buf();
    merge_into(&mut ctx.merged, table, &other_file_source, &ctx.provenance)?;

    // Recurse into this file's own includes. Glob base = this file's
    // directory (design doc §7.2: "Paths are relative to the file that
    // declares the includes").
    let this_dir = canonical.parent().unwrap_or(&ctx.root).to_path_buf();
    for pattern in &child_includes {
        let matched = resolve_include_pattern(pattern, &this_dir, &ctx.root, canonical)?;
        for matched_path in matched {
            let canonical_child = canonicalize_path(&matched_path).map_err(|e| vec![e])?;
            ensure_inside_root(&canonical_child, &ctx.root, canonical)?;
            load_file(&canonical_child, ctx, depth + 1, now)?;
        }
    }

    let popped = ctx.loading_stack.pop();
    debug_assert_eq!(popped.as_deref(), Some(canonical));

    ctx.loaded.insert(canonical.to_path_buf());

    Ok(())
}

// ── include pattern handling ────────────────────────────────────────

fn parse_include_patterns(
    raw: Option<toml::Value>,
    file: &Path,
) -> Result<Vec<String>, Vec<ConfigError>> {
    let Some(v) = raw else {
        return Ok(Vec::new());
    };
    let arr = match v {
        toml::Value::Array(a) => a,
        _ => {
            return Err(vec![ConfigError::Parse(
                ErrorContext::new("`includes` must be an array of strings")
                    .with_file(file.to_path_buf()),
            )]);
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        match item {
            toml::Value::String(s) => out.push(s),
            other => {
                return Err(vec![ConfigError::Parse(
                    ErrorContext::new(format!(
                        "`includes` entries must be strings, got {}",
                        other.type_str(),
                    ))
                    .with_file(file.to_path_buf()),
                )]);
            }
        }
    }
    Ok(out)
}

fn resolve_include_pattern(
    pattern: &str,
    base_dir: &Path,
    root: &Path,
    declared_by: &Path,
) -> Result<Vec<PathBuf>, Vec<ConfigError>> {
    if pattern.is_empty() {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new("empty include pattern").with_file(declared_by.to_path_buf()),
        )]);
    }
    let pb = Path::new(pattern);
    if pb.is_absolute() {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "include pattern must be relative, got absolute path: {pattern}"
            ))
            .with_file(declared_by.to_path_buf()),
        )]);
    }
    if pb
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!("include pattern must not contain `..`: {pattern}"))
                .with_file(declared_by.to_path_buf()),
        )]);
    }

    let has_wildcard = pattern.contains('*') || pattern.contains('?') || pattern.contains('[');

    let matches = if !has_wildcard {
        let full = base_dir.join(pattern);
        if !full.exists() {
            return Err(vec![ConfigError::Parse(
                ErrorContext::new(format!("include file not found: {}", full.display(),))
                    .with_file(declared_by.to_path_buf()),
            )]);
        }
        vec![full]
    } else {
        expand_wildcard(pattern, base_dir, declared_by, root)?
    };

    // Byte-wise sort for deterministic cross-platform ordering.
    let mut sorted = matches;
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

/// Expand a single include pattern with wildcards. Only supports one
/// wildcard segment (e.g. `devices.d/*.toml`, not `**/*.toml`); anything
/// more adventurous is rejected until a concrete need arises.
fn expand_wildcard(
    pattern: &str,
    base_dir: &Path,
    declared_by: &Path,
    _root: &Path,
) -> Result<Vec<PathBuf>, Vec<ConfigError>> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let wild_idx = parts
        .iter()
        .position(|p| p.contains('*') || p.contains('?') || p.contains('['));
    let Some(wild_idx) = wild_idx else {
        // Shouldn't happen — caller checked for wildcards. Defensive.
        return Ok(vec![base_dir.join(pattern)]);
    };
    if wild_idx != parts.len() - 1 {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "wildcard is only supported in the final path segment, got: {pattern}"
            ))
            .with_file(declared_by.to_path_buf())
            .with_suggestion("split the include into multiple patterns, one per directory"),
        )]);
    }
    if parts[wild_idx].matches('*').count() > 1 {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "only one `*` per path segment is supported, got: {pattern}"
            ))
            .with_file(declared_by.to_path_buf()),
        )]);
    }
    if parts[wild_idx].contains('?') || parts[wild_idx].contains('[') {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "`?` and `[` glob metacharacters are not supported, got: {pattern}"
            ))
            .with_file(declared_by.to_path_buf()),
        )]);
    }

    let dir = if wild_idx == 0 {
        base_dir.to_path_buf()
    } else {
        base_dir.join(parts[..wild_idx].join(std::path::MAIN_SEPARATOR_STR))
    };
    let wildcard = parts[wild_idx];
    let star = wildcard.find('*').unwrap();
    let prefix = &wildcard[..star];
    let suffix = &wildcard[star + 1..];

    let mut out = Vec::new();
    if dir.is_dir() {
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            vec![ConfigError::Parse(
                ErrorContext::new(format!("cannot read {}: {e}", dir.display()))
                    .with_file(declared_by.to_path_buf()),
            )]
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                vec![ConfigError::Parse(
                    ErrorContext::new(format!("cannot read directory entry: {e}"))
                        .with_file(declared_by.to_path_buf()),
                )]
            })?;
            let ft = entry.file_type().map_err(|e| {
                vec![ConfigError::Parse(
                    ErrorContext::new(format!("cannot stat entry: {e}"))
                        .with_file(declared_by.to_path_buf()),
                )]
            })?;
            if !(ft.is_file() || ft.is_symlink()) {
                continue;
            }
            // loader-10: skip a glob self-match — the declaring file caught by
            // its own `*.toml` — so it doesn't recurse into a spurious
            // "include cycle detected" error (logrotate/systemd self-skip
            // semantics). Compare canonically since `entry.path()` and
            // `declared_by` can differ in form.
            if let (Ok(a), Ok(b)) = (entry.path().canonicalize(), declared_by.canonicalize()) {
                if a == b {
                    continue;
                }
            }
            let name = entry.file_name();
            let name_s = match name.to_str() {
                Some(s) => s,
                None => continue, // non-UTF-8 filename, skip
            };
            // loader-11: a bare `*` has an empty prefix, so `*.toml` would
            // match `.disabled.toml` — defeating the rename-to-dotfile disable
            // convention (and could transiently catch staged temps). Skip
            // dotfiles unless the pattern's prefix explicitly opts in with a
            // leading dot.
            if name_s.starts_with('.') && !prefix.starts_with('.') {
                continue;
            }
            if name_s.starts_with(prefix)
                && name_s.ends_with(suffix)
                && name_s.len() >= prefix.len() + suffix.len()
            {
                out.push(entry.path());
            }
        }
    }
    // Empty match is allowed per design §7.2 ("Glob matching zero files
    // → allowed, supports fresh install with empty .d dir").
    Ok(out)
}

/// Read a file to a `String`, capping the read at `cap + 1` bytes so a
/// file that grew past the remaining aggregate size budget in the
/// stat->read TOCTOU window (loader-08, N11) can't be slurped unbounded.
/// Returns a `ValidationFailed` when the file exceeds `cap`; peak memory
/// stays bounded by `cap + 1`.
fn read_to_string_capped(path: &Path, cap: u64) -> Result<String, Vec<ConfigError>> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|io_err| {
        vec![ConfigError::Parse(
            ErrorContext::new(format!("cannot read config: {io_err}"))
                .with_file(path.to_path_buf()),
        )]
    })?;
    let mut buf = String::new();
    let read = file
        .take(cap.saturating_add(1))
        .read_to_string(&mut buf)
        .map_err(|io_err| {
            vec![ConfigError::Parse(
                ErrorContext::new(format!("cannot read config: {io_err}"))
                    .with_file(path.to_path_buf()),
            )]
        })?;
    if read as u64 > cap {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "config file grew past the remaining {cap}-byte aggregate budget while loading (N11 TOCTOU guard)"
            ))
            .with_file(path.to_path_buf()),
        )]);
    }
    Ok(buf)
}

// ── path security ───────────────────────────────────────────────────

/// Canonicalise a path with the "parent + leaf" trick so files that
/// don't yet exist still produce a deterministic canonical form (N12).
/// Returns a Parse error if neither the path nor its parent exist.
pub(crate) fn canonicalize_path(p: &Path) -> Result<PathBuf, ConfigError> {
    if p.exists() {
        p.canonicalize().map_err(|e| {
            ConfigError::Parse(
                ErrorContext::new(format!("cannot canonicalise {}: {e}", p.display()))
                    .with_file(p.to_path_buf()),
            )
        })
    } else {
        let parent = p.parent().ok_or_else(|| {
            ConfigError::Parse(
                ErrorContext::new(format!("path has no parent: {}", p.display()))
                    .with_file(p.to_path_buf()),
            )
        })?;
        let leaf = p.file_name().ok_or_else(|| {
            ConfigError::Parse(
                ErrorContext::new(format!("path has no file name: {}", p.display()))
                    .with_file(p.to_path_buf()),
            )
        })?;
        let parent_c = parent.canonicalize().map_err(|e| {
            ConfigError::Parse(
                ErrorContext::new(format!(
                    "cannot canonicalise parent {}: {e}",
                    parent.display(),
                ))
                .with_file(p.to_path_buf()),
            )
        })?;
        Ok(parent_c.join(leaf))
    }
}

fn ensure_inside_root(
    candidate: &Path,
    root: &Path,
    declared_by: &Path,
) -> Result<(), Vec<ConfigError>> {
    if candidate.starts_with(root) {
        Ok(())
    } else {
        Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "include target {} escapes config root {}",
                candidate.display(),
                root.display(),
            ))
            .with_file(declared_by.to_path_buf())
            .with_suggestion("move the target inside the config directory or remove the include"),
        )])
    }
}

// ── merge logic ─────────────────────────────────────────────────────

fn merge_into(
    merged: &mut toml::Table,
    child: toml::Table,
    child_source: &Path,
    provenance: &ProvenanceMap,
) -> Result<(), Vec<ConfigError>> {
    let mut errs = Vec::new();
    for (key, value) in child {
        if is_array_of_tables_key(&key) {
            merge_array_of_tables(merged, &key, value, child_source, &mut errs);
        } else if is_named_map_key(&key) {
            merge_named_map(merged, &key, value, child_source, provenance, &mut errs);
        } else {
            merge_singleton(merged, &key, value, child_source, provenance, &mut errs);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn merge_array_of_tables(
    merged: &mut toml::Table,
    key: &str,
    value: toml::Value,
    child_source: &Path,
    errs: &mut Vec<ConfigError>,
) {
    let incoming = match value {
        toml::Value::Array(a) => a,
        other => {
            errs.push(ConfigError::Parse(
                ErrorContext::new(format!(
                    "expected `[[{key}]]` array-of-tables, got {}",
                    other.type_str(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(key.to_string()),
            ));
            return;
        }
    };
    match merged.get_mut(key) {
        None => {
            merged.insert(key.to_string(), toml::Value::Array(incoming));
        }
        Some(toml::Value::Array(existing)) => existing.extend(incoming),
        Some(other) => {
            errs.push(ConfigError::Parse(
                ErrorContext::new(format!(
                    "merge conflict: `{key}` is {} in merged output but array-of-tables in {}",
                    other.type_str(),
                    child_source.display(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(key.to_string()),
            ));
        }
    }
}

fn merge_named_map(
    merged: &mut toml::Table,
    key: &str,
    value: toml::Value,
    child_source: &Path,
    provenance: &ProvenanceMap,
    errs: &mut Vec<ConfigError>,
) {
    let incoming = match value {
        toml::Value::Table(t) => t,
        other => {
            errs.push(ConfigError::Parse(
                ErrorContext::new(format!(
                    "expected `[{key}.<id>]` named-map, got {}",
                    other.type_str(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(key.to_string()),
            ));
            return;
        }
    };
    let target = merged
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let target_table = match target {
        toml::Value::Table(t) => t,
        _ => unreachable!("named-map entry re-typed: impossible after or_insert_with"),
    };
    for (sub_key, sub_value) in incoming {
        if target_table.contains_key(&sub_key) {
            let full_path = format!("{key}.{sub_key}");
            let existing_loc = provenance
                .get(&full_path)
                .map(|(p, l)| format!("{}:{l}", p.display()))
                .unwrap_or_else(|| "earlier file".to_string());
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "duplicate `[{full_path}]` table: defined in {existing_loc} and {}",
                    child_source.display(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(full_path)
                .with_suggestion("remove one of the two definitions, or change the id"),
            ));
        } else {
            target_table.insert(sub_key, sub_value);
        }
    }
}

fn merge_singleton(
    merged: &mut toml::Table,
    key: &str,
    value: toml::Value,
    child_source: &Path,
    provenance: &ProvenanceMap,
    errs: &mut Vec<ConfigError>,
) {
    // §4.11-3: a small allowlist of singletons (currently only `[server]`)
    // may be split across files and field-merged rather than rejected as a
    // whole-section duplicate. See [`SPLIT_MERGE_SINGLETONS`]. Cluster-only —
    // the default build keeps the original singleton-duplicate semantics.
    #[cfg(feature = "cluster")]
    if SPLIT_MERGE_SINGLETONS.contains(&key) {
        merge_split_singleton(merged, key, value, child_source, provenance, errs);
        return;
    }
    if merged.contains_key(key) {
        let existing_loc = provenance
            .get(key)
            .map(|(p, l)| format!("{}:{l}", p.display()))
            .unwrap_or_else(|| "earlier file".to_string());
        errs.push(ConfigError::DuplicateId(
            ErrorContext::new(format!(
                "duplicate singleton `[{key}]`: defined in {existing_loc} and {}",
                child_source.display(),
            ))
            .with_file(child_source.to_path_buf())
            .with_entity(key.to_string())
            .with_suggestion("keep the section in exactly one file"),
        ));
    } else {
        merged.insert(key.to_string(), value);
    }
}

/// Field-merge a split-allowed singleton (currently only `[server]`,
/// §4.11-3). The incoming table's sub-keys are unioned into the
/// accumulated table; a duplicate *sub-key* across files is reported as a
/// `DuplicateId` (mirroring [`merge_named_map`]). The first occurrence
/// simply inserts. A non-table value on either side fails closed as a
/// singleton conflict — a malformed `[server]` is the deserialiser's job
/// to reject, but the merge stays well-typed here.
#[cfg(feature = "cluster")]
fn merge_split_singleton(
    merged: &mut toml::Table,
    key: &str,
    value: toml::Value,
    child_source: &Path,
    provenance: &ProvenanceMap,
    errs: &mut Vec<ConfigError>,
) {
    // First definition — nothing to merge against yet.
    if !merged.contains_key(key) {
        merged.insert(key.to_string(), value);
        return;
    }
    let incoming = match value {
        toml::Value::Table(t) => t,
        other => {
            errs.push(ConfigError::Parse(
                ErrorContext::new(format!(
                    "expected `[{key}]` table to field-merge, got {}",
                    other.type_str(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(key.to_string()),
            ));
            return;
        }
    };
    let Some(toml::Value::Table(target)) = merged.get_mut(key) else {
        // Existing value is not a table — cannot field-merge; fail closed.
        errs.push(ConfigError::DuplicateId(
            ErrorContext::new(format!(
                "cannot field-merge `[{key}]` from {}: the existing value is not a table",
                child_source.display(),
            ))
            .with_file(child_source.to_path_buf())
            .with_entity(key.to_string()),
        ));
        return;
    };
    for (sub_key, sub_value) in incoming {
        if target.contains_key(&sub_key) {
            let full_path = format!("{key}.{sub_key}");
            let existing_loc = provenance
                .get(&full_path)
                .or_else(|| provenance.get(key))
                .map(|(p, l)| format!("{}:{l}", p.display()))
                .unwrap_or_else(|| "earlier file".to_string());
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "duplicate `[{key}].{sub_key}`: defined in {existing_loc} and {}",
                    child_source.display(),
                ))
                .with_file(child_source.to_path_buf())
                .with_entity(full_path)
                .with_suggestion("define each `server` field in exactly one file"),
            ));
        } else {
            target.insert(sub_key, sub_value);
        }
    }
}

fn is_array_of_tables_key(key: &str) -> bool {
    ARRAY_OF_TABLES_KEYS.contains(&key)
}

fn is_named_map_key(key: &str) -> bool {
    NAMED_MAP_KEYS.contains(&key)
}

// ── unknown-key + provenance helpers ────────────────────────────────

/// Build the same-file legacy+canonical conflict error (loader-02). When
/// a single file declares BOTH a deprecated key and its canonical
/// replacement, the legacy value would otherwise be silently dropped — a
/// config could lose a security control (`[ip_denylists]` is a
/// DoH-bypass blocklist) during exactly the half-migrated state the alias
/// exists to support. Refuse loudly, matching the cross-file
/// duplicate-singleton behaviour the merger already applies.
fn deprecated_key_conflict(file: &Path, line: usize, legacy: &str, canonical: &str) -> ConfigError {
    ConfigError::ValidationFailed(
        ErrorContext::new(format!(
            "file declares both `{legacy}` (deprecated) and `{canonical}`; \
             the `{legacy}` value would be silently dropped"
        ))
        .with_file(file.to_path_buf())
        .with_line(line)
        .with_entity(canonical)
        .with_suggestion(format!(
            "remove the deprecated `{legacy}` and keep only `{canonical}`"
        )),
    )
}

/// Emit a `tracing::warn!` and rewrite deprecated key names (both
/// top-level sections and nested fields) to their canonical form in
/// place. Silent when only the canonical name is used. If a single file
/// declares BOTH the legacy and canonical spelling the load is REFUSED
/// with a `ValidationFailed` (loader-02): silently keeping the canonical
/// and dropping the legacy could discard a security control, and the
/// cross-file case already hard-errors as a duplicate singleton, so the
/// same-file case must be just as loud.
///
/// DEPRECATED — remove at schema_version = 3 (design doc §3 R1).
/// Emit one key-deprecation notice on **both** channels.
///
/// `config-lint-blind-to-loader-deprecations`: these notices used to exist
/// only as `tracing::warn!`, a different channel from the validator's
/// `AuditWarnings`. The daemon has a global subscriber so they reached
/// journald at boot; `warden config lint` installs none and takes its
/// warnings from `load_config_collect`'s return value, so it reported 1
/// warning where boot emitted 5 — and the four it missed were exactly the
/// "this key disappears at schema_version = 3" notices, all four in use on
/// real installs. A deploy gated on `warden config lint` therefore never told
/// the operator that keys they depend on are going away.
///
/// The fix is to feed the existing notices into the channel lint already
/// reads, **not** to restate them in the validator: two copies of the same
/// rule is how the two drift apart.
///
/// The single `msg` is used for both channels so their text cannot diverge.
/// The collected copy is prefixed `file:line` because lint prints a bare
/// string list, while the `tracing` copy keeps `file` / `line` as structured
/// fields where journald can query them — same information, each in the form
/// its consumer can use.
fn note_deprecation(deprecations: &mut Vec<String>, file: &Path, line: usize, msg: &str) {
    tracing::warn!(file = %file.display(), line, "{msg}");
    deprecations.push(format!("{}:{}: {}", file.display(), line, msg));
}

/// What a `[[blocklists]]` row carrying the pre-v3 `kind` key is told.
///
/// **Why this is an ERROR and not a silent alias.** `kind` was renamed to
/// `base` in plp-s3b, and adding `#[serde(alias = "kind")]` would have made
/// every v2 config load unchanged — which is precisely the danger. A v2
/// config has no `profiles.<id>.lists` overrides, so under v3 every list is
/// inherited by every profile: the tag intersection that used to scope a
/// list to some profiles is simply gone, and lists start applying where they
/// did not. Silently. On a DNS filter that direction is invisible until
/// somebody notices a site is blocked, or worse, is not.
///
/// **Why it is here and not in the validator.** `Blocklist` carries
/// `#[serde(deny_unknown_fields)]` and `check_schema_version` only ever sees
/// an already-deserialised `ConfigV1`. So a v2 config dies during
/// deserialisation with serde's `unknown field \`kind\`, expected one of
/// ...` — fail-closed, but it names a field instead of naming the fix, and
/// the operator is standing in front of a daemon that will not start. This
/// pass runs on the raw table, before deserialisation, so the message the
/// operator actually gets is the one with the command in it.
///
/// `{id}` is the blocklist id (`?` when the row has no readable `id`).
pub const BLOCKLIST_KIND_RENAMED_TO_BASE: &str =
    "blocklist \"{id}\" carries `kind`, which was renamed to `base` in schema_version 3";

/// Substitute `{id}` into [`BLOCKLIST_KIND_RENAMED_TO_BASE`].
#[must_use]
pub fn format_blocklist_kind_renamed_to_base(id_hint: &str) -> String {
    BLOCKLIST_KIND_RENAMED_TO_BASE.replace("{id}", id_hint)
}

/// The next step printed under [`BLOCKLIST_KIND_RENAMED_TO_BASE`].
///
/// Names the whole conversion, not the one field: a config old enough to
/// say `kind` is also missing `profiles.<id>.lists`, and hand-editing the
/// key alone produces a file that loads and filters differently from the
/// one the daemon was running. `--target` equal to `--from-config` is the
/// in-place form; it is atomic, keeps a `.bak`, and preserves the file's
/// mode and owner (`config::atomic_write::hardened_atomic_write`).
pub const BLOCKLIST_KIND_RENAMED_TO_BASE_SUGGESTION: &str =
    "run `warden migrate v2-to-v3 --from-config <config.toml> --target <config.toml> --force` \
     — renaming the key by hand does NOT reproduce the tag model's scoping, so lists would \
     start applying to profiles they never reached";

fn normalise_deprecated_keys(
    table: &mut toml::Table,
    file: &Path,
    src: &str,
    deprecations: &mut Vec<String>,
) -> Result<(), Vec<ConfigError>> {
    let mut errs = Vec::new();

    // plp-s3b — `[[blocklists]].kind` → `base`, WITHOUT a rewrite. Every
    // other arm in this function normalises a legacy key into its
    // successor; this one refuses. See `BLOCKLIST_KIND_RENAMED_TO_BASE`
    // for why an alias here would be a silent verdict change rather than
    // a courtesy, and why the message has to come from the raw table.
    if let Some(blocklists_arr) = table.get("blocklists").and_then(|v| v.as_array()) {
        let anchor_line = line_of_top_anchor(src, "blocklists").unwrap_or(1);
        for entry in blocklists_arr {
            let Some(entry_table) = entry.as_table() else {
                continue;
            };
            if !entry_table.contains_key("kind") {
                continue;
            }
            let id_hint = entry_table
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            errs.push(ConfigError::UnknownField(
                ErrorContext::new(format_blocklist_kind_renamed_to_base(id_hint))
                    .with_file(file.to_path_buf())
                    .with_line(anchor_line)
                    .with_entity(format!("blocklists.{id_hint}"))
                    .with_suggestion(BLOCKLIST_KIND_RENAMED_TO_BASE_SUGGESTION.to_string()),
            ));
        }
    }

    // S42 T2 — top-level `[ip_denylists]` → `[ip_blocklists]`.
    if let Some(legacy) = table.remove("ip_denylists") {
        let line = line_of_top_anchor(src, "ip_denylists").unwrap_or(1);
        if table.contains_key("ip_blocklists") {
            errs.push(deprecated_key_conflict(
                file,
                line,
                "ip_denylists",
                "ip_blocklists",
            ));
        } else {
            note_deprecation(deprecations, file, line, "config key '[ip_denylists]' deprecated, use '[ip_blocklists]' (removal at schema_version = 3)");
            table.insert("ip_blocklists".to_string(), legacy);
        }
    }

    // S42 T5 — top-level `[[clients]]` → `[[devices]]`. Reuses the T2
    // verbatim template (array-of-tables section, single top-level key
    // swap).
    if let Some(legacy) = table.remove("clients") {
        let line = line_of_top_anchor(src, "clients").unwrap_or(1);
        if table.contains_key("devices") {
            errs.push(deprecated_key_conflict(file, line, "clients", "devices"));
        } else {
            note_deprecation(deprecations, file, line, "config key '[[clients]]' deprecated, use '[[devices]]' (removal at schema_version = 3)");
            table.insert("devices".to_string(), legacy);
        }
    }

    // Per-device rules are on their way out: policy will reach a device
    // only through a profile, so an exemption is visible in one place
    // instead of being reachable from two. Still honoured, only announced —
    // and read from the raw table, after the `clients` rename above, so a
    // config using either spelling is covered.
    //
    // Once per device, not once per rule: the notice is about the field,
    // and a device carrying twenty rules needs one sentence.
    if let Some(devices_arr) = table.get("devices").and_then(|v| v.as_array()) {
        let anchor_line = line_of_top_anchor(src, "devices").unwrap_or(1);
        for entry in devices_arr {
            let Some(entry_table) = entry.as_table() else {
                continue;
            };
            // Keyed on a NON-EMPTY array, not on the key's presence: a
            // device that has already been migrated still carries
            // `allow_rules = []`, and nagging it is how a notice stops
            // being read.
            let carries = |key: &str| {
                entry_table
                    .get(key)
                    .and_then(|v| v.as_array())
                    .is_some_and(|rules| !rules.is_empty())
            };
            if !carries("allow_rules") && !carries("deny_rules") {
                continue;
            }
            let id_hint = entry_table
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let msg = format!(
                "device '{id_hint}': 'allow_rules'/'deny_rules' are deprecated and will be \
                 removed — put the domains in a custom list and mount it on the device's profile"
            );
            note_deprecation(deprecations, file, anchor_line, &msg);
        }
    }

    // S42 T4 — nested `[lists].refresh_interval_secs` →
    // `update_interval_secs`. `line_of_top_anchor` resolves the `[lists]`
    // block heading, so the WARN points at the section header — close
    // enough for operators to locate the field in their own file.
    if let Some(lists_table) = table.get_mut("lists").and_then(|v| v.as_table_mut()) {
        if let Some(legacy) = lists_table.remove("refresh_interval_secs") {
            let line = line_of_top_anchor(src, "lists").unwrap_or(1);
            if lists_table.contains_key("update_interval_secs") {
                errs.push(deprecated_key_conflict(
                    file,
                    line,
                    "lists.refresh_interval_secs",
                    "lists.update_interval_secs",
                ));
            } else {
                note_deprecation(deprecations, file, line, "config key 'lists.refresh_interval_secs' deprecated, use 'lists.update_interval_secs' (removal at schema_version = 3)");
                lists_table.insert("update_interval_secs".to_string(), legacy);
            }
        }
    }

    // S42 T5 — nested `[tracking].max_clients` → `max_devices`.
    if let Some(tracking_table) = table.get_mut("tracking").and_then(|v| v.as_table_mut()) {
        if let Some(legacy) = tracking_table.remove("max_clients") {
            let line = line_of_top_anchor(src, "tracking").unwrap_or(1);
            if tracking_table.contains_key("max_devices") {
                errs.push(deprecated_key_conflict(
                    file,
                    line,
                    "tracking.max_clients",
                    "tracking.max_devices",
                ));
            } else {
                note_deprecation(deprecations, file, line, "config key 'tracking.max_clients' deprecated, use 'tracking.max_devices' (removal at schema_version = 3)");
                tracking_table.insert("max_devices".to_string(), legacy);
            }
        }
    }

    // S42 T5 — nested `[server].enforce_client_mac` → `enforce_device_mac`.
    if let Some(server_table) = table.get_mut("server").and_then(|v| v.as_table_mut()) {
        if let Some(legacy) = server_table.remove("enforce_client_mac") {
            let line = line_of_top_anchor(src, "server").unwrap_or(1);
            if server_table.contains_key("enforce_device_mac") {
                errs.push(deprecated_key_conflict(
                    file,
                    line,
                    "server.enforce_client_mac",
                    "server.enforce_device_mac",
                ));
            } else {
                note_deprecation(deprecations, file, line, "config key 'server.enforce_client_mac' deprecated, use 'server.enforce_device_mac' (removal at schema_version = 3)");
                server_table.insert("enforce_device_mac".to_string(), legacy);
            }
        }
    }

    // S42 T4 — per-entry `[[blocklists]].refresh_interval_hours` →
    // `update_interval_hours`. Iterate the array so every entry that
    // carries the legacy key is normalised; each match emits its own
    // WARN so operators see which list triggered the deprecation.
    if let Some(blocklists_arr) = table.get_mut("blocklists").and_then(|v| v.as_array_mut()) {
        let anchor_line = line_of_top_anchor(src, "blocklists").unwrap_or(1);
        for entry in blocklists_arr.iter_mut() {
            let Some(entry_table) = entry.as_table_mut() else {
                continue;
            };
            if let Some(legacy) = entry_table.remove("refresh_interval_hours") {
                let id_hint = entry_table
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                if entry_table.contains_key("update_interval_hours") {
                    errs.push(deprecated_key_conflict(
                        file,
                        anchor_line,
                        "blocklists[].refresh_interval_hours",
                        "blocklists[].update_interval_hours",
                    ));
                } else {
                    let msg = format!(
                        "blocklist '{id_hint}' field 'refresh_interval_hours' deprecated, use 'update_interval_hours' (removal at schema_version = 3)"
                    );
                    note_deprecation(deprecations, file, anchor_line, &msg);
                    entry_table.insert("update_interval_hours".to_string(), legacy);
                }
            }
        }
    }

    // plp-s5a F1 — `tags` is gone from all five entity structs, and every
    // one of them is `#[serde(deny_unknown_fields)]`. Strip the retired key
    // before serde sees it, and tell the operator which entities carried
    // it.
    //
    // This is the `ip_denylists` shape above (remove + note), NOT the
    // `kind` shape (refuse). The `kind` refusal is right because renaming
    // that key by hand changes a filtering verdict; `tags` decided nothing
    // after the plp-s3 cutover, so removing it changes none — and a
    // refusal here is precisely the outage the strip exists to prevent.
    //
    // **Belt-and-braces, and the second half is not optional.** The
    // single-file fast path re-parses the raw bytes and never sees this
    // table, so `schema::load::parse_v1` strips too, through the same
    // function. The *note* below needs no counterpart: this runs before
    // both loader exits and its drain sits above the fast-path branch.
    for entity in crate::config::schema::retired_keys::strip_retired_tag_keys(table) {
        // `[profiles.<id>]` has no `[profiles]` heading to anchor on, so
        // `line_of_top_anchor("profiles")` falls through to line 1 and the
        // notice points at the top of the file. Try the qualified heading
        // first and keep the section anchor as the fallback for the
        // array-of-tables sections, which do have one.
        let line = line_of_top_anchor(src, &entity)
            .or_else(|| line_of_top_anchor(src, entity.split('.').next().unwrap_or("blocklists")))
            .unwrap_or(1);
        let msg = format!(
            "'{entity}' carries the retired key 'tags' — removed at load, not applied. \
             Tags no longer decide which lists apply; set the direction with \
             `profiles.<id>.lists = {{ <list-id> = \"deny\" | \"allow\" | \"ignore\" }}`. \
             Delete the key from the file to silence this."
        );
        note_deprecation(deprecations, file, line, &msg);
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn reject_unknown_top_level(
    table: &toml::Table,
    file: &Path,
    src: &str,
) -> Result<(), Vec<ConfigError>> {
    let mut errs = Vec::new();
    for key in table.keys() {
        if !KNOWN_TOP_LEVEL.contains(&key.as_str()) {
            let line = line_of_top_anchor(src, key).unwrap_or(1);
            let ctx = ErrorContext::new(format!("unknown top-level key `{key}`"))
                .with_file(file.to_path_buf())
                .with_line(line)
                .with_entity(key.clone());
            // loader-01: a config migrating off v1 most often still carries
            // `[[categories]]` — give it a directed next step instead of the
            // generic allowed-keys dump.
            //
            // **The manual route was removed in `plp-s5f`, and it was the
            // harmful half.** This used to end "or move each category's
            // members onto the relevant entity's `tags`". `tags` replaced
            // `categories` in schema_version 2 and was itself retired at the
            // plp cutover; `plp-s5a` deleted the field and the loader now
            // strips it. So the advice, followed exactly, produced a config
            // whose tags are dropped at load with the operator's intent
            // silently discarded — defect E2, the failure this whole
            // workstream exists to repair, recommended by warden's own error
            // message to the one population that would act on it.
            //
            // Only the migrate route survives, and it is the one that works:
            // `v1-to-v3` writes `profiles.<id>.lists`, which is what decides
            // filtering now.
            let ctx = if key == "categories" {
                ctx.with_suggestion(
                    "`categories` was removed in schema_version 2, and the per-entity `tags` \
                     that replaced it have themselves been retired — the loader strips them. \
                     Run `warden migrate v1-to-v3` to convert a v1 config: it writes \
                     `profiles.<id>.lists`, which is what decides filtering now",
                )
            } else {
                ctx.with_suggestion(format!("allowed keys: {}", KNOWN_TOP_LEVEL.join(", ")))
            };
            errs.push(ConfigError::UnknownField(ctx));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// The provenance of ONE file, parsed but neither merged nor validated.
///
/// `cluster join` needs `file:line` for the sections in the master it is
/// about to rewrite, and it must get them **without loading**: a policy-free
/// secondary master does not validate until it has joined, and the file it
/// would name on the staged-write path is the staging temp file — a path that
/// no longer exists by the time the operator reads the message.
///
/// Errors only on a TOML parse failure, which every caller already surfaces
/// with a better message of its own.
pub fn provenance_of_file(path: &Path, src: &str) -> Result<ProvenanceMap, toml::de::Error> {
    let table: toml::Table = src.parse()?;
    let mut provenance = ProvenanceMap::new();
    record_provenance(&table, path, src, &mut provenance);
    Ok(provenance)
}

/// Walk a parsed file + source string, recording each top-level key
/// and each sub-entity (array-of-tables `id` / named-map sub-key) in
/// the provenance sidecar. First-writer-wins — a later file merging
/// into an existing key does not overwrite the provenance of the
/// original definition.
fn record_provenance(table: &toml::Table, file: &Path, src: &str, provenance: &mut ProvenanceMap) {
    let array_headings = collect_array_headings(src);
    let table_headings = collect_table_headings(src);

    for (key, value) in table {
        match value {
            toml::Value::Array(items) if items.iter().all(|v| v.is_table()) => {
                let lines = array_headings.get(key).cloned().unwrap_or_default();
                for (idx, item) in items.iter().enumerate() {
                    let entity_id = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let line = lines.get(idx).copied().unwrap_or(1);
                    if let Some(id) = entity_id {
                        let path_key = format!("{key}.{id}");
                        provenance
                            .entry(path_key)
                            .or_insert((file.to_path_buf(), line));
                    }
                }
                if let Some(&first_line) = lines.first() {
                    provenance
                        .entry(key.clone())
                        .or_insert((file.to_path_buf(), first_line));
                }
            }
            toml::Value::Table(inner) if is_named_map_key(key) => {
                for sub_key in inner.keys() {
                    let heading = format!("{key}.{sub_key}");
                    let line = table_headings
                        .get(&heading)
                        .copied()
                        .unwrap_or_else(|| table_headings.get(key).copied().unwrap_or(1));
                    provenance
                        .entry(heading)
                        .or_insert((file.to_path_buf(), line));
                }
                if let Some(&line) = table_headings.get(key) {
                    provenance
                        .entry(key.clone())
                        .or_insert((file.to_path_buf(), line));
                }
            }
            toml::Value::Table(inner) => {
                let line = table_headings.get(key).copied().unwrap_or(1);
                // loader-05: also record per-sub-key provenance so a
                // split-merge duplicate-sub-key error (a `server.*` field
                // defined across two files on a cluster secondary) is
                // attributed to the file that contributed the field, not
                // whichever file first declared the `[section]`. The line is
                // the section heading — field lines aren't headings — but the
                // FILE attribution is the point of the fix.
                for sub_key in inner.keys() {
                    provenance
                        .entry(format!("{key}.{sub_key}"))
                        .or_insert((file.to_path_buf(), line));
                }
                provenance
                    .entry(key.clone())
                    .or_insert((file.to_path_buf(), line));
            }
            _ => {
                let line = line_of_top_anchor(src, key).unwrap_or(1);
                provenance
                    .entry(key.clone())
                    .or_insert((file.to_path_buf(), line));
            }
        }
    }
}

/// `[[array]]` headings → their 1-based line numbers, in source order.
fn collect_array_headings(src: &str) -> BTreeMap<String, Vec<usize>> {
    let mut map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("[[") {
            if let Some(end) = rest.find("]]") {
                let name = rest[..end].trim();
                // Only track top-level keys (no dot). Nested headings
                // (theoretical) are ignored — entity id attribution is
                // what matters here.
                if !name.is_empty() && !name.contains('.') {
                    map.entry(name.to_string()).or_default().push(i + 1);
                }
            }
        }
    }
    map
}

/// `[table]` and `[table.sub]` headings → their 1-based line numbers.
fn collect_table_headings(src: &str) -> BTreeMap<String, usize> {
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[[") {
            continue; // array-of-tables handled elsewhere
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let name = rest[..end].trim();
                if !name.is_empty() {
                    map.entry(name.to_string()).or_insert(i + 1);
                }
            }
        }
    }
    map
}

/// Resolve the 1-based source line of a top-level `key` whether it
/// appears as a `[key]` table heading, a `[[key]]` array-of-tables
/// heading, or a `key = ...` scalar / inline line. `line_of_top_key`
/// alone matched only the scalar form, so every `[section]`-anchored
/// diagnostic (deprecation WARNs, unknown-key errors) reported line 1
/// (loader-03).
fn line_of_top_anchor(src: &str, key: &str) -> Option<usize> {
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        // `[[key]]` array-of-tables heading.
        if let Some((name, _)) = t.strip_prefix("[[").and_then(|r| r.split_once("]]")) {
            if name.trim() == key {
                return Some(i + 1);
            }
            continue;
        }
        // `[key]` table heading.
        if let Some((name, _)) = t.strip_prefix('[').and_then(|r| r.split_once(']')) {
            if name.trim() == key {
                return Some(i + 1);
            }
        }
    }
    // Fall back to the scalar `key = ...` form.
    line_of_top_key(src, key)
}

/// Locate `key = ...` on a top-level line. Returns the 1-based line
/// number of the first match. Scalar-only — heading-aware callers use
/// [`line_of_top_anchor`].
fn line_of_top_key(src: &str, key: &str) -> Option<usize> {
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key) {
            if rest
                .chars()
                .next()
                .map(|c| c == '=' || c.is_whitespace())
                .unwrap_or(false)
            {
                return Some(i + 1);
            }
        }
    }
    None
}

fn line_of(src: &str, offset: usize) -> usize {
    let clamped = offset.min(src.len());
    src[..clamped].bytes().filter(|b| *b == b'\n').count() + 1
}

fn include_chain(stack: &[PathBuf], next: &Path) -> String {
    let mut chain: Vec<String> = stack.iter().map(|p| p.display().to_string()).collect();
    chain.push(next.display().to_string());
    chain.join(" → ")
}

// ── error enrichment ────────────────────────────────────────────────

fn enrich_with_provenance(mut err: ConfigError, provenance: &ProvenanceMap) -> ConfigError {
    let ctx = match &mut err {
        ConfigError::Parse(c)
        | ConfigError::MissingRequired(c)
        | ConfigError::UnknownField(c)
        | ConfigError::UnknownVariant(c)
        | ConfigError::DuplicateId(c)
        | ConfigError::CrossRefMiss(c)
        | ConfigError::VersionMismatch(c)
        | ConfigError::InvalidId(c)
        | ConfigError::IdRecentlyRetired(c)
        | ConfigError::UnsignedAllowListRequiresAck(c)
        | ConfigError::TrustSignedNotYetSupported(c)
        | ConfigError::InvalidTagSlug(c)
        | ConfigError::ValidationFailed(c) => c,
    };
    if ctx.file.is_some() {
        return err;
    }
    if let Some(entity) = ctx.entity.clone() {
        if let Some((p, l)) = provenance.get(&entity) {
            ctx.file = Some(p.clone());
            ctx.line = Some(*l);
        } else if let Some((p, l)) = lookup_entity_prefix(&entity, provenance) {
            ctx.file = Some(p.clone());
            ctx.line = Some(*l);
        }
    }
    err
}

/// Walk the provenance map for the longest prefix of `entity` that
/// matches a stored key. Handles validator errors that tag fine-grained
/// paths (e.g. `devices.iphone.profile`) when the provenance only
/// records the entity itself (`devices.iphone`).
fn lookup_entity_prefix<'a>(
    entity: &str,
    provenance: &'a ProvenanceMap,
) -> Option<&'a (PathBuf, usize)> {
    let mut probe = entity.to_string();
    while !probe.is_empty() {
        if let Some(v) = provenance.get(&probe) {
            return Some(v);
        }
        match probe.rfind('.') {
            Some(idx) => probe.truncate(idx),
            None => break,
        }
    }
    None
}

fn classify_merged_error(err: toml::de::Error, _provenance: &ProvenanceMap) -> ConfigError {
    let msg = err.to_string();
    // loader-12: shared, drift-proof, user-content-masked classifier.
    // error-01: bound the stored reason (toml can excerpt a multi-MB line);
    // classification still matches on the full `msg`.
    super::error::classify_config_error(
        &msg,
        ErrorContext::new(super::error::truncate_for_error(&msg).into_owned()),
    )
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
