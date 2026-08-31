//! §4.7 Phase 2 T1 integration: `warden list forget` end-to-end via
//! the in-process [`ListManagerCommand`] channel.
//!
//! Verifies that the wire-up that the IPC handler depends on —
//! `set_command_channel` → `spawn_refresh_loop` drains commands →
//! `forget_source` mutates in-memory + unlinks files — works as a
//! cohesive unit. The actual Unix-socket round-trip is exercised by
//! the CT smoke step on `the lab host`; this test isolates the
//! manager-side half so a regression in the channel plumbing surfaces
//! in `cargo test` rather than only on hardware.

use std::sync::Arc;
use std::time::Duration;

use purge_warden::filter::FilterEngine;
use purge_warden::lists::catalog::Catalog;
use purge_warden::lists::manager::{ListManager, ListManagerCommand};
use purge_warden::lists::source_key::SourceBitMap;

#[tokio::test]
async fn forget_via_command_channel_unlinks_disk_files_and_drops_memory() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().to_path_buf();

    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();

    let mut mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        200 * 1024 * 1024,
        5_000_000,
        Some(cache_dir.clone()),
    );

    // Seed fixture .cache + .meta on disk so forget has something to
    // unlink. Use the same stem the production writer would compute.
    let stem = purge_warden::lists::manager::source_to_cache_stem("privacy/ads");
    let cache_path = cache_dir.join(format!("{stem}.cache"));
    let meta_path = cache_dir.join(format!("{stem}.meta"));
    std::fs::write(&cache_path, b"example.com\nads.example.org\n").unwrap();
    std::fs::write(
        &meta_path,
        b"etag=\"abc\"\nlast-modified=\nfetched-at=\nsize=27\n",
    )
    .unwrap();
    assert!(cache_path.exists() && meta_path.exists());

    // Wire the command channel, spawn the refresh loop, send Forget,
    // and await the oneshot ack. Loop never ticks the refresh because
    // the 3600s interval is far longer than the test runtime.
    let (tx, rx) = tokio::sync::mpsc::channel::<ListManagerCommand>(4);
    mgr.set_command_channel(rx);
    let _join = mgr.spawn_refresh_loop();

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    tx.send(ListManagerCommand::Forget {
        source: "privacy/ads".to_string(),
        ack: ack_tx,
    })
    .await
    .expect("channel send");

    let was_cached = tokio::time::timeout(Duration::from_secs(2), ack_rx)
        .await
        .expect("forget ack timed out")
        .expect("ack channel closed before reply");
    assert!(
        was_cached,
        "fixture seeded disk files; forget must report was_cached = true"
    );
    assert!(
        !cache_path.exists(),
        "<stem>.cache must be unlinked after forget"
    );
    assert!(
        !meta_path.exists(),
        "<stem>.meta must be unlinked after forget"
    );

    // Idempotency: a second forget on the now-empty source returns
    // false but never errors out.
    let (ack_tx2, ack_rx2) = tokio::sync::oneshot::channel();
    tx.send(ListManagerCommand::Forget {
        source: "privacy/ads".to_string(),
        ack: ack_tx2,
    })
    .await
    .expect("channel send");
    let was_cached2 = tokio::time::timeout(Duration::from_secs(2), ack_rx2)
        .await
        .expect("second forget ack timed out")
        .expect("second ack channel closed");
    assert!(
        !was_cached2,
        "second forget on already-cleared source must report was_cached = false"
    );
}
