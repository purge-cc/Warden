use super::*;
use crate::common::domain::is_valid_domain;
use crate::config::settings::ListsConfig;
use crate::filter::engine::{ListPolicy, DOMAIN_SHARDS};
use crate::filter::FilterEngine;
use crate::lists::parser::{
    DEFAULT_MAX_LIST_ENTRIES, DETECT_PREFIX_MAX_BYTES, DETECT_PREFIX_MAX_LINES,
    STREAMING_LINE_MAX_BYTES,
};
use std::io::Cursor;
use std::time::Duration;

const TWO_GIB: u128 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unsupported {
    Overflow,
}

fn as_u128(value: usize) -> Result<u128, Unsupported> {
    u128::try_from(value).map_err(|_| Unsupported::Overflow)
}

fn checked_add(left: u128, right: u128) -> Result<u128, Unsupported> {
    left.checked_add(right).ok_or(Unsupported::Overflow)
}

fn checked_mul(left: u128, right: u128) -> Result<u128, Unsupported> {
    left.checked_mul(right).ok_or(Unsupported::Overflow)
}

fn installed_entry_size() -> usize {
    let domain = "a.b";
    let mut spill = ShardSpill::open(None).expect("memory spill opens for a shape probe");
    spill
        .push(domain, 1)
        .expect("shape probe spills its domain");

    let idx = FilterEngine::shard_index(domain);
    let built = spill
        .build_shard(idx, 1, &ListPolicy::publish_uniform(0))
        .expect("shape probe builds its shard");
    let engine = FilterEngine::new();
    engine.swap_shard_sorted(idx, built.shard);

    let shape = engine.memory_shapes_for_test()[idx];
    assert_eq!(shape.entry_count, 1);
    assert_eq!(shape.heap_capacity, 0, "a.b must stay inline");
    assert!(shape.policy_generation > 0);
    shape.entry_size
}

fn legal_max_length_domain(ordinal: u128) -> String {
    // A fixed-width suffix gives at least 2^32 distinct legal names without
    // materialising the 24 million-name corpus used by the model.
    let suffix = format!("{ordinal:08x}");
    assert_eq!(suffix.len(), 8);
    let final_label = format!("{}{}", "d".repeat(53), suffix);
    let domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        final_label,
    );
    assert_eq!(domain.len(), 253);
    assert!(
        is_valid_domain(&domain),
        "253-byte domain must remain legal"
    );
    domain
}

fn representation_lower_bound(
    domains: u128,
    entry_size: u128,
    payload_size: u128,
) -> Result<u128, Unsupported> {
    checked_mul(domains, checked_add(entry_size, payload_size)?)
}

/// Model the current `Vec<(CompactString, u64)>` growth from an observed
/// initial reservation. The small disk-spill test below binds this recurrence
/// to the actual builder without allocating the default-scale raw vector.
fn raw_vec_capacity_for_rows(
    initial_capacity: u128,
    rows: u128,
) -> Result<(u128, Option<u128>), Unsupported> {
    if rows <= initial_capacity {
        return Ok((initial_capacity, None));
    }

    let mut capacity = initial_capacity;
    let mut previous_capacity = None;
    while capacity < rows {
        previous_capacity = Some(capacity);
        capacity = if capacity < 4 {
            4
        } else {
            checked_mul(capacity, 2)?
        };
    }
    Ok((capacity, previous_capacity))
}

fn supported_by_two_gib(
    domains: u128,
    entry_size: u128,
    payload_size: u128,
) -> Result<bool, Unsupported> {
    Ok(representation_lower_bound(domains, entry_size, payload_size)? < TWO_GIB)
}

#[test]
fn s7_memory_policy_inputs_are_pinned() {
    let lists = ListsConfig::default();
    assert_eq!(lists.max_body_bytes, 536_870_912);
    assert_eq!(lists.max_entries, 20_000_000);
    assert_eq!(lists.max_total_domains, 24_000_000);
    assert_eq!(DEFAULT_MAX_LIST_ENTRIES, lists.max_entries);
    assert_eq!(STREAMING_LINE_MAX_BYTES, 65_536);
    assert_eq!(DETECT_PREFIX_MAX_BYTES, 65_536);
    assert_eq!(DETECT_PREFIX_MAX_LINES, 256);
    assert_eq!(MAX_LIST_SOURCES, 64);
    assert_eq!(DOMAIN_SHARDS, 16);
    assert_eq!(SPILL_WRITE_BUF, 65_536);
    assert_eq!(installed_entry_size(), 32);
}

#[test]
fn s7_long_name_defaults_exceed_two_gib() {
    let lists = ListsConfig::default();
    let domain = legal_max_length_domain(0);
    let source_count = 12_u128;
    let rows_per_source = 2_000_000_u128;
    let domain_bytes = u128::try_from(domain.len()).expect("usize always fits u128");
    let entry_size = u128::try_from(installed_entry_size()).expect("usize always fits u128");
    let row_bytes = checked_add(domain_bytes, 1).expect("long-name row arithmetic is supported");
    let source_body_bytes =
        checked_mul(rows_per_source, row_bytes).expect("long-name source arithmetic is supported");
    let union = checked_mul(source_count, rows_per_source)
        .expect("long-name union arithmetic is supported");
    let final_domain = legal_max_length_domain(
        union
            .checked_sub(1)
            .expect("nonempty long-name corpus has a final ordinal"),
    );

    assert!(source_count <= as_u128(MAX_LIST_SOURCES).unwrap());
    assert!(rows_per_source <= as_u128(lists.max_entries).unwrap());
    assert!(source_body_bytes <= as_u128(lists.max_body_bytes).unwrap());
    assert!(union <= as_u128(lists.max_total_domains).unwrap());
    assert_eq!(source_body_bytes, 508_000_000);
    assert_eq!(union, 24_000_000);
    assert_ne!(domain, final_domain, "modeled long names must be distinct");

    let lower_bound = representation_lower_bound(union, entry_size, domain_bytes)
        .expect("long-name representation arithmetic is supported");
    assert_eq!(lower_bound, 6_840_000_000);
    assert!(lower_bound > TWO_GIB);
}

#[test]
fn s7_raw_rows_not_union_drive_build_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(
        spill.is_disk(),
        "test must use the disk spill implementation"
    );
    let repeated = "a.b\n".repeat(1_025);

    let first = parse_source_into_spill_counted(
        Cursor::new(repeated.as_bytes()),
        1,
        &mut spill,
        2_000,
        "first",
        SpillParseOptions {
            declared: Some(ListFormat::DomainOnly),
            counting: UniqueCount::Measure(None),
            rollback_site: SpillRollbackSite::DirectTest,
        },
    )
    .unwrap();
    let second = parse_source_into_spill_counted(
        Cursor::new(repeated.as_bytes()),
        2,
        &mut spill,
        2_000,
        "second",
        SpillParseOptions {
            declared: Some(ListFormat::DomainOnly),
            counting: UniqueCount::Measure(None),
            rollback_site: SpillRollbackSite::DirectTest,
        },
    )
    .unwrap();
    assert_eq!(first.counts.parsed_ok, 1_025);
    assert_eq!(second.counts.parsed_ok, 1_025);
    assert_eq!(first.counts.unique_domains, 1);
    assert_eq!(second.counts.unique_domains, 1);

    spill.flush().unwrap();
    spill.prepare_validate().unwrap();
    let mut novel_by_bit = [0; 64];
    let union: u64 = (0..DOMAIN_SHARDS)
        .map(|idx| spill.count_unique(idx, &mut novel_by_bit).unwrap())
        .sum();
    assert_eq!(union, 1);

    let idx = FilterEngine::shard_index("a.b");
    let built = spill
        .build_shard(idx, union as usize, &ListPolicy::publish_uniform(0))
        .unwrap();
    assert_eq!(built.shape.raw_rows, 2_050);
    assert_eq!(built.shape.raw_capacity, 4_096);
    assert_eq!(built.shape.previous_capacity, Some(2_048));
    assert_eq!(built.shape.raw_heap_capacity, 0);

    let entries: Vec<_> = built.shard.iter().collect();
    assert_eq!(entries, vec![("a.b", 3)]);
}

#[test]
fn s7_default_budget_claim_is_not_supported() {
    let lists = ListsConfig::default();
    let entry_size = as_u128(installed_entry_size()).unwrap();
    let long_name_lower_bound = representation_lower_bound(
        as_u128(lists.max_total_domains).unwrap(),
        entry_size,
        u128::try_from(legal_max_length_domain(0).len()).unwrap(),
    )
    .expect("long-name default arithmetic is supported");
    let raw_rows = checked_mul(2, as_u128(lists.max_entries).unwrap())
        .expect("default raw row arithmetic is supported");
    let duplicate_source_body = checked_mul(
        as_u128(lists.max_entries).unwrap(),
        u128::try_from("a.b\n".len()).unwrap(),
    )
    .expect("duplicate-source body arithmetic is supported");
    let (raw_capacity, previous_capacity) =
        raw_vec_capacity_for_rows(1, raw_rows).expect("default Vec growth arithmetic is supported");
    let raw_bytes = checked_mul(raw_capacity, entry_size)
        .expect("default raw vector byte arithmetic is supported");

    const { assert!(2 <= MAX_LIST_SOURCES) };
    assert_eq!(duplicate_source_body, 80_000_000);
    assert!(duplicate_source_body <= as_u128(lists.max_body_bytes).unwrap());
    assert!(1 <= lists.max_total_domains, "the duplicate union is legal");
    assert_eq!(raw_rows, 40_000_000);
    assert_eq!(raw_capacity, 67_108_864);
    assert_eq!(previous_capacity, Some(33_554_432));
    assert_eq!(raw_bytes, TWO_GIB);
    assert_eq!(long_name_lower_bound, 6_840_000_000);
    assert!(long_name_lower_bound > TWO_GIB);

    let supported_claim = long_name_lower_bound < TWO_GIB && raw_bytes < TWO_GIB;
    assert!(
        !supported_claim,
        "defaults cannot imply a 2 GiB process bound before other memory"
    );
}

#[test]
fn s7_checked_arithmetic_never_wraps_to_supported() {
    assert_eq!(checked_mul(u128::MAX, 2), Err(Unsupported::Overflow));
    assert_eq!(
        representation_lower_bound(u128::MAX, 32, 253),
        Err(Unsupported::Overflow)
    );
    assert_eq!(
        supported_by_two_gib(u128::MAX, 32, 253),
        Err(Unsupported::Overflow),
        "overflow is unsupported, never evidence that a workload fits"
    );
}

async fn spawn_first_chunk_tls_origin(
    first_chunk: Vec<u8>,
    tail: Vec<u8>,
    mut release_tail: tokio::sync::mpsc::UnboundedReceiver<()>,
) -> (
    std::net::SocketAddr,
    String,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (first_sent, first_sent_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return;
        };
        let mut request = [0_u8; 4096];
        if tls.read(&mut request).await.is_err() {
            return;
        }

        let content_len = first_chunk.len() + tail.len();
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {content_len}\r\nConnection: close\r\n\r\n"
        );
        if tls.write_all(headers.as_bytes()).await.is_err()
            || tls.write_all(&first_chunk).await.is_err()
            || tls.flush().await.is_err()
        {
            return;
        }
        let _ = first_sent.send(());
        if release_tail.recv().await.is_none() {
            return;
        }
        let _ = tls.write_all(&tail).await;
        let _ = tls.shutdown().await;
    });
    (address, pem, first_sent_rx, task)
}

fn staged_temp_has_bytes(cache_dir: &std::path::Path) -> bool {
    std::fs::read_dir(cache_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .any(|entry| {
            entry.file_name().to_string_lossy().contains(".download-")
                && entry.metadata().is_ok_and(|metadata| metadata.len() > 0)
        })
}

#[tokio::test]
async fn disk_http_stages_first_chunk_before_origin_releases_tail() {
    // This is larger than the staging buffer, so the post-write checkpoint
    // can observe actual temporary-file bytes before the origin sends its tail.
    let first_chunk = "#\n".repeat(SPILL_WRITE_BUF).into_bytes();
    let tail = b"staged.example\n".to_vec();
    let (release_tail, release_tail_rx) = tokio::sync::mpsc::unbounded_channel();
    let (origin, pem, first_sent, origin_task) =
        spawn_first_chunk_tls_origin(first_chunk, tail, release_tail_rx).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/s7-first-chunk.txt".to_string();
    let mut manager = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        std::sync::Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    let (staged_checkpoint, mut staged_checkpoint_rx) = tokio::sync::mpsc::unbounded_channel();
    let cache_dir_for_hook = cache_dir.path().to_path_buf();
    let release_tail_for_hook = release_tail.clone();
    let mut released = false;
    manager.set_worker_hook_for_test(move |at| {
        if at == "staged_body_write" && !released && staged_temp_has_bytes(&cache_dir_for_hook) {
            released = true;
            let _ = release_tail_for_hook.send(());
            let _ = staged_checkpoint.send(());
        }
    });

    let worker =
        spawn_list_refresh_worker(manager, RefreshMode::Force, RefreshCancellation::default());
    tokio::time::timeout(Duration::from_secs(10), first_sent)
        .await
        .expect("origin must send headers and its first body chunk")
        .expect("origin closed before sending the first body chunk");

    let checkpoint =
        tokio::time::timeout(Duration::from_secs(10), staged_checkpoint_rx.recv()).await;
    if !matches!(checkpoint, Ok(Some(()))) {
        let _ = release_tail.send(());
        let _ = tokio::time::timeout(Duration::from_secs(10), worker).await;
        panic!(
            "whole-body buffering must time out before staged_body_write observes the first chunk"
        );
    }

    let outcome = tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .expect("refresh must complete after the staged first chunk releases the tail")
        .expect("refresh worker must not panic");
    origin_task.await.expect("origin task must finish");
    let RefreshWorkerOutcome::Completed {
        manager,
        completion,
    } = outcome
    else {
        panic!("streamed 200 refresh must complete rather than cancel");
    };

    assert_eq!(completion.domain_count, 1);
    assert!(manager.filter.is_blocked("staged.example"));
    assert!(
        manager
            .cache
            .get(&source)
            .is_some_and(|cache| cache.body.is_none()),
        "disk-backed HTTP must not retain FreshBody::Resident"
    );
    assert!(selected_cache_body_path(cache_dir.path(), &source).is_some());
}
