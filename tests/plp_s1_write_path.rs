//! **The write-path checklist** — `_docs/features/profile_list_policy.md`
//! §2.4, test 4.
//!
//! §2.4's consequence, and the one it says gets written wrong: *"ogni
//! mutazione che tocca l'insieme delle liste, l'assegnazione dei bit, il
//! corpo di una lista **o la politica di un profilo** deve ripubblicare la
//! stessa `FilterGeneration`. […] Un percorso che ripubblica solo
//! `ResolverMap` dopo un cambio di direzione è il bug — ed è un bug del
//! *write path*, quindi testabile a tavolino."*
//!
//! `ListPolicy::publish` is the only way to take a generation id, so "did
//! this mutation reach the filter?" is answerable by whether the served
//! `gen_id` moved — no call-graph reading required.
//!
//! # Why the no-op row is the load-bearing one
//!
//! A table where every row expects a republish is satisfied by a manager
//! that republishes unconditionally, which would make the other rows
//! meaningless. The `nothing changed` row is what makes a republish an
//! *event*: the bodies are byte-identical and the direction map is
//! unchanged, so the corpus digest matches and pass 2 is skipped. If that
//! row ever republishes, every other row here is satisfied by a manager that
//! rebuilds on every tick and this file measures nothing.
//!
//! The direction rows are the ones §2.4 is actually about. The digest is
//! seeded with `allow_bits` (`manager.rs`, `new_corpus_digest_ctx`) precisely
//! because it once was not: with the two disconnected, an operator who
//! flipped a list's `kind` and reloaded got no rebuild whenever no list body
//! had changed, so a revoked exemption kept exempting until some unrelated
//! list happened to change.
//!
//! # The trap this fixture fell into first — do not re-set the interval to 0
//!
//! The first version passed `Duration::from_secs(0)` to force every cycle to
//! re-fetch. It does not: `ListManager::new` clamps the interval to
//! `MIN_REFRESH_INTERVAL` (60 s, `manager.rs`), so the cached body stayed
//! *fresh*, `probe_unchanged_corpus` settled the cycle from disk, and the run
//! issued exactly **one** HTTP request in total — the boot one. The body-change
//! row then failed while the product was behaving correctly, which is the
//! worst kind of red: a diagnostic pointing at the write path for a fault
//! that was in the fixture.
//!
//! So the body row evicts the on-disk `.cache` file instead of racing the
//! clock. That is not a hack around the clamp — it exercises the documented
//! `"cache marked fresh but body missing, falling back to HTTP"` arm, which
//! is a real state (an operator or a disk cleaner can produce it), and it is
//! the only zero-wait way to reach the network through the public API.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ahash::RandomState;
use compact_str::CompactString;
use purge_warden::config::loader::load_config;
use purge_warden::filter::engine::{FilterEngine, PolicyMasks, ProfileMasks};
use purge_warden::lists::catalog::Catalog;
use purge_warden::lists::manager::{merge_sources_with_blocklists, ListManager};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::lists::status::LastOutcome;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What a step does to the world before the refresh.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// The world is untouched.
    Nothing,
    /// A list's body changes at the origin, and the on-disk cache is evicted
    /// so the cycle actually goes and gets it. See the module doc.
    Body(&'static str),
    /// Only direction changes: the same bytes, a different base direction.
    /// The policy-only republish §2.4 says a write path forgets.
    Direction(u64),
    /// Only a **per-profile override** changes: same bytes, same `base`.
    ///
    /// `plp-s3` widened the digest from one `u64` to the whole per-profile
    /// table, and this row is what makes that widening falsifiable. An
    /// operator who edits `profiles.<id>.lists` and nothing else must still
    /// get a republish — otherwise the override is accepted, written, and
    /// never served, which is the silent no-op the whole workstream exists to
    /// remove.
    ProfileOverride(&'static str, u64, u64),
}

struct Row {
    what: &'static str,
    mutation: Mutation,
    /// Must the served generation id move?
    must_republish: bool,
    /// How many domains the corpus must hold after this step.
    ///
    /// **Without this the no-op row is worthless.** A refresh that died on
    /// its first line also leaves the generation id where it was and also
    /// issues no request — indistinguishable, to the two columns above, from
    /// a correct decision not to republish. Asserting on state the product
    /// preserves *in failure* proves nothing; this column asserts on state a
    /// failed cycle would not produce.
    expect_domains: usize,
    /// Must the cycle reach the origin?
    ///
    /// A policy change must republish **without** a network round trip: it
    /// changes what the same bytes mean, not what the bytes are. Asserting
    /// this is what proves the republish came from the digest rather than
    /// from an incidental re-download — without it, a manager that re-fetched
    /// on every tick would satisfy every `must_republish` row for the wrong
    /// reason.
    must_fetch: bool,
    /// Why, in the failure message — a bare `false` tells a reader nothing.
    because: &'static str,
}

const TABLE: &[Row] = &[
    Row {
        what: "nothing changed",
        mutation: Mutation::Nothing,
        must_republish: false,
        expect_domains: 1,
        must_fetch: false,
        because: "the corpus digest is unchanged, so pass 2 is skipped and the \
                  installed generation keeps serving. If this row republishes, \
                  every other row in this table is satisfied by a manager that \
                  republishes unconditionally and measures nothing",
    },
    Row {
        what: "a list body changed (cache evicted so the fetch happens)",
        mutation: Mutation::Body("a-only.test\nnew-domain.test\n"),
        must_republish: true,
        expect_domains: 2,
        must_fetch: true,
        because: "the corpus moved; a filter still serving the old generation is \
                  filtering on domains that are no longer what the operator's \
                  lists say",
    },
    Row {
        what: "direction only — deny flipped to allow, same bytes",
        mutation: Mutation::Direction(0b1),
        must_republish: true,
        expect_domains: 2,
        must_fetch: false,
        because: "this is the row the digest was widened for. Direction decides \
                  allow vs block for every domain on that list, and a write path \
                  that skips the republish leaves a revoked exemption exempting \
                  until some unrelated list happens to change",
    },
    Row {
        what: "per-profile override only — one profile flips a list to allow",
        mutation: Mutation::ProfileOverride("kids", 0b1, 0),
        must_republish: true,
        expect_domains: 2,
        must_fetch: false,
        because: "`plp-s3`: direction is per profile now, so the digest folds \
                  the whole table. An operator editing `profiles.kids.lists` \
                  and nothing else must get a republish — a digest that only \
                  hashed `base` would pass every other row here and silently \
                  drop this one",
    },
    Row {
        what: "direction only — back to deny",
        mutation: Mutation::Direction(0),
        must_republish: true,
        expect_domains: 2,
        must_fetch: false,
        because: "the reverse flip must republish too; a digest that folded \
                  direction in only one direction would pass the row above and \
                  fail here",
    },
];

// ── origin ────────────────────────────────────────────────────────────

struct Origin {
    addr: SocketAddr,
    pem: String,
    body: Arc<Mutex<String>>,
    hits: Arc<std::sync::atomic::AtomicUsize>,
}

impl Origin {
    fn hits(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn serve(initial: &str) -> Origin {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_crypto));

    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(Mutex::new(initial.to_string()));
    let served = body.clone();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hit_counter = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let served = served.clone();
            let hit_counter = hit_counter.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                if tls.read(&mut buf).await.is_err() {
                    return;
                }
                // No ETag / Last-Modified: every fetch is a fresh 200, so a
                // body change is always visible to the parser and the only
                // thing that can suppress a republish is the digest.
                hit_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = served.lock().unwrap().clone();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Origin {
        addr,
        pem,
        body,
        hits,
    }
}

fn client_for(origin: &Origin) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("purge-warden/0.1")
        .timeout(Duration::from_secs(10))
        .resolve("lists.test", origin.addr)
        .add_root_certificate(reqwest::Certificate::from_pem(origin.pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

const CONFIG: &str = "schema_version = 3\n\n\
     [server]\n\
     default_profile = \"default\"\n\n\
     [profiles.default]\n\
     display_name = \"Default\"\n\
     tags = [\"t\"]\n\n\
     [[blocklists]]\n\
     id = \"a\"\n\
     display_name = \"A\"\n\
     url = \"https://lists.test/a.txt\"\n\
     format = \"domains\"\n\
     base = \"deny\"\n\
     tags = [\"t\"]\n\n\
     [upstream]\n\
     servers = [\"192.0.2.1:53\"]\n";

/// Every shard's generation id must agree, and that agreement is itself part
/// of what is being checked: a partial install would mean some shards are
/// interpreting their bits with one direction map and some with another.
fn served_generation(filter: &FilterEngine, step: &str) -> u64 {
    let ids = filter.filter_gen_ids();
    let first = ids[0];
    assert!(
        ids.iter().all(|id| *id == first),
        "{step}: shards straddle generations {ids:?} — a partial install leaves \
         some shards splitting their bits with a different direction map than \
         others"
    );
    first
}

#[tokio::test]
async fn every_write_path_republishes_the_filter_generation() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(&cfg_path, CONFIG).unwrap();
    let config = load_config(&cfg_path, time::OffsetDateTime::now_utc())
        .map(|l| l.config)
        .expect("fixture config must load");

    let origin = serve("a-only.test\n").await;
    let (merged, _trust) = merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);
    let source_bits = SourceBitMap::build(&merged, &config.blocklists).unwrap();

    let filter = Arc::new(FilterEngine::new());
    let cache_dir = dir.path().join("lists-cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let cache_dir = cache_dir.clone();

    let mut mgr = ListManager::new(
        client_for(&origin),
        filter.clone(),
        merged,
        Catalog::fallback(),
        // A production-shaped interval. Nothing here depends on it expiring:
        // the body row evicts the cache instead of waiting, and the direction
        // rows change the digest without needing the network at all.
        Duration::from_secs(3600),
        source_bits,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(cache_dir.clone()),
    );
    mgr.set_list_policy(PolicyMasks::default());

    // Boot. This one must publish: before it, the engine is empty and every
    // shard carries the reserved `gen_id == 0`.
    assert!(
        filter.filter_gen_ids().iter().all(|id| *id == 0),
        "a fresh engine must carry the inert policy, so that the boot publish \
         below is observable as a change rather than assumed"
    );
    mgr.refresh().await;
    let mut previous = served_generation(&filter, "boot");
    assert_ne!(previous, 0, "boot must publish a real generation");

    for row in TABLE {
        match row.mutation {
            Mutation::Nothing => {}
            Mutation::Body(next) => {
                *origin.body.lock().unwrap() = next.to_string();
                // Evict the body but leave the in-memory entry: the cycle
                // then takes the documented "cache marked fresh but body
                // missing, falling back to HTTP" arm.
                for e in std::fs::read_dir(&cache_dir).unwrap() {
                    let path = e.unwrap().path();
                    if path.extension().is_some_and(|x| x == "cache") {
                        std::fs::remove_file(&path).unwrap();
                    }
                }
            }
            Mutation::Direction(allow) => mgr.set_list_policy(PolicyMasks {
                base: ProfileMasks {
                    allow,
                    block: !allow,
                },
                ..PolicyMasks::default()
            }),
            Mutation::ProfileOverride(profile, allow, block) => {
                let mut per_profile: HashMap<CompactString, ProfileMasks, RandomState> =
                    HashMap::default();
                per_profile.insert(CompactString::new(profile), ProfileMasks { allow, block });
                mgr.set_list_policy(PolicyMasks {
                    base: ProfileMasks {
                        allow: 0,
                        block: !0,
                    },
                    per_profile,
                });
            }
        }
        let hits_before = origin.hits();
        mgr.refresh().await;
        let now = served_generation(&filter, row.what);
        let fetched = origin.hits() > hits_before;

        // A cycle that fell over on its first line would satisfy both columns
        // below for the no-op row. These two say it actually ran.
        for (id, st) in mgr.status_registry().snapshot() {
            assert_eq!(
                st.last_outcome,
                LastOutcome::Ok,
                "ENVIRONMENT, not the write path: `{id}` is not Ok after `{}`, so \
                 this row says nothing about republish behaviour",
                row.what,
            );
        }
        assert_eq!(
            filter.domain_count(),
            row.expect_domains,
            "`{}` left {} domains installed, expected {}. The generation-id \
             columns cannot tell a correct no-op from a cycle that died early; \
             this can.",
            row.what,
            filter.domain_count(),
            row.expect_domains,
        );

        assert_eq!(
            fetched,
            row.must_fetch,
            "WRITE PATH: `{}` {} the origin.\n  A policy-only change must reach \
             the filter through the corpus digest, not through a re-download; a \
             corpus change must actually go and get the new bytes.",
            row.what,
            if fetched { "reached" } else { "did not reach" },
        );

        if row.must_republish {
            assert!(
                now > previous,
                "WRITE PATH: `{}` did NOT republish (generation stayed {previous}).\n  {}",
                row.what,
                row.because,
            );
        } else {
            assert_eq!(
                now, previous,
                "WRITE PATH: `{}` republished when nothing changed.\n  {}",
                row.what, row.because,
            );
        }
        previous = now;
    }
}

/// **One install is ONE generation, even through the flat adapter.**
///
/// `swap_blocklist(Default::default())` is a production path, not a fixture:
/// `cli/commands/start.rs` runs it when the operator removes every list
/// source from the config, and it reaches the engine through `partition` →
/// `SortedShard::from_pairs` — the two-mask adapter, which *derives*
/// `allow_bits` per shard rather than being handed a finished policy.
///
/// Because it derives per shard, the obvious implementation takes a
/// generation id per shard too, and then this one coherent clear reports 16
/// different generations — indistinguishable, to
/// [`FilterEngine::filter_gen_ids`] and to `served_generation` above, from a
/// genuinely torn install. This test exists because that is exactly what the
/// first cut of `plp-s1` did.
#[test]
fn a_flat_install_stamps_one_generation_across_every_shard() {
    let engine = FilterEngine::new();
    assert!(
        engine.filter_gen_ids().iter().all(|id| *id == 0),
        "a fresh engine must be inert, so the install below is observable"
    );

    let mut domains: std::collections::HashSet<compact_str::CompactString, ahash::RandomState> =
        std::collections::HashSet::with_hasher(ahash::RandomState::new());
    // Enough names, spread over enough shards, that a per-shard mint would
    // show up as more than one distinct id.
    for i in 0..512 {
        domains.insert(compact_str::CompactString::from(format!("d{i:04}.test")));
    }
    engine.swap_blocklist(domains);

    let ids = engine.filter_gen_ids();
    let distinct: std::collections::BTreeSet<u64> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "one install produced {} distinct generation ids ({ids:?}). Every shard \
         of one install must carry one generation: a reader cannot otherwise \
         tell this apart from a reload that got half way",
        distinct.len(),
    );
    assert_ne!(
        ids[0], 0,
        "the install must take a real generation id, not leave the inert one"
    );
}
