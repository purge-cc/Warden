#![no_main]
use ahash::RandomState;
use compact_str::CompactString;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut map: HashMap<CompactString, u64, RandomState> =
            HashMap::with_hasher(RandomState::new());
        purge_warden::lists::parser::parse_hosts_list_into_map(
            s,
            1,
            &mut map,
            purge_warden::lists::parser::DEFAULT_MAX_LIST_ENTRIES,
            "fuzz",
        );
    }
});
