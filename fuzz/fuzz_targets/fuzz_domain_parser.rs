#![no_main]
use ahash::RandomState;
use compact_str::CompactString;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut set: HashSet<CompactString, RandomState> =
            HashSet::with_hasher(RandomState::new());
        purge_warden::lists::parser::parse_domain_list_into(s, &mut set);
    }
});
