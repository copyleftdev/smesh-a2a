#![no_main]

use libfuzzer_sys::fuzz_target;
use smesh_a2a::{AuthorizationPolicy, QuotaPolicy, push::PushPolicy, transport::PrincipalMap};

const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = AuthorizationPolicy::from_json(data);
    let _ = QuotaPolicy::from_json(data);
    let _ = PushPolicy::parse_bytes(data);
    let _ = PrincipalMap::from_json(data, MAX_INPUT, 1_024);
});
