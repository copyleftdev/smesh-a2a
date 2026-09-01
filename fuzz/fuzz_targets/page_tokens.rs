#![no_main]

use libfuzzer_sys::fuzz_target;
use smesh_a2a::{fuzz_decode_opaque_page_token, fuzz_parse_callback_page_token};

const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut key = [0_u8; 32];
    for (target, source) in key.iter_mut().zip(data.iter().copied()) {
        *target = source;
    }
    let _ = fuzz_decode_opaque_page_token(text);
    let _ = fuzz_parse_callback_page_token(&key, text, "tenant-fuzz", "task-fuzz");
});
