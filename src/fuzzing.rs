use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

const MAX_PAGE_TOKEN_BYTES: usize = 4096;

pub(crate) fn decode_opaque_page_token_hash(token: &str) -> Option<[u8; 32]> {
    if token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    if raw.len() != 32 {
        return None;
    }
    Some(Sha256::digest(raw).into())
}

pub(crate) fn parse_callback_page_token(
    key: &[u8; 32],
    token: &str,
    tenant: &str,
    task: &str,
) -> Option<(i64, String)> {
    if token.is_empty() || token.len() > MAX_PAGE_TOKEN_BYTES {
        return None;
    }
    let (payload_text, mac_text) = token.split_once('.')?;
    if payload_text.is_empty() || mac_text.is_empty() || mac_text.contains('.') {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(payload_text).ok()?;
    let supplied = URL_SAFE_NO_PAD.decode(mac_text).ok()?;
    if supplied.len() != 32 {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(b"smesh-callback-page-v1\0");
    mac.update(&payload);
    mac.verify_slice(&supplied).ok()?;
    let text = std::str::from_utf8(&payload).ok()?;
    let mut fields = text.split('\u{1f}');
    if fields.next() != Some("1") || fields.next() != Some(tenant) || fields.next() != Some(task) {
        return None;
    }
    let created = fields.next()?.parse().ok()?;
    let id = fields.next().filter(|value| !value.is_empty())?.to_owned();
    if fields.next().is_some() {
        return None;
    }
    Some((created, id))
}

#[doc(hidden)]
#[must_use]
pub fn fuzz_decode_opaque_page_token(token: &str) -> bool {
    decode_opaque_page_token_hash(token).is_some()
}

#[doc(hidden)]
#[must_use]
pub fn fuzz_parse_callback_page_token(
    key: &[u8; 32],
    token: &str,
    tenant: &str,
    task: &str,
) -> bool {
    parse_callback_page_token(key, token, tenant, task).is_some()
}
