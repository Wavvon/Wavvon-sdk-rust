//! Verifying what a hub POSTs to a program (wire-format.md, "Webhook delivery").
//!
//! Framework-agnostic: hand over the three headers and the raw body bytes,
//! exactly as received. Verify before you parse.

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::VerifyError;

pub const HEADER_HUB_PUBKEY: &str = "X-Wavvon-Hub-Pubkey";
pub const HEADER_SIGNATURE_V1: &str = "X-Wavvon-Signature-V1";
pub const HEADER_TIMESTAMP: &str = "X-Wavvon-Timestamp";
/// A delivery older (or newer) than this is refused.
pub const MAX_SKEW_SECS: u64 = 300;

const DELIVERY_TAG: &[u8] = b"wavvon/webhook-delivery/v1\0";
const HKDF_SALT: &[u8] = b"wavvon-webhook-signing";

/// The headers a verifier reads; `None` where the request had none.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeliveryHeaders<'a> {
    pub hub_pubkey: Option<&'a str>,
    pub signature_v1: Option<&'a str>,
    pub timestamp: Option<&'a str>,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `tag || timestamp (u64 LE) || body`: what both signatures cover.
pub fn delivery_signing_bytes(timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut buf = DELIVERY_TAG.to_vec();
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(body);
    buf
}

/// The HMAC key for an outgoing webhook: HKDF-SHA256 over the 32 bytes the
/// secret decodes to, salt `wavvon-webhook-signing`, empty info.
pub fn outgoing_signing_key(raw_secret: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(HKDF_SALT), raw_secret);
    let mut key = [0u8; 32];
    hk.expand(b"", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn timestamp_in_window(raw: &str, now: u64) -> Result<u64, VerifyError> {
    let ts: u64 = raw
        .trim()
        .parse()
        .map_err(|_| VerifyError::BadHeader(HEADER_TIMESTAMP))?;
    let skew = now.abs_diff(ts);
    if skew > MAX_SKEW_SECS {
        return Err(VerifyError::Stale { skew });
    }
    Ok(ts)
}

fn header<'a>(v: Option<&'a str>, name: &'static str) -> Result<&'a str, VerifyError> {
    v.ok_or(VerifyError::MissingHeader(name))
}

/// Slash and component dispatch: Ed25519 by the hub's key over
/// [`delivery_signing_bytes`], then the 300 s window.
///
/// `trusted_hub_pubkey` is the hub's key as *you* know it (`Client::hub_public_key`,
/// or `/info`). The header only has to agree with it: a signature checked
/// against a key the sender names proves nothing.
pub fn verify_dispatch(
    trusted_hub_pubkey: &str,
    headers: &DeliveryHeaders<'_>,
    body: &[u8],
    now: u64,
) -> Result<(), VerifyError> {
    let named = header(headers.hub_pubkey, HEADER_HUB_PUBKEY)?;
    if !named.eq_ignore_ascii_case(trusted_hub_pubkey) {
        return Err(VerifyError::WrongHub);
    }
    let sig_hex = header(headers.signature_v1, HEADER_SIGNATURE_V1)?;
    let ts_raw = header(headers.timestamp, HEADER_TIMESTAMP)?;

    let key: [u8; 32] = hex::decode(trusted_hub_pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::BadHeader(HEADER_HUB_PUBKEY))?;
    let key =
        VerifyingKey::from_bytes(&key).map_err(|_| VerifyError::BadHeader(HEADER_HUB_PUBKEY))?;
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::BadHeader(HEADER_SIGNATURE_V1))?;

    let ts: u64 = ts_raw
        .trim()
        .parse()
        .map_err(|_| VerifyError::BadHeader(HEADER_TIMESTAMP))?;
    key.verify_strict(
        &delivery_signing_bytes(ts, body),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| VerifyError::BadSignature)?;
    timestamp_in_window(ts_raw, now).map(|_| ())
}

/// Outgoing webhooks: HMAC-SHA256 keyed by the derived key. `secret_as_shown`
/// is the base64url (no padding) text the admin was shown once.
pub fn verify_outgoing_webhook(
    secret_as_shown: &str,
    headers: &DeliveryHeaders<'_>,
    body: &[u8],
    now: u64,
) -> Result<(), VerifyError> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_as_shown.trim())
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or(VerifyError::BadSecret)?;
    let sig_hex = header(headers.signature_v1, HEADER_SIGNATURE_V1)?;
    let ts_raw = header(headers.timestamp, HEADER_TIMESTAMP)?;
    let sig = hex::decode(sig_hex).map_err(|_| VerifyError::BadHeader(HEADER_SIGNATURE_V1))?;
    let ts: u64 = ts_raw
        .trim()
        .parse()
        .map_err(|_| VerifyError::BadHeader(HEADER_TIMESTAMP))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&outgoing_signing_key(&raw))
        .expect("HMAC takes any key length");
    mac.update(&delivery_signing_bytes(ts, body));
    mac.verify_slice(&sig)
        .map_err(|_| VerifyError::BadSignature)?;
    timestamp_in_window(ts_raw, now).map(|_| ())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signed(ts: u64, body: &[u8]) -> (String, String) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let sig = key.sign(&delivery_signing_bytes(ts, body));
        (
            hex::encode(key.verifying_key().to_bytes()),
            hex::encode(sig.to_bytes()),
        )
    }

    fn headers<'a>(pk: &'a str, sig: &'a str, ts: &'a str) -> DeliveryHeaders<'a> {
        DeliveryHeaders {
            hub_pubkey: Some(pk),
            signature_v1: Some(sig),
            timestamp: Some(ts),
        }
    }

    #[test]
    fn dispatch_accepts_a_fresh_signed_delivery() {
        let (pk, sig) = signed(1000, b"{}");
        assert_eq!(
            verify_dispatch(&pk, &headers(&pk, &sig, "1000"), b"{}", 1100),
            Ok(())
        );
    }

    #[test]
    fn dispatch_refuses_stale_tampered_and_foreign() {
        let (pk, sig) = signed(1000, b"{}");
        let h = headers(&pk, &sig, "1000");
        assert_eq!(
            verify_dispatch(&pk, &h, b"{}", 1301),
            Err(VerifyError::Stale { skew: 301 })
        );
        assert_eq!(
            verify_dispatch(&pk, &h, b"{ }", 1000),
            Err(VerifyError::BadSignature)
        );
        assert_eq!(
            verify_dispatch(&pk, &headers(&pk, &sig, "1001"), b"{}", 1001),
            Err(VerifyError::BadSignature)
        );
        let other = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert_eq!(
            verify_dispatch(&other, &h, b"{}", 1000),
            Err(VerifyError::WrongHub)
        );
        assert_eq!(
            verify_dispatch(&pk, &DeliveryHeaders::default(), b"{}", 1000),
            Err(VerifyError::MissingHeader(HEADER_HUB_PUBKEY))
        );
    }

    #[test]
    fn outgoing_round_trip_and_bad_secret() {
        use base64::Engine;
        let raw = [7u8; 32];
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let sig = hex::encode(hmac_sha256(
            &outgoing_signing_key(&raw),
            &delivery_signing_bytes(50, b"x"),
        ));
        let h = DeliveryHeaders {
            hub_pubkey: None,
            signature_v1: Some(&sig),
            timestamp: Some("50"),
        };
        assert_eq!(verify_outgoing_webhook(&secret, &h, b"x", 60), Ok(()));
        assert_eq!(
            verify_outgoing_webhook(&secret, &h, b"y", 60),
            Err(VerifyError::BadSignature)
        );
        assert_eq!(
            verify_outgoing_webhook(&secret, &h, b"x", 5000),
            Err(VerifyError::Stale { skew: 4950 })
        );
        assert_eq!(
            verify_outgoing_webhook("not base64!", &h, b"x", 60),
            Err(VerifyError::BadSecret)
        );
        assert_eq!(
            verify_outgoing_webhook(&hex::encode(raw), &h, b"x", 60),
            Err(VerifyError::BadSecret)
        );
    }
}
