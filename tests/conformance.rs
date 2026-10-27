//! Byte-for-byte checks against the shared vector file owned by Wavvon-server
//! (`crates/identity/wire-vectors.json`). Set WAVVON_WIRE_VECTORS to point at
//! another copy; CI fetches the pinned one.

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use wavvon_sdk::auth::{challenge_signing_bytes, Identity, AUTH_CHALLENGE_SCHEME};
use wavvon_sdk::error::VerifyError;
use wavvon_sdk::webhooks::{
    delivery_signing_bytes, hmac_sha256, outgoing_signing_key, verify_dispatch,
    verify_outgoing_webhook, DeliveryHeaders,
};

struct Vectors {
    root: Value,
}

fn load() -> Option<Vectors> {
    let path = std::env::var("WAVVON_WIRE_VECTORS").map_or_else(
        |_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../server/crates/identity/wire-vectors.json")
        },
        PathBuf::from,
    );
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let root: Value = serde_json::from_str(&text).expect("vectors file is JSON");
            assert_eq!(root["format"], 1, "vector file format changed");
            Some(Vectors { root })
        }
        Err(e) if std::env::var_os("CI").is_some() => {
            panic!("conformance vectors missing at {}: {e}", path.display())
        }
        Err(e) => {
            eprintln!(
                "\n!!!!!! CONFORMANCE SKIPPED: no vectors at {} ({e}) !!!!!!\n",
                path.display()
            );
            None
        }
    }
}

impl Vectors {
    fn resolve(&self, v: &Value) -> Value {
        match v {
            Value::String(s) if s.starts_with('@') => self.root["fixtures"][&s[1..]].clone(),
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), self.resolve(v)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(|v| self.resolve(v)).collect()),
            other => other.clone(),
        }
    }

    fn vector(&self, name: &str) -> Value {
        self.resolve(&self.root["vectors"][name])
    }
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(s(v)).expect("hex")
}

#[test]
fn auth_challenge() {
    let Some(vectors) = load() else { return };
    let v = vectors.vector("auth_challenge");
    let challenge = unhex(&v["inputs"]["challenge"]);
    let signing = challenge_signing_bytes(&challenge, Some(AUTH_CHALLENGE_SCHEME)).unwrap();
    assert_eq!(hex::encode(signing), s(&v["signing_bytes"]));

    let id = Identity::from_seed_hex(s(&v["inputs"]["signer_seed"])).unwrap();
    let sig = id
        .sign_challenge(s(&v["inputs"]["challenge"]), Some(AUTH_CHALLENGE_SCHEME))
        .unwrap();
    assert_eq!(sig, s(&v["signature"]));
}

#[test]
fn webhook_delivery_hub() {
    let Some(vectors) = load() else { return };
    let v = vectors.vector("webhook_delivery_hub");
    let ts = v["inputs"]["timestamp"].as_u64().unwrap();
    let body = s(&v["inputs"]["body"]).as_bytes();

    let signing = delivery_signing_bytes(ts, body);
    assert_eq!(hex::encode(&signing), s(&v["signing_bytes"]));

    let seed: [u8; 32] = unhex(&v["inputs"]["hub_seed"]).try_into().unwrap();
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        s(&v["hub_pubkey"])
    );
    assert_eq!(
        hex::encode(key.sign(&signing).to_bytes()),
        s(&v["signature_v1"])
    );

    let ts_text = ts.to_string();
    let headers = DeliveryHeaders {
        hub_pubkey: Some(s(&v["hub_pubkey"])),
        signature_v1: Some(s(&v["signature_v1"])),
        timestamp: Some(&ts_text),
    };
    assert_eq!(
        verify_dispatch(s(&v["hub_pubkey"]), &headers, body, ts + 299),
        Ok(())
    );
    assert_eq!(
        verify_dispatch(s(&v["hub_pubkey"]), &headers, body, ts + 301),
        Err(VerifyError::Stale { skew: 301 })
    );
    assert_eq!(
        v["headers"]["signature_v1"],
        wavvon_sdk::webhooks::HEADER_SIGNATURE_V1
    );
    assert_eq!(
        v["headers"]["timestamp"],
        wavvon_sdk::webhooks::HEADER_TIMESTAMP
    );
    assert_eq!(
        v["headers"]["hub_pubkey"],
        wavvon_sdk::webhooks::HEADER_HUB_PUBKEY
    );
}

#[test]
fn webhook_delivery_outgoing() {
    use base64::Engine;
    let Some(vectors) = load() else { return };
    let v = vectors.vector("webhook_delivery_outgoing");
    let ts = v["inputs"]["timestamp"].as_u64().unwrap();
    let body = s(&v["inputs"]["body"]).as_bytes();
    let shown = s(&v["inputs"]["secret_as_shown"]);

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(shown)
        .unwrap();
    assert_eq!(hex::encode(&raw), s(&v["inputs"]["raw_secret"]));
    assert_eq!(s(&v["inputs"]["hkdf_salt"]), "wavvon-webhook-signing");
    assert_eq!(s(&v["inputs"]["hkdf_info"]), "");

    let key = outgoing_signing_key(&raw);
    assert_eq!(hex::encode(key), s(&v["signing_key"]));
    let signing = delivery_signing_bytes(ts, body);
    assert_eq!(hex::encode(&signing), s(&v["signing_bytes"]));
    assert_eq!(
        hex::encode(hmac_sha256(&key, &signing)),
        s(&v["signature_v1"])
    );

    let ts_text = ts.to_string();
    let headers = DeliveryHeaders {
        hub_pubkey: None,
        signature_v1: Some(s(&v["signature_v1"])),
        timestamp: Some(&ts_text),
    };
    assert_eq!(verify_outgoing_webhook(shown, &headers, body, ts), Ok(()));
    assert_eq!(
        verify_outgoing_webhook(s(&v["inputs"]["raw_secret"]), &headers, body, ts),
        Err(VerifyError::BadSecret),
        "the hex form of the secret is not the secret as shown"
    );
}
