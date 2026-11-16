//! The DM and voice vectors of `wire-vectors.json` (sdk-dm.md section 6,
//! sdk-voice.md section 2), asserted against the crypto the SDK builds on.

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha512};
use wavvon_sdk::auth::Identity;

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
        Ok(text) => Some(Vectors {
            root: serde_json::from_str(&text).expect("vectors file is JSON"),
        }),
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

fn b32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().expect("32 bytes")
}

fn n32(v: &Value) -> u32 {
    v.as_u64().expect("number") as u32
}

fn dh_secret(seed: &Value) -> [u8; 32] {
    let hash = Sha512::digest(b32(seed));
    let mut k = [0u8; 32];
    k.copy_from_slice(&hash[..32]);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

fn x_pub(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*secret, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn dh_pair(seed: &Value) -> ([u8; 32], [u8; 32]) {
    let secret = dh_secret(seed);
    (secret, x_pub(&secret))
}

fn check_signed(vectors: &Vectors, name: &str, signing: Vec<u8>) {
    let v = vectors.vector(name);
    assert_eq!(hex::encode(&signing), s(&v["signing_bytes"]), "{name}");
    let key = SigningKey::from_bytes(&b32(&v["inputs"]["signer_seed"]));
    assert_eq!(
        hex::encode(key.sign(&signing).to_bytes()),
        s(&v["signature"]),
        "{name}"
    );
}

#[test]
fn master_dh_pubkey() {
    let Some(vectors) = load() else { return };
    let v = vectors.vector("master_dh_pubkey");
    let id = Identity::from_seed(b32(&v["inputs"]["seed"]));
    assert_eq!(id.dh_public_key_hex(), s(&v["dh_pubkey"]));
}

#[test]
fn dh_key_record() {
    let Some(vectors) = load() else { return };
    let i = vectors.vector("dh_key_record")["inputs"].clone();
    check_signed(
        &vectors,
        "dh_key_record",
        wavvon_identity::DhKeyRecord::signing_bytes(s(&i["pubkey"]), s(&i["dh_pubkey"])),
    );
}

#[test]
fn voice_key_wrap() {
    let Some(vectors) = load() else { return };
    let v = vectors.vector("voice_key_wrap");
    let i = &v["inputs"];
    let (_, recipient_pub) = dh_pair(&i["recipient_seed"]);
    let (_, sender_pub) = dh_pair(&i["sender_seed"]);
    let key = b32(&i["sender_key"]);
    let salt: [u8; 4] = unhex(&i["nonce_salt"]).try_into().unwrap();
    let nonce: [u8; 12] = unhex(&i["wrap_nonce"]).try_into().unwrap();
    let key_id = n32(&i["key_id"]);
    let ct = wavvon_identity::voice_key_wrap_with_nonce(
        &b32(&i["sender_seed"]),
        &recipient_pub,
        s(&i["channel_id"]),
        &key,
        &salt,
        key_id,
        &nonce,
    )
    .unwrap();
    assert_eq!(hex::encode(&ct), s(&v["ciphertext"]));
    let opened = wavvon_identity::voice_key_unwrap(
        &b32(&i["recipient_seed"]),
        &sender_pub,
        s(&i["channel_id"]),
        &ct,
        &nonce,
    )
    .unwrap();
    assert_eq!(opened, (key, salt, key_id));
}

#[test]
fn voice_packets() {
    let Some(vectors) = load() else { return };
    for name in ["voice_packet_ctr0", "voice_packet_ctr7"] {
        let v = vectors.vector(name);
        let i = &v["inputs"];
        let key = b32(&i["sender_key"]);
        let salt: [u8; 4] = unhex(&i["nonce_salt"]).try_into().unwrap();
        let (key_id, ts) = (n32(&i["key_id"]), n32(&i["timestamp"]));
        let ctr = i["counter"].as_u64().unwrap();
        let opus = unhex(&i["opus"]);
        let packet = wavvon_identity::voice_packet_seal(&key, &salt, key_id, ctr, ts, &opus);
        assert_eq!(hex::encode(&packet), s(&v["packet"]), "{name}");
        let opened = wavvon_identity::voice_packet_open(&key, &salt, &packet).unwrap();
        assert_eq!(opened, (key_id, ctr, ts, opus), "{name}");
    }
}

#[test]
fn signed_dm_envelopes() {
    use wavvon_identity::*;
    let Some(vectors) = load() else { return };
    let i = vectors.vector("dm_envelope")["inputs"].clone();
    check_signed(
        &vectors,
        "dm_envelope",
        dm_envelope_signing_bytes(
            s(&i["conversation_id"]),
            s(&i["ciphertext"]),
            s(&i["nonce"]),
            s(&i["sender_dh_pubkey"]),
        ),
    );
    let i = vectors.vector("dr_envelope")["inputs"].clone();
    check_signed(
        &vectors,
        "dr_envelope",
        dr_envelope_signing_bytes(
            s(&i["conversation_id"]),
            n32(&i["message_index"]),
            n32(&i["prev_count"]),
            s(&i["ciphertext"]),
            s(&i["dh_pubkey"]),
        ),
    );
    let i = vectors.vector("group_dm_envelope")["inputs"].clone();
    check_signed(
        &vectors,
        "group_dm_envelope",
        group_dm_envelope_signing_bytes(
            s(&i["conversation_id"]),
            n32(&i["sender_key_version"]),
            n32(&i["iteration"]),
            s(&i["ciphertext"]),
            s(&i["nonce"]),
        ),
    );
    let i = vectors.vector("sender_key_dist")["inputs"].clone();
    let recipients: Vec<(String, String)> = i["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (s(&r[0]).to_string(), s(&r[1]).to_string()))
        .collect();
    check_signed(
        &vectors,
        "sender_key_dist",
        sender_key_dist_signing_bytes(s(&i["conversation_id"]), n32(&i["version"]), &recipients),
    );
    let i = vectors.vector("dm_member_change")["inputs"].clone();
    let list = |k: &str| -> Vec<String> {
        i[k].as_array()
            .unwrap()
            .iter()
            .map(|x| s(x).to_string())
            .collect()
    };
    check_signed(
        &vectors,
        "dm_member_change",
        dm_member_change_signing_bytes(
            s(&i["conversation_id"]),
            s(&i["actor"]),
            &list("added"),
            &list("removed"),
            i["timestamp"].as_u64().unwrap(),
        ),
    );
    let i = vectors.vector("federated_plaintext_dm_v2")["inputs"].clone();
    let members: Vec<String> = i["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| s(x).to_string())
        .collect();
    check_signed(
        &vectors,
        "federated_plaintext_dm_v2",
        federated_plaintext_dm_v2_signing_bytes(
            s(&i["conversation_id"]),
            s(&i["kind"]),
            s(&i["content"]),
            s(&i["message_id"]),
            i["created_at"].as_u64().unwrap(),
            &members,
        ),
    );
    let v = vectors.vector("subkey_cert");
    let i = &v["inputs"];
    let cert = SubkeyCert {
        master_pubkey: s(&i["master_pubkey"]).into(),
        subkey_pubkey: s(&i["subkey_pubkey"]).into(),
        device_label: s(&i["device_label"]).into(),
        issued_at: i["issued_at"].as_u64().unwrap(),
        not_after: None,
        fallback_hubs: vec![],
        signature: s(&v["signature"]).into(),
    };
    assert_eq!(hex::encode(cert.to_signing_bytes()), s(&v["signing_bytes"]));
    cert.verify().unwrap();
}

#[test]
fn dm_key_v1() {
    use wavvon_identity::dm::*;
    let Some(vectors) = load() else { return };
    let v = vectors.vector("dm_key_v1");
    let i = &v["inputs"];
    let (a, a_pub) = dh_pair(&i["alice_seed"]);
    let (b, b_pub) = dh_pair(&i["bob_seed"]);
    let conv = s(&i["conversation_id"]);
    let key = dm_key_v1(&a, &b_pub, conv);
    assert_eq!(key, dm_key_v1(&b, &a_pub, conv));
    assert_eq!(hex::encode(key), s(&v["key"]));
    let nonce: [u8; 12] = unhex(&i["nonce"]).try_into().unwrap();
    let plaintext = s(&i["plaintext"]).as_bytes();
    let ct = dm_v1_seal(&key, &nonce, plaintext).unwrap();
    assert_eq!(hex::encode(&ct), s(&v["ciphertext"]));
    assert_eq!(dm_v1_open(&key, &nonce, &ct).unwrap(), plaintext);
}

#[test]
fn dr_session() {
    use wavvon_identity::dm::*;
    let Some(vectors) = load() else { return };
    let v = vectors.vector("dr_session");
    let i = &v["inputs"];
    let (a, a_pub) = dh_pair(&i["alice_seed"]);
    let (b, b_pub) = dh_pair(&i["bob_seed"]);
    let conv = s(&i["conversation_id"]);
    let (a_eph, b_eph) = (b32(&i["alice_eph_secret"]), b32(&i["bob_eph_secret"]));
    let want = |k: &str| s(&v[k]).to_string();

    let rk0 = dr_root_key(&a, &b_pub, conv);
    assert_eq!(rk0, dr_root_key(&b, &a_pub, conv));
    assert_eq!(hex::encode(rk0), want("rk0"));
    let alice = dr_initiator_init(&a, &b_pub, conv, &a_eph);
    assert_eq!(hex::encode(alice.eph_pub), want("alice_eph_pub"));
    assert_eq!(hex::encode(alice.rk), want("alice_rk"));
    assert_eq!(hex::encode(alice.cks), want("alice_cks"));
    let (mk, next) = dr_kdf_ck(&alice.cks);
    assert_eq!(hex::encode(mk), want("message_key"));
    assert_eq!(hex::encode(dr_derive_nonce(&mk)), want("nonce"));
    assert_eq!(hex::encode(next), want("next_cks"));
    let ct = dr_message_seal(&mk, s(&i["plaintext"]).as_bytes()).unwrap();
    assert_eq!(hex::encode(&ct), want("ciphertext"));

    let bob = dr_responder_init(&b, &a_pub, conv, &alice.eph_pub, &b_eph);
    assert_eq!(hex::encode(bob.rk), want("bob_rk"));
    assert_eq!(hex::encode(bob.ckr), want("bob_ckr"));
    assert_eq!(hex::encode(bob.cks), want("bob_cks"));
    assert_eq!(hex::encode(bob.eph_pub), want("bob_eph_pub"));
    let (reply_mk, _) = dr_kdf_ck(&bob.cks);
    assert_eq!(hex::encode(reply_mk), want("reply_message_key"));
    let reply = dr_message_seal(&reply_mk, s(&i["reply_plaintext"]).as_bytes()).unwrap();
    assert_eq!(hex::encode(&reply), want("reply_ciphertext"));
    let (step_rk, step_ckr) = dr_kdf_rk(&alice.rk, &dr_dh(&a_eph, &x_pub(&b_eph)));
    assert_eq!(hex::encode(step_rk), want("reply_step_rk"));
    assert_eq!(hex::encode(step_ckr), want("reply_step_ckr"));
}

#[test]
fn group_ratchet_and_key_wrap() {
    use wavvon_identity::dm::*;
    let Some(vectors) = load() else { return };
    let v = vectors.vector("group_ratchet");
    let i = &v["inputs"];
    let ck = b32(&i["chain_key"]);
    let it = n32(&i["iteration"]);
    assert_eq!(hex::encode(group_msg_key(&ck, it)), s(&v["message_key"]));
    assert_eq!(
        hex::encode(group_next_chain_key(&ck, it)),
        s(&v["next_chain_key"])
    );
    let (ct, nonce, _) = group_message_seal(&ck, it, s(&i["plaintext"]).as_bytes()).unwrap();
    assert_eq!(hex::encode(nonce), s(&v["nonce"]));
    assert_eq!(hex::encode(&ct), s(&v["ciphertext"]));

    let v = vectors.vector("group_key_wrap");
    let i = &v["inputs"];
    let (a, a_pub) = dh_pair(&i["sender_seed"]);
    let (b, b_pub) = dh_pair(&i["recipient_seed"]);
    let conv = s(&i["conversation_id"]);
    let nonce: [u8; 12] = unhex(&i["nonce"]).try_into().unwrap();
    let (chain, iteration) = (b32(&i["chain_key"]), n32(&i["iteration"]));
    let wrapped = group_key_wrap(&a, &b_pub, conv, &chain, iteration, &nonce).unwrap();
    assert_eq!(hex::encode(&wrapped), s(&v["ciphertext"]));
    let back = group_key_unwrap(&b, &a_pub, conv, &nonce, &wrapped).unwrap();
    assert_eq!(back, (chain, iteration));
}
