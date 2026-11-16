//! End-to-end encrypted DMs for a program (sdk-dm.md): 1:1 double ratchet
//! (v2 send, v2 and v1 receive) and group sender keys. The crypto is
//! `wavvon_identity::dm`; this module keeps the sessions and drives the REST
//! endpoints. Nothing here ever falls back to plaintext: that is the separate,
//! explicit [`Dms::send_plaintext`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use rand::RngExt;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wavvon_identity::dm as crypto;
use wavvon_identity::{
    dm_envelope_signing_bytes, dm_member_change_signing_bytes, dr_envelope_signing_bytes,
    federated_plaintext_dm_signing_bytes, federated_plaintext_dm_v2_signing_bytes,
    group_dm_envelope_signing_bytes, sender_key_dist_signing_bytes, verify_signature, SubkeyCert,
};

use crate::client::{encode, ok_or_status, Client};
use crate::dh::key32;
use crate::error::{DmError, Error, Result};
use crate::events::Event;
use crate::store::{get_json, put_json, StateStore};

const MAX_SKIP: usize = 1000;
const PLAIN_CACHE: usize = 2048;
const SEEN_CAP: usize = 4096;

/// State shared by every clone of a [`Client`]: one lock so a ratchet is
/// never advanced by two tasks at once, a cache of what was already
/// decrypted, and which messages `poll` has handed out.
#[derive(Default)]
pub(crate) struct Shared {
    lock: tokio::sync::Mutex<()>,
    plain: Mutex<Cache>,
    seen: Mutex<Seen>,
}

// A ratchet message key is used once, so reading a message a second time
// needs the plaintext kept from the first. Bounded; a restart forgets it.
#[derive(Default)]
struct Cache {
    map: HashMap<String, DmPlaintext>,
    order: VecDeque<String>,
}

#[derive(Default)]
struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
}

/// What a DM carries inside its ciphertext.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DmPlaintext {
    #[serde(default)]
    pub content: String,
    /// Attachment descriptors as the clients write them. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Value>,
}

impl DmPlaintext {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            attachments: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Conversation {
    pub id: String,
    /// `"dm"` for 1:1, `"group"` otherwise.
    pub conv_type: String,
    pub members: Vec<String>,
}

/// One message of a conversation as read. `content` is per message: a program
/// keeps going past one it cannot read. A row the hub stored in the clear has
/// `encrypted == false`; what to do about that is the program's call.
#[derive(Debug)]
pub struct DmMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub created_at: i64,
    pub encrypted: bool,
    pub content: Result<DmPlaintext>,
}

/// Who got a group sender key and who was skipped (no DH key, a changed key).
/// A skipped member cannot read messages under that key.
#[derive(Debug)]
pub struct Distribution {
    pub version: u32,
    pub delivered: Vec<String>,
    pub skipped: Vec<(String, Error)>,
}

#[derive(Debug)]
pub struct Sent {
    pub id: String,
    pub created_at: i64,
    /// Set when this send created the group sender key first.
    pub distribution: Option<Distribution>,
}

#[derive(Clone, Debug, Default)]
pub struct MessagesPage {
    /// 1..=100, the hub's default when unset.
    pub limit: Option<u32>,
    /// Page backwards: the `id` of the oldest message already held.
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
struct Row {
    id: String,
    conversation_id: String,
    sender: String,
    #[serde(default)]
    sender_name: Option<String>,
    #[serde(default)]
    content: Option<String>,
    created_at: i64,
    #[serde(default)]
    attachments: Vec<Value>,
    #[serde(default)]
    encrypted_envelope: Option<Value>,
    #[serde(default)]
    group_encrypted_envelope: Option<Value>,
}

// ---------------------------------------------------------------------------
// Double ratchet session (the persisted shape matches the desktop client's)
// ---------------------------------------------------------------------------

#[derive(Clone, Default, Serialize, Deserialize)]
struct DrSession {
    rk: String,
    cks: Option<String>,
    ckr: Option<String>,
    ns: u32,
    nr: u32,
    pn: u32,
    dhs_priv: String,
    dhs_pub: String,
    dhr: Option<String>,
    mkskipped: HashMap<String, String>,
}

fn h32(s: &str) -> std::result::Result<[u8; 32], DmError> {
    key32(s).ok_or_else(|| DmError::Malformed("expected 32 bytes of hex".into()))
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rng().fill(&mut b);
    b
}

fn x_pub(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*secret, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn crypto_err(e: impl std::fmt::Display) -> DmError {
    DmError::Crypto(e.to_string())
}

impl DrSession {
    fn initiator(my_static: &[u8; 32], their_static: &[u8; 32], conv: &str, eph: [u8; 32]) -> Self {
        let init = crypto::dr_initiator_init(my_static, their_static, conv, &eph);
        Self {
            rk: hex::encode(init.rk),
            cks: Some(hex::encode(init.cks)),
            dhs_priv: hex::encode(eph),
            dhs_pub: hex::encode(init.eph_pub),
            ..Self::default()
        }
    }

    fn responder(
        my_static: &[u8; 32],
        their_static: &[u8; 32],
        conv: &str,
        incoming_dhr: &str,
        eph: [u8; 32],
    ) -> std::result::Result<Self, DmError> {
        let init =
            crypto::dr_responder_init(my_static, their_static, conv, &h32(incoming_dhr)?, &eph);
        Ok(Self {
            rk: hex::encode(init.rk),
            cks: Some(hex::encode(init.cks)),
            ckr: Some(hex::encode(init.ckr)),
            dhs_priv: hex::encode(eph),
            dhs_pub: hex::encode(init.eph_pub),
            dhr: Some(incoming_dhr.to_string()),
            ..Self::default()
        })
    }

    /// Seals `plaintext`; returns `(ciphertext, message_index, prev_count)`
    /// and advances the sending chain.
    fn seal(&mut self, plaintext: &[u8]) -> std::result::Result<(Vec<u8>, u32, u32), DmError> {
        let cks = self.cks.as_deref().ok_or(DmError::NoSession)?;
        let (mk, next) = crypto::dr_kdf_ck(&h32(cks)?);
        let ct = crypto::dr_message_seal(&mk, plaintext).map_err(crypto_err)?;
        let out = (ct, self.ns, self.pn);
        self.cks = Some(hex::encode(next));
        self.ns += 1;
        Ok(out)
    }

    /// The receive algorithm of e2e-encryption.md "1:1 DM Encryption - v2":
    /// skipped-key cache, DH-ratchet step on a new remote key, chain advance.
    /// The caller works on a copy and keeps it only on success.
    fn open(
        &mut self,
        dh_pub: &str,
        index: u32,
        prev: u32,
        ct: &[u8],
    ) -> std::result::Result<Vec<u8>, DmError> {
        if let Some(mk) = self.mkskipped.remove(&format!("{dh_pub}:{index}")) {
            return crypto::dr_message_open(&h32(&mk)?, ct).map_err(|_| DmError::DecryptionFailed);
        }
        if self.dhr.as_deref() != Some(dh_pub) {
            if let Some(ckr) = self.ckr.clone() {
                let old = self.dhr.clone().unwrap_or_default();
                self.skip(&old, h32(&ckr)?, self.nr, prev)?;
            }
            let their = h32(dh_pub)?;
            let (rk, ckr) = crypto::dr_kdf_rk(
                &h32(&self.rk)?,
                &crypto::dr_dh(&h32(&self.dhs_priv)?, &their),
            );
            let new_priv = random32();
            let (rk, cks) = crypto::dr_kdf_rk(&rk, &crypto::dr_dh(&new_priv, &their));
            self.rk = hex::encode(rk);
            self.cks = Some(hex::encode(cks));
            self.pn = self.ns;
            self.ns = 0;
            self.nr = 0;
            self.dhr = Some(dh_pub.to_string());
            self.ckr = Some(hex::encode(ckr));
            self.dhs_priv = hex::encode(new_priv);
            self.dhs_pub = hex::encode(x_pub(&new_priv));
        }
        let ckr = h32(self.ckr.as_deref().ok_or(DmError::NoSession)?)?;
        let ckr = self.skip(dh_pub, ckr, self.nr, index)?;
        let (mk, next) = crypto::dr_kdf_ck(&ckr);
        let plain = crypto::dr_message_open(&mk, ct).map_err(|_| DmError::DecryptionFailed)?;
        self.ckr = Some(hex::encode(next));
        self.nr = index + 1;
        Ok(plain)
    }

    /// Caches the message keys of chain `dh` from `from` up to (not
    /// including) `to`; returns the chain key at `to`.
    fn skip(
        &mut self,
        dh: &str,
        mut ck: [u8; 32],
        from: u32,
        to: u32,
    ) -> std::result::Result<[u8; 32], DmError> {
        if self.mkskipped.len() + to.saturating_sub(from) as usize > MAX_SKIP {
            return Err(DmError::TooManySkipped);
        }
        for n in from..to {
            let (mk, next) = crypto::dr_kdf_ck(&ck);
            self.mkskipped.insert(format!("{dh}:{n}"), hex::encode(mk));
            ck = next;
        }
        Ok(ck)
    }
}

// ---------------------------------------------------------------------------
// Group sender chains
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct GroupOwn {
    version: u32,
    chain_key: String,
    iteration: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct GroupPeer {
    chain_key: String,
    iteration: u32,
}

// ---------------------------------------------------------------------------
// Envelope checks
// ---------------------------------------------------------------------------

/// Whether `sender` (the member the hub names) signed this envelope:
/// directly, or through a device whose `SubkeyCert` `sender` issued. The hub
/// checked too; a program does not rely on that.
fn verify_envelope(conv: &str, env: &Value, sender: &str) -> std::result::Result<(), DmError> {
    let bad = DmError::NotSignedBySender;
    let text = |k: &str| env[k].as_str().unwrap_or_default();
    let int = |k: &str| env[k].as_u64().and_then(|v| u32::try_from(v).ok());
    if text("sender_pubkey") != sender {
        return Err(bad);
    }
    let signed = if env.get("sender_key_version").is_some() {
        let (Some(version), Some(iteration)) = (int("sender_key_version"), int("iteration")) else {
            return Err(bad);
        };
        group_dm_envelope_signing_bytes(
            conv,
            version,
            iteration,
            text("ciphertext_hex"),
            text("nonce_hex"),
        )
    } else if env["v"].as_u64() == Some(2) {
        let (Some(index), Some(prev)) = (int("message_index"), int("prev_count")) else {
            return Err(bad);
        };
        dr_envelope_signing_bytes(
            conv,
            index,
            prev,
            text("ciphertext_hex"),
            text("dh_pubkey_hex"),
        )
    } else {
        dm_envelope_signing_bytes(
            conv,
            text("ciphertext_hex"),
            text("nonce_hex"),
            text("dh_pubkey_hex"),
        )
    };
    let sig = hex::decode(text("signature_hex")).map_err(|_| DmError::NotSignedBySender)?;
    let signer = match env.get("signer_cert").filter(|c| !c.is_null()) {
        None => sender.to_string(),
        Some(cert) => {
            let cert: SubkeyCert =
                serde_json::from_value(cert.clone()).map_err(|_| DmError::NotSignedBySender)?;
            if cert.master_pubkey != sender || cert.verify().is_err() {
                return Err(DmError::NotSignedBySender);
            }
            cert.subkey_pubkey
        }
    };
    verify_signature(&signer, &signed, &sig).map_err(|_| DmError::NotSignedBySender)
}

fn parse_plaintext(bytes: &[u8]) -> std::result::Result<DmPlaintext, DmError> {
    serde_json::from_slice(bytes).map_err(|e| DmError::Malformed(format!("plaintext JSON: {e}")))
}

fn hex_field(env: &Value, k: &str) -> std::result::Result<Vec<u8>, DmError> {
    hex::decode(env[k].as_str().unwrap_or_default())
        .map_err(|_| DmError::Malformed(format!("{k} is not hex")))
}

fn u32_field(env: &Value, k: &str) -> std::result::Result<u32, DmError> {
    env[k]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| DmError::Malformed(format!("{k} missing")))
}

/// Errors that belong to one message, not to the call that read it.
pub(crate) fn per_message(e: &Error) -> bool {
    matches!(
        e,
        Error::Dm(_)
            | Error::RecipientHasNoKey { .. }
            | Error::DhKeyChanged { .. }
            | Error::DhKeyUnsigned { .. }
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The API
// ---------------------------------------------------------------------------

impl Client {
    /// E2E DMs. Publish the DH key first ([`Client::publish_dh_key`]).
    pub fn dms(&self) -> Dms {
        Dms {
            client: self.clone(),
        }
    }
}

/// A program's DMs. Cheap to clone; clones share the session and the state.
#[derive(Clone)]
pub struct Dms {
    client: Client,
}

impl Dms {
    fn me(&self) -> String {
        self.client.public_key()
    }

    fn store(&self) -> &dyn StateStore {
        self.client.store()
    }

    pub async fn conversation(&self, id: &str) -> Result<Conversation> {
        self.client
            .json(
                Method::GET,
                &format!("/conversations/{}", encode(id)),
                &[],
                None,
                true,
            )
            .await
    }

    /// Every conversation, paged to exhaustion where the hub pages
    /// (`list.cursor.lists`).
    pub async fn conversations(&self) -> Result<Vec<Conversation>> {
        let paged = self.client.capabilities().has("list.cursor.lists");
        let mut out: Vec<Conversation> = Vec::new();
        loop {
            let mut query = Vec::new();
            if paged {
                query.push(("limit", "500".to_string()));
                if let Some(last) = out.last() {
                    query.push(("cursor", last.id.clone()));
                }
            }
            let page: Vec<Conversation> = self
                .client
                .json(Method::GET, "/conversations", &query, None, true)
                .await?;
            let n = page.len();
            out.extend(page);
            if !paged || n < 500 {
                return Ok(out);
            }
        }
    }

    /// `members` are the others; the hub adds the caller. A 1:1 with a
    /// member you already talk to is returned, not duplicated.
    pub async fn create_conversation(&self, members: &[String]) -> Result<Conversation> {
        self.client
            .json(
                Method::POST,
                "/conversations",
                &[],
                Some(&json!({ "members": members })),
                true,
            )
            .await
    }

    pub async fn send_text(&self, conv: &str, text: &str) -> Result<Sent> {
        self.send(conv, &DmPlaintext::text(text)).await
    }

    /// Encrypts and sends: the double ratchet in a 1:1, the sender-key chain
    /// in a group. Fails with `RecipientHasNoKey` or `DhKeyChanged` rather
    /// than ever sending in the clear.
    pub async fn send(&self, conv: &str, message: &DmPlaintext) -> Result<Sent> {
        let _guard = self.client.dm_shared().lock.lock().await;
        let c = self.conversation(conv).await?;
        let plaintext = serde_json::to_vec(message).map_err(|e| Error::Request(e.to_string()))?;
        let (body, distribution) = if c.conv_type == "dm" {
            (self.seal_dr(&c, &plaintext).await?, None)
        } else {
            self.seal_group(&c, &plaintext).await?
        };
        let created = self.post_message(conv, &body).await?;
        Ok(Sent {
            distribution,
            ..created
        })
    }

    /// The explicit, signed plaintext DM. Whether to ever call it is the
    /// program's decision; `send` never does.
    pub async fn send_plaintext(&self, conv: &str, content: &str) -> Result<Sent> {
        let c = self.conversation(conv).await?;
        let v2 = self.client.capabilities().has("dms.plaintext.v2");
        let message_id = {
            let mut b = [0u8; 16];
            rand::rng().fill(&mut b);
            uuid::Builder::from_random_bytes(b).into_uuid().to_string()
        };
        let created_at = unix_now();
        let signing = if v2 {
            federated_plaintext_dm_v2_signing_bytes(
                conv,
                &c.conv_type,
                content,
                &message_id,
                created_at,
                &c.members,
            )
        } else {
            federated_plaintext_dm_signing_bytes(conv, &c.conv_type, content)
        };
        let mut body = json!({
            "content": content,
            "attachments": [],
            "plaintext_signature": self.client.identity().sign_hex(&signing),
        });
        if v2 {
            body["message_id"] = json!(message_id);
            body["created_at"] = json!(created_at);
        }
        self.post_message(conv, &body).await
    }

    async fn post_message(&self, conv: &str, body: &Value) -> Result<Sent> {
        let v: Value = self
            .client
            .json(
                Method::POST,
                &format!("/conversations/{}/messages", encode(conv)),
                &[],
                Some(body),
                true,
            )
            .await?;
        Ok(Sent {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            created_at: v["created_at"].as_i64().unwrap_or_default(),
            distribution: None,
        })
    }

    // ---- 1:1 send ----

    async fn seal_dr(&self, c: &Conversation, plaintext: &[u8]) -> Result<Value> {
        let me = self.me();
        let peer = c
            .members
            .iter()
            .find(|m| **m != me)
            .ok_or_else(|| DmError::Malformed("conversation has no other member".into()))?;
        let key = format!("dr/{}", c.id);
        let mut session = match get_json::<DrSession>(self.store(), &key)? {
            Some(s) => s,
            None => {
                let their = self.client.peer_dh_key(peer).await?;
                DrSession::initiator(
                    &self.client.identity().dh_secret(),
                    &their,
                    &c.id,
                    random32(),
                )
            }
        };
        let dh_pub = session.dhs_pub.clone();
        let (ct, index, prev) = session.seal(plaintext)?;
        // Persisted before the POST: a key is never used twice, and a failed
        // send leaves a gap the receiver skips over.
        put_json(self.store(), &key, &session)?;
        let ct_hex = hex::encode(ct);
        let signature = self.client.identity().sign_hex(&dr_envelope_signing_bytes(
            &c.id, index, prev, &ct_hex, &dh_pub,
        ));
        Ok(json!({ "encrypted_envelope": {
            "sender_pubkey": me,
            "conv_id": c.id,
            "ciphertext_hex": ct_hex,
            "nonce_hex": "",
            "dh_pubkey_hex": dh_pub,
            "signature_hex": signature,
            "v": 2,
            "message_index": index,
            "prev_count": prev,
        }}))
    }

    // ---- group send ----

    async fn seal_group(
        &self,
        c: &Conversation,
        plaintext: &[u8],
    ) -> Result<(Value, Option<Distribution>)> {
        let own_key = format!("group-own/{}", c.id);
        let (mut own, distribution) = match get_json::<GroupOwn>(self.store(), &own_key)? {
            Some(o) => (o, None),
            None => {
                let (own, dist) = self.new_chain(c, 1).await?;
                (own, Some(dist))
            }
        };
        let iteration = own.iteration;
        let (ct, nonce, next) =
            crypto::group_message_seal(&h32(&own.chain_key)?, iteration, plaintext)
                .map_err(crypto_err)?;
        let version = own.version;
        own.chain_key = hex::encode(next);
        own.iteration += 1;
        put_json(self.store(), &own_key, &own)?;
        let (ct_hex, nonce_hex) = (hex::encode(ct), hex::encode(nonce));
        let signature = self
            .client
            .identity()
            .sign_hex(&group_dm_envelope_signing_bytes(
                &c.id, version, iteration, &ct_hex, &nonce_hex,
            ));
        Ok((
            json!({ "group_encrypted_envelope": {
                "sender_pubkey": self.me(),
                "conv_id": c.id,
                "sender_key_version": version,
                "iteration": iteration,
                "ciphertext_hex": ct_hex,
                "nonce_hex": nonce_hex,
                "signature_hex": signature,
            }}),
            distribution,
        ))
    }

    /// A fresh chain at `version`, distributed to every other member, stored
    /// once the hub accepted the distribution.
    async fn new_chain(&self, c: &Conversation, version: u32) -> Result<(GroupOwn, Distribution)> {
        let own = GroupOwn {
            version,
            chain_key: hex::encode(random32()),
            iteration: 0,
        };
        let dist = self.distribute(c, &own).await?;
        put_json(self.store(), &format!("group-own/{}", c.id), &own)?;
        Ok((own, dist))
    }

    async fn distribute(&self, c: &Conversation, own: &GroupOwn) -> Result<Distribution> {
        let me = self.me();
        let my_dh = self.client.identity().dh_secret();
        let chain_key = h32(&own.chain_key)?;
        let (mut delivered, mut skipped, mut blobs, mut pairs) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for member in c.members.iter().filter(|m| **m != me) {
            let their = match self.client.peer_dh_key(member).await {
                Ok(k) => k,
                Err(e) if per_message(&e) => {
                    skipped.push((member.clone(), e));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let mut nonce = [0u8; 12];
            rand::rng().fill(&mut nonce);
            let wrapped = hex::encode(
                crypto::group_key_wrap(&my_dh, &their, &c.id, &chain_key, own.iteration, &nonce)
                    .map_err(crypto_err)?,
            );
            blobs.push(json!({
                "recipient_pubkey": member,
                "wrapped_key_hex": wrapped,
                "wrap_nonce_hex": hex::encode(nonce),
                "iteration": own.iteration,
            }));
            pairs.push((member.clone(), wrapped));
            delivered.push(member.clone());
        }
        let signature = self
            .client
            .identity()
            .sign_hex(&sender_key_dist_signing_bytes(&c.id, own.version, &pairs));
        let resp = self
            .client
            .execute(
                Method::PUT,
                &format!("/conversations/{}/sender-keys", encode(&c.id)),
                &[],
                Some(&json!({
                    "sender_key_version": own.version,
                    "recipients": blobs,
                    "signature_hex": signature,
                })),
                true,
            )
            .await?;
        ok_or_status(resp).await?;
        Ok(Distribution {
            version: own.version,
            delivered,
            skipped,
        })
    }

    /// New sender key (`version + 1`), re-distributed to the members now in
    /// the conversation, so someone who left cannot read what follows. Earlier
    /// messages stay readable: peers keep a chain per version.
    pub async fn rotate_group_key(&self, conv: &str) -> Result<Distribution> {
        let _guard = self.client.dm_shared().lock.lock().await;
        let c = self.conversation(conv).await?;
        let old = get_json::<GroupOwn>(self.store(), &format!("group-own/{conv}"))?;
        Ok(self
            .new_chain(&c, old.map_or(1, |o| o.version + 1))
            .await?
            .1)
    }

    /// Rotates the sender key on `dm_member_changed` when this program has
    /// one for that conversation; a no-op for every other event. Call it with
    /// the events you read, or call [`Dms::rotate_group_key`] yourself.
    pub async fn handle_event(&self, event: &Event) -> Result<Option<Distribution>> {
        let Event::DmMemberChanged {
            conversation_id, ..
        } = event
        else {
            return Ok(None);
        };
        if get_json::<GroupOwn>(self.store(), &format!("group-own/{conversation_id}"))?.is_none() {
            return Ok(None);
        }
        self.rotate_group_key(conversation_id).await.map(Some)
    }

    /// The signed membership change the hub's `dms.group.signedmembers`
    /// wants; `None` on a hub without it.
    fn signed_change(&self, conv: &str, added: &[String], removed: &[String]) -> Option<Value> {
        if !self.client.capabilities().has("dms.group.signedmembers") {
            return None;
        }
        let issued_at = unix_now();
        let signing = dm_member_change_signing_bytes(conv, &self.me(), added, removed, issued_at);
        Some(json!({
            "issued_at": issued_at,
            "signature": self.client.identity().sign_hex(&signing),
        }))
    }

    /// Adds members (one request each, as the hub takes them), then rotates
    /// the sender key if this program holds one.
    pub async fn add_members(&self, conv: &str, members: &[String]) -> Result<()> {
        for member in members {
            let mut body = json!({ "public_key": member });
            if let Some(signed) = self.signed_change(conv, std::slice::from_ref(member), &[]) {
                body["signed"] = signed;
            }
            let resp = self
                .client
                .execute(
                    Method::POST,
                    &format!("/conversations/{}/members", encode(conv)),
                    &[],
                    Some(&body),
                    true,
                )
                .await?;
            ok_or_status(resp).await?;
        }
        if get_json::<GroupOwn>(self.store(), &format!("group-own/{conv}"))?.is_some() {
            self.rotate_group_key(conv).await?;
        }
        Ok(())
    }

    /// Leaves a group. The hub lets a member remove only themselves.
    pub async fn leave(&self, conv: &str) -> Result<()> {
        let me = self.me();
        let body = self.signed_change(conv, &[], std::slice::from_ref(&me));
        let resp = self
            .client
            .execute(
                Method::DELETE,
                &format!("/conversations/{}/members/{}", encode(conv), encode(&me)),
                &[],
                body.as_ref(),
                true,
            )
            .await?;
        ok_or_status(resp).await.map(|_| ())
    }

    // ---- receive ----

    /// A page of a conversation, oldest first, each message decrypted.
    /// Transient hub failures are the call's error; a message that cannot be
    /// read is that message's `content`.
    pub async fn messages(&self, conv: &str, page: &MessagesPage) -> Result<Vec<DmMessage>> {
        let mut query = Vec::new();
        if let Some(l) = page.limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = &page.cursor {
            query.push(("cursor", c.clone()));
        }
        let rows = self.rows(conv, &query).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(self.read_row(conv, row).await?);
        }
        Ok(out)
    }

    /// Messages this handle has not returned yet, oldest first. The first
    /// call for a conversation returns its newest page, so a program that
    /// only wants what arrives from now on calls [`Dms::skip_existing`] first.
    /// The hub's `dm` event says a message arrived; this fetches it.
    pub async fn poll(&self, conv: &str) -> Result<Vec<DmMessage>> {
        let mut out = Vec::new();
        for row in self.rows(conv, &[("limit", "100".to_string())]).await? {
            if self.is_seen(&row.id) {
                continue;
            }
            let id = row.id.clone();
            out.push(self.read_row(conv, row).await?);
            self.mark_seen(&id);
        }
        Ok(out)
    }

    /// Marks what is in the conversation now as delivered, without decrypting
    /// it: [`Dms::poll`] then returns only later messages.
    pub async fn skip_existing(&self, conv: &str) -> Result<()> {
        for row in self.rows(conv, &[("limit", "100".to_string())]).await? {
            self.mark_seen(&row.id);
        }
        Ok(())
    }

    async fn rows(&self, conv: &str, query: &[(&str, String)]) -> Result<Vec<Row>> {
        let rows: Vec<Value> = self
            .client
            .json(
                Method::GET,
                &format!("/conversations/{}/messages", encode(conv)),
                query,
                None,
                true,
            )
            .await?;
        rows.into_iter()
            .map(|raw| {
                serde_json::from_value(raw).map_err(|e| Error::Decode(format!("DM row: {e}")))
            })
            .collect()
    }

    fn is_seen(&self, id: &str) -> bool {
        let seen = self
            .client
            .dm_shared()
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        seen.set.contains(id)
    }

    fn mark_seen(&self, id: &str) {
        let mut seen = self
            .client
            .dm_shared()
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if seen.set.insert(id.to_string()) {
            seen.order.push_back(id.to_string());
            if seen.order.len() > SEEN_CAP {
                if let Some(old) = seen.order.pop_front() {
                    seen.set.remove(&old);
                }
            }
        }
    }

    async fn read_row(&self, conv: &str, row: Row) -> Result<DmMessage> {
        let encrypted = row.encrypted_envelope.is_some() || row.group_encrypted_envelope.is_some();
        let content = match self.open_row(conv, &row).await {
            Err(e) if !per_message(&e) => return Err(e),
            other => other,
        };
        Ok(DmMessage {
            id: row.id,
            conversation_id: row.conversation_id,
            sender: row.sender,
            sender_name: row.sender_name,
            created_at: row.created_at,
            encrypted,
            content,
        })
    }

    async fn open_row(&self, conv: &str, row: &Row) -> Result<DmPlaintext> {
        let shared = self.client.dm_shared();
        if let Some(hit) = shared
            .plain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&row.id)
        {
            return Ok(hit.clone());
        }
        let _guard = shared.lock.lock().await;
        let plain = if let Some(env) = &row.encrypted_envelope {
            verify_envelope(conv, env, &row.sender)?;
            if row.sender == self.me() {
                return Err(DmError::OwnMessage.into());
            }
            let bytes = if env["v"].as_u64() == Some(2) {
                self.open_dr(conv, env, &row.sender).await?
            } else {
                self.open_v1(conv, env)?
            };
            parse_plaintext(&bytes)?
        } else if let Some(env) = &row.group_encrypted_envelope {
            verify_envelope(conv, env, &row.sender)?;
            if row.sender == self.me() {
                return Err(DmError::OwnMessage.into());
            }
            parse_plaintext(&self.open_group(conv, env, &row.sender).await?)?
        } else {
            DmPlaintext {
                content: row.content.clone().unwrap_or_default(),
                attachments: row.attachments.clone(),
            }
        };
        let mut cache = shared.plain.lock().unwrap_or_else(|e| e.into_inner());
        if cache.map.insert(row.id.clone(), plain.clone()).is_none() {
            cache.order.push_back(row.id.clone());
            if cache.order.len() > PLAIN_CACHE {
                if let Some(old) = cache.order.pop_front() {
                    cache.map.remove(&old);
                }
            }
        }
        Ok(plain)
    }

    fn open_v1(&self, conv: &str, env: &Value) -> Result<Vec<u8>> {
        let their = key32(env["dh_pubkey_hex"].as_str().unwrap_or_default())
            .ok_or_else(|| DmError::Malformed("dh_pubkey_hex".into()))?;
        let key = crypto::dm_key_v1(&self.client.identity().dh_secret(), &their, conv);
        crypto::dm_v1_open(
            &key,
            &hex_field(env, "nonce_hex")?,
            &hex_field(env, "ciphertext_hex")?,
        )
        .map_err(|_| DmError::DecryptionFailed.into())
    }

    async fn open_dr(&self, conv: &str, env: &Value, sender: &str) -> Result<Vec<u8>> {
        let key = format!("dr/{conv}");
        let dh_pub = env["dh_pubkey_hex"].as_str().unwrap_or_default();
        let mut session = match get_json::<DrSession>(self.store(), &key)? {
            Some(s) => s,
            None => {
                // First inbound message of a conversation this side never
                // sent in: responder-init from the sender's published key.
                let their = self.client.peer_dh_key(sender).await?;
                DrSession::responder(
                    &self.client.identity().dh_secret(),
                    &their,
                    conv,
                    dh_pub,
                    random32(),
                )?
            }
        };
        let plain = session.open(
            dh_pub,
            u32_field(env, "message_index")?,
            env["prev_count"].as_u64().unwrap_or(0) as u32,
            &hex_field(env, "ciphertext_hex")?,
        )?;
        put_json(self.store(), &key, &session)?;
        Ok(plain)
    }

    async fn open_group(&self, conv: &str, env: &Value, sender: &str) -> Result<Vec<u8>> {
        let version = u32_field(env, "sender_key_version")?;
        let iteration = u32_field(env, "iteration")?;
        let key = format!("group-peer/{conv}/{sender}/{version}");
        let mut chain = get_json::<GroupPeer>(self.store(), &key)?;
        if chain.is_none() {
            self.refresh_sender_keys(conv).await?;
            chain = get_json(self.store(), &key)?;
        }
        let chain = chain.ok_or_else(|| DmError::KeyNotFound {
            sender: sender.to_string(),
            version,
        })?;
        if chain.iteration > iteration {
            return Err(DmError::ChainAdvancedPastMessage.into());
        }
        crypto::group_message_open(
            &h32(&chain.chain_key)?,
            chain.iteration,
            iteration,
            &hex_field(env, "nonce_hex")?,
            &hex_field(env, "ciphertext_hex")?,
        )
        .map_err(|_| DmError::DecryptionFailed.into())
    }

    /// Unwraps the sender keys the hub holds for this program and stores the
    /// ones not held yet. A sender whose DH key is missing or changed is
    /// skipped: its messages then report `KeyNotFound`.
    async fn refresh_sender_keys(&self, conv: &str) -> Result<()> {
        let entries: Vec<Value> = self
            .client
            .json(
                Method::GET,
                &format!("/conversations/{}/sender-keys", encode(conv)),
                &[],
                None,
                true,
            )
            .await?;
        let my_dh = self.client.identity().dh_secret();
        for e in entries {
            let (Some(sender), Some(version), Some(wrapped), Some(nonce)) = (
                e["sender_pubkey"].as_str(),
                e["sender_key_version"].as_u64(),
                e["wrapped_key_hex"]
                    .as_str()
                    .and_then(|h| hex::decode(h).ok()),
                e["wrap_nonce_hex"]
                    .as_str()
                    .and_then(|h| hex::decode(h).ok()),
            ) else {
                continue;
            };
            let key = format!("group-peer/{conv}/{sender}/{version}");
            if self.store().get(&key)?.is_some() {
                continue;
            }
            let their = match self.client.peer_dh_key(sender).await {
                Ok(k) => k,
                Err(e) if per_message(&e) => continue,
                Err(e) => return Err(e),
            };
            let Ok((chain_key, iteration)) =
                crypto::group_key_unwrap(&my_dh, &their, conv, &nonce, &wrapped)
            else {
                continue;
            };
            put_json(
                self.store(),
                &key,
                &GroupPeer {
                    chain_key: hex::encode(chain_key),
                    iteration,
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DrSession, DrSession) {
        let (a, b) = ([0x11u8; 32], [0x22u8; 32]);
        let (a_pub, b_pub) = (x_pub(&a), x_pub(&b));
        let alice = DrSession::initiator(&a, &b_pub, "c", random32());
        let first = alice.dhs_pub.clone();
        let bob = DrSession::responder(&b, &a_pub, "c", &first, random32()).unwrap();
        (alice, bob)
    }

    #[test]
    fn ratchet_round_trips_out_of_order_and_across_a_reply() {
        let (mut alice, mut bob) = pair();
        let sent: Vec<_> = (0..3)
            .map(|i| {
                let dh = alice.dhs_pub.clone();
                let (ct, idx, prev) = alice.seal(format!("m{i}").as_bytes()).unwrap();
                (dh, idx, prev, ct)
            })
            .collect();
        // Delivered 2, 0, 1: the skip cache covers the gap.
        for i in [2usize, 0, 1] {
            let (dh, idx, prev, ct) = &sent[i];
            assert_eq!(
                bob.open(dh, *idx, *prev, ct).unwrap(),
                format!("m{i}").as_bytes()
            );
        }
        let bob_dh = bob.dhs_pub.clone();
        let (ct, idx, prev) = bob.seal(b"reply").unwrap();
        assert_eq!(alice.open(&bob_dh, idx, prev, &ct).unwrap(), b"reply");
        // Alice's next message uses a fresh ratchet key, which Bob steps to.
        let dh = alice.dhs_pub.clone();
        assert_ne!(dh, sent[0].0);
        let (ct, idx, prev) = alice.seal(b"again").unwrap();
        assert_eq!(bob.open(&dh, idx, prev, &ct).unwrap(), b"again");
    }

    #[test]
    fn a_replayed_or_tampered_message_is_refused() {
        let (mut alice, mut bob) = pair();
        let dh = alice.dhs_pub.clone();
        let (ct, idx, prev) = alice.seal(b"once").unwrap();
        let before = bob.clone();
        assert!(bob.open(&dh, idx, prev, &ct).is_ok());
        let mut replay = bob.clone();
        assert!(matches!(
            replay.open(&dh, idx, prev, &ct),
            Err(DmError::DecryptionFailed)
        ));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let mut tampered = before;
        assert!(matches!(
            tampered.open(&dh, idx, prev, &bad),
            Err(DmError::DecryptionFailed)
        ));
    }

    #[test]
    fn a_huge_gap_is_refused_not_cached() {
        let (alice, mut bob) = pair();
        assert!(matches!(
            bob.open(&alice.dhs_pub, 5000, 0, &[0; 32]),
            Err(DmError::TooManySkipped)
        ));
    }

    #[test]
    fn an_envelope_its_named_sender_did_not_sign_is_refused() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let sender = hex::encode(key.verifying_key().to_bytes());
        let ct = "aa";
        let sig = key.sign(&dr_envelope_signing_bytes("c", 1, 0, ct, "bb"));
        let env = json!({
            "sender_pubkey": sender, "v": 2, "message_index": 1, "prev_count": 0,
            "ciphertext_hex": ct, "dh_pubkey_hex": "bb",
            "signature_hex": hex::encode(sig.to_bytes()),
        });
        assert!(verify_envelope("c", &env, &sender).is_ok());
        assert!(verify_envelope("other-conv", &env, &sender).is_err());
        assert!(verify_envelope("c", &env, "someone-else").is_err());
    }
}
