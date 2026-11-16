//! The program's X25519 key and its peers': publish, look up, verify, pin.
//! One key serves DMs and voice (sdk-voice.md section 2, sdk-dm.md section 1).

use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use wavvon_identity::DhKeyRecord;

use crate::client::{encode, ok_or_status, Client};
use crate::error::{Error, Result};

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    dh_pubkey_hex: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
}

fn pin_key(pubkey: &str) -> String {
    format!("dh-pin/{pubkey}")
}

pub(crate) fn key32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

impl Client {
    /// Publishes this program's DH key on this hub, once per hub. Without it
    /// nobody can wrap a voice key or encrypt a DM to the program, and the
    /// program cannot unwrap theirs. Returns `false` when the hub already
    /// held exactly this key.
    pub async fn publish_dh_key(&self) -> Result<bool> {
        let own = self.public_key();
        let dh_hex = self.identity().dh_public_key_hex();
        match self.fetch_dh_record(&own).await {
            Ok(Some(published)) if published == dh_hex => return Ok(false),
            Ok(_) | Err(Error::DhKeyUnsigned { .. }) => {}
            Err(e) => return Err(e),
        }
        let signature = self
            .identity()
            .sign_hex(&DhKeyRecord::signing_bytes(&own, &dh_hex));
        let resp = self
            .execute(
                Method::PUT,
                &format!("/identity/{}/dh-key", encode(&own)),
                &[],
                Some(&json!({ "dh_pubkey_hex": dh_hex, "signature_hex": signature })),
                true,
            )
            .await?;
        ok_or_status(resp).await?;
        Ok(true)
    }

    /// `None` on a 404 or a record with no key. A record `pubkey` did not
    /// sign is an error, never "no key": the hub is not trusted with it.
    pub(crate) async fn fetch_dh_record(&self, pubkey: &str) -> Result<Option<String>> {
        let resp = self
            .execute(
                Method::GET,
                &format!("/identity/{}/dh-key", encode(pubkey)),
                &[],
                None,
                true,
            )
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let record: Record = ok_or_status(resp)
            .await?
            .json()
            .await
            .map_err(|e| Error::Decode(e.to_string()))?;
        let Some(dh) = record.dh_pubkey_hex else {
            return Ok(None);
        };
        let unsigned = || Error::DhKeyUnsigned {
            pubkey: pubkey.to_string(),
        };
        let sig =
            hex::decode(record.signature_hex.ok_or_else(unsigned)?).map_err(|_| unsigned())?;
        wavvon_identity::verify_signature(pubkey, &DhKeyRecord::signing_bytes(pubkey, &dh), &sig)
            .map_err(|_| unsigned())?;
        Ok(Some(dh))
    }

    /// A peer's verified, pinned DH key. The first key seen is pinned; a
    /// different validly signed one is [`Error::DhKeyChanged`] and is not
    /// used. A 404 is [`Error::RecipientHasNoKey`]; 429, 5xx and timeouts are
    /// retried and surface as `Transient`, never as either.
    pub async fn peer_dh_key(&self, pubkey: &str) -> Result<[u8; 32]> {
        let dh = self
            .fetch_dh_record(pubkey)
            .await?
            .ok_or_else(|| Error::RecipientHasNoKey {
                pubkey: pubkey.to_string(),
            })?;
        let raw =
            key32(&dh).ok_or_else(|| Error::Decode("DH key is not 32 bytes of hex".into()))?;
        let key = pin_key(pubkey);
        match self.store().get(&key)? {
            None => self.store().put(&key, dh.as_bytes())?,
            Some(pinned) if pinned == dh.as_bytes() => {}
            Some(pinned) => {
                return Err(Error::DhKeyChanged {
                    pubkey: pubkey.to_string(),
                    pinned: String::from_utf8_lossy(&pinned).into_owned(),
                    fetched: dh,
                })
            }
        }
        Ok(raw)
    }

    /// The program checked out a changed key and accepts it: re-pins what the
    /// hub now holds. Policy (when to call this) is the program's.
    pub async fn accept_dh_key(&self, pubkey: &str) -> Result<()> {
        let dh = self
            .fetch_dh_record(pubkey)
            .await?
            .ok_or_else(|| Error::RecipientHasNoKey {
                pubkey: pubkey.to_string(),
            })?;
        Ok(self.store().put(&pin_key(pubkey), dh.as_bytes())?)
    }
}
