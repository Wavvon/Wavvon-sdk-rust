//! Signed listings in a Wavvon directory's invite directory
//! (`docs/docs/invite-directory.md` in Wavvon-docs): a program publishes the
//! `wavvon.identity` document that lets people find it and invite it.
//!
//! The directory is not a hub, so these are free functions over an
//! [`Identity`], not methods on a [`Client`](crate::Client).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Method;
use serde::Serialize;

use crate::auth::Identity;
use crate::error::{Error, Result};
use crate::retry::{classify, RetryPolicy, Verdict};

/// Where a listing's invitations are delivered: exactly one route.
#[derive(Clone, Debug)]
pub enum Contact {
    /// The hub the identity lives on.
    HomeHub(String),
    /// A public https URL of the program's own.
    Endpoint(String),
}

/// A label the publisher chooses; nobody verifies it.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListingKind {
    Person,
    #[default]
    Program,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListingCommand {
    pub name: String,
    pub description: String,
}

/// What a program offers once invited, shown on its listing.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ListingApp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<ListingCommand>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mini_app: Option<bool>,
}

/// What the publisher writes; the key comes from the identity.
#[derive(Clone, Debug)]
pub struct Listing {
    pub name: String,
    pub tagline: String,
    /// Markdown, up to 8000 characters.
    pub description: String,
    pub kind: ListingKind,
    pub tags: Vec<String>,
    pub languages: Vec<String>,
    pub contact: Contact,
    pub app: Option<ListingApp>,
    /// Seconds. The directory keeps only the newest listing per key, so this
    /// must grow with every publish. `None` is now.
    pub listed_at: Option<u64>,
}

impl Listing {
    /// A program's listing with everything optional left empty.
    pub fn new(name: impl Into<String>, contact: Contact) -> Self {
        Self {
            name: name.into(),
            tagline: String::new(),
            description: String::new(),
            kind: ListingKind::Program,
            tags: Vec::new(),
            languages: Vec::new(),
            contact,
            app: None,
            listed_at: None,
        }
    }
}

#[derive(Serialize)]
enum WireContact<'a> {
    #[serde(rename = "home_hub")]
    HomeHub(&'a str),
    #[serde(rename = "endpoint")]
    Endpoint(&'a str),
}

// Field order is the wire order: the same as the Wavvon clients' builder.
#[derive(Serialize)]
struct Doc<'a> {
    format: &'static str,
    version: u8,
    pubkey: String,
    name: &'a str,
    tagline: &'a str,
    description: &'a str,
    kind: ListingKind,
    tags: &'a [String],
    languages: &'a [String],
    contact: WireContact<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<&'a ListingApp>,
    listed_at: u64,
}

/// The exact bytes a listing signs and submits: byte-identical to what the
/// Wavvon clients build for the same fields.
pub fn build_identity_listing(listing: &Listing, public_key_hex: &str) -> String {
    let contact = match &listing.contact {
        Contact::HomeHub(url) => WireContact::HomeHub(url.trim_end_matches('/')),
        Contact::Endpoint(url) => WireContact::Endpoint(url),
    };
    let listed_at = listing.listed_at.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    serde_json::to_string(&Doc {
        format: "wavvon.identity",
        version: 1,
        pubkey: format!("ed25519:{public_key_hex}"),
        name: listing.name.trim(),
        tagline: listing.tagline.trim(),
        description: &listing.description,
        kind: listing.kind,
        tags: &listing.tags,
        languages: &listing.languages,
        contact,
        app: listing.app.as_ref(),
        listed_at,
    })
    .expect("a listing always serializes")
}

/// Ed25519 over the UTF-8 bytes, base64url without padding.
fn sign(identity: &Identity, message: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identity.sign(message.as_bytes()))
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("wavvon-sdk-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Request(e.to_string()))
}

/// One request with the SDK's retry rules. A 404 is returned; any other
/// refusal is `Error::Directory` with the reason the directory gave.
async fn send(
    http: &reqwest::Client,
    method: Method,
    url: &str,
    body: Option<String>,
    sig: Option<&str>,
) -> Result<reqwest::Response> {
    let policy = RetryPolicy::default();
    let mut last = String::new();
    for attempt in 0..policy.max_attempts {
        let mut req = http.request(method.clone(), url);
        if let Some(b) = &body {
            req = req.body(b.clone());
        }
        if let Some(s) = sig {
            req = req.header("x-wavvon-signature", s);
        }
        match req.send().await {
            Err(e) if e.is_builder() => return Err(Error::Request(e.to_string())),
            Err(e) => last = e.to_string(),
            Ok(resp) => {
                let status = resp.status().as_u16();
                if classify(status) != Verdict::Retry {
                    if resp.status().is_success() || status == 404 {
                        return Ok(resp);
                    }
                    let text = resp.text().await.unwrap_or_default();
                    let reason = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("error")?.as_str().map(str::to_owned))
                        .unwrap_or(text);
                    return Err(Error::Directory { status, reason });
                }
                last = format!("HTTP {status}");
            }
        }
        tokio::time::sleep(policy.delay(attempt)).await;
    }
    Err(Error::Transient {
        attempts: policy.max_attempts,
        last,
    })
}

/// Publishes (or replaces) this identity's listing. Returns its page URL.
pub async fn publish_listing(
    identity: &Identity,
    listing: &Listing,
    directory: &str,
) -> Result<String> {
    let base = directory.trim_end_matches('/');
    let pubkey = identity.public_key_hex();
    let payload = build_identity_listing(listing, &pubkey);
    let body = serde_json::json!({ "sig": sign(identity, &payload), "payload": payload });
    // No JSON content type: the directory parses the body either way.
    let resp = send(
        &http()?,
        Method::POST,
        &format!("{base}/api/identities"),
        Some(body.to_string()),
        None,
    )
    .await?;
    if resp.status().as_u16() == 404 {
        return Err(Error::Directory {
            status: 404,
            reason: "this directory has no invite directory".into(),
        });
    }
    Ok(format!("{base}/identities/{pubkey}"))
}

/// Removes this identity's listing with the signed delete. `Ok(false)` if
/// there was none.
pub async fn unpublish_listing(identity: &Identity, directory: &str) -> Result<bool> {
    let pubkey = identity.public_key_hex();
    let url = format!(
        "{}/api/identities/{pubkey}",
        directory.trim_end_matches('/')
    );
    let http = http()?;
    let current = send(&http, Method::GET, &url, None, None).await?;
    if current.status().as_u16() == 404 {
        return Ok(false);
    }
    let held: serde_json::Value = current
        .json()
        .await
        .map_err(|e| Error::Decode(e.to_string()))?;
    let listed_at = held
        .get("listed_at")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| Error::Decode("listing has no listed_at".into()))?;
    let sig = sign(identity, &delete_message(&pubkey, listed_at));
    let resp = send(&http, Method::DELETE, &url, None, Some(&sig)).await?;
    Ok(resp.status().as_u16() != 404)
}

/// What a removal signs: it names the `listed_at` of the listing it removes.
fn delete_message(pubkey_hex: &str, listed_at: u64) -> String {
    format!("wavvon-directory/delete/v1:identity:{pubkey_hex}:{listed_at}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn identity() -> Identity {
        Identity::from_seed([0x11; 32])
    }

    #[test]
    fn matches_the_clients_builder_byte_for_byte() {
        let id = identity();
        let pk = id.public_key_hex();
        let listing = Listing {
            tagline: "hi".into(),
            kind: ListingKind::Person,
            tags: vec!["chess".into()],
            languages: vec!["it".into()],
            listed_at: Some(7),
            ..Listing::new(" Ada ", Contact::HomeHub("https://hub.example/".into()))
        };
        // What clients' packages/core buildIdentityListing returns for these fields.
        let clients = format!(
            r#"{{"format":"wavvon.identity","version":1,"pubkey":"ed25519:{pk}","name":"Ada","tagline":"hi","description":"","kind":"person","tags":["chess"],"languages":["it"],"contact":{{"home_hub":"https://hub.example"}},"listed_at":7}}"#
        );
        assert_eq!(build_identity_listing(&listing, &pk), clients);
    }

    #[test]
    fn app_block_sits_before_listed_at() {
        let listing = Listing {
            app: Some(ListingApp {
                commands: None,
                mini_app: Some(true),
            }),
            listed_at: Some(1),
            ..Listing::new("Tallyman", Contact::Endpoint("https://t.example/i".into()))
        };
        let doc = build_identity_listing(&listing, "00");
        assert!(doc.ends_with(
            r#""kind":"program","tags":[],"languages":[],"contact":{"endpoint":"https://t.example/i"},"app":{"mini_app":true},"listed_at":1}"#
        ));
    }

    #[test]
    fn signature_is_base64url_over_the_exact_bytes() {
        let id = identity();
        let msg = delete_message(&id.public_key_hex(), 42);
        let sig = sign(&id, &msg);
        assert!(!sig.contains(['+', '/', '=']));
        let bytes: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig)
            .unwrap()
            .try_into()
            .unwrap();
        let key: [u8; 32] = hex::decode(id.public_key_hex())
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&key)
            .unwrap()
            .verify(msg.as_bytes(), &Signature::from_bytes(&bytes))
            .unwrap();
    }
}
