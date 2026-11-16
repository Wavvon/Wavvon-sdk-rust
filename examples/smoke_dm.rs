//! Smoke test of E2E DMs against a real hub, with fresh identities each run.
//!
//!   WAVVON_SMOKE_HUB=http://localhost:3400 [WAVVON_SMOKE_SEED=<64 hex>] \
//!   cargo run --example smoke_dm
//!
//! The seed identity (default `5a` repeated) must be a hub owner, so it can
//! mint the invites the others join with: start the hub with
//! `WAVVON_OWNER_PUBKEY` set to its public key.

use std::time::Duration;

use rand::RngExt;
use wavvon_sdk::dm::MessagesPage;
use wavvon_sdk::{Client, ConnectOptions, Error, Event, EventsOptions, Identity};

type Out = Result<(), Box<dyn std::error::Error>>;

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> Result<T, String> {
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .map_err(|_| format!("timed out waiting for {what}"))
}

async fn join(hub: &str, owner: &Client) -> Result<Client, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed);
    let identity = Identity::from_seed(seed);
    let pubkey = identity.public_key_hex();
    let invite = owner
        .call(|api| {
            let pubkey = pubkey.clone();
            async move {
                api.create_invite()
                    .body_map(|b| b.bound_pubkey(pubkey))
                    .send()
                    .await
            }
        })
        .await?
        .into_inner();
    let opts = ConnectOptions {
        invite_code: invite.code,
        ..Default::default()
    };
    Ok(Client::connect(hub, identity, opts).await?)
}

fn text(m: &wavvon_sdk::DmMessage) -> Result<String, Box<dyn std::error::Error>> {
    match &m.content {
        Ok(p) => Ok(p.content.clone()),
        Err(e) => Err(format!("message {} unreadable: {e}", m.id).into()),
    }
}

#[tokio::main]
async fn main() -> Out {
    let hub = std::env::var("WAVVON_SMOKE_HUB").map_err(|_| "set WAVVON_SMOKE_HUB")?;
    let seed = std::env::var("WAVVON_SMOKE_SEED").unwrap_or_else(|_| "5a".repeat(32));
    let owner = Client::connect(
        &hub,
        Identity::from_seed_hex(&seed)?,
        ConnectOptions::default(),
    )
    .await?;
    let a = join(&hub, &owner).await?;
    let b = join(&hub, &owner).await?;
    let c = join(&hub, &owner).await?;
    println!(
        "joined A {} B {} C {}",
        a.public_key(),
        b.public_key(),
        c.public_key()
    );

    a.publish_dh_key().await?;
    b.publish_dh_key().await?;
    assert!(
        !b.publish_dh_key().await?,
        "a second publish must be a no-op"
    );

    let mut b_events = b.events(EventsOptions::default());
    within("hello", async {
        loop {
            if let Some(Ok(Event::Hello { .. })) = b_events.next().await {
                break;
            }
        }
    })
    .await?;

    // No key published by C: encrypting to it is refused, never downgraded.
    let to_c = a.dms().create_conversation(&[c.public_key()]).await?;
    match a.dms().send_text(&to_c.id, "secret").await {
        Err(Error::RecipientHasNoKey { .. }) => println!("no DH key: refused, nothing sent"),
        other => return Err(format!("expected RecipientHasNoKey, got {other:?}").into()),
    }
    assert!(
        a.dms()
            .messages(&to_c.id, &MessagesPage::default())
            .await?
            .is_empty(),
        "a refused send must leave nothing in the conversation"
    );

    // 1:1: A starts the ratchet, B answers, A ratchets forward.
    let conv = a.dms().create_conversation(&[b.public_key()]).await?;
    let (da, db) = (a.dms(), b.dms());
    a.dms().send_text(&conv.id, "hello B").await?;
    a.dms().send_text(&conv.id, "second").await?;
    match within("a dm event on B", async {
        loop {
            if let Some(Ok(Event::Dm { .. })) = b_events.next().await {
                break;
            }
        }
    })
    .await
    {
        Ok(()) => println!("B's socket announced the new conversation's message"),
        Err(e) => println!("note: {e} (a conversation created after connect)"),
    }
    let got = db.poll(&conv.id).await?;
    let texts: Vec<_> = got.iter().map(text).collect::<Result<_, _>>()?;
    assert_eq!(texts, ["hello B", "second"]);
    assert!(got.iter().all(|m| m.encrypted));
    db.send_text(&conv.id, "hi A").await?;
    let got = da.poll(&conv.id).await?;
    let from_b: Vec<_> = got
        .iter()
        .filter(|m| m.sender == b.public_key())
        .map(text)
        .collect::<Result<_, _>>()?;
    assert_eq!(from_b, ["hi A"]);
    da.send_text(&conv.id, "third, after the reply").await?;
    let got = db.poll(&conv.id).await?;
    let texts: Vec<_> = got
        .iter()
        .filter(|m| m.sender == a.public_key())
        .map(text)
        .collect::<Result<_, _>>()?;
    assert_eq!(texts, ["third, after the reply"]);
    // Reading history again does not need the spent keys.
    let again = db
        .messages(&conv.id, &MessagesPage::default())
        .await?
        .iter()
        .filter(|m| m.content.is_ok())
        .count();
    assert!(again >= 3, "history re-read lost messages");
    println!("1:1 double ratchet: round trip, reply, ratchet step, re-read");

    // Group: C publishes now, so it is in the distribution.
    c.publish_dh_key().await?;
    let group = a
        .dms()
        .create_conversation(&[b.public_key(), c.public_key()])
        .await?;
    let sent = a.dms().send_text(&group.id, "hello group").await?;
    let dist = sent
        .distribution
        .ok_or("first group send must distribute")?;
    assert_eq!(dist.delivered.len(), 2, "{:?}", dist.skipped);
    for member in [&b, &c] {
        let got = member.dms().poll(&group.id).await?;
        let texts: Vec<_> = got.iter().map(text).collect::<Result<_, _>>()?;
        assert_eq!(texts, ["hello group"]);
    }
    a.dms().rotate_group_key(&group.id).await?;
    a.dms().send_text(&group.id, "after rotation").await?;
    let got = c.dms().poll(&group.id).await?;
    let texts: Vec<_> = got.iter().map(text).collect::<Result<_, _>>()?;
    assert_eq!(texts, ["after rotation"]);
    println!("group sender keys: distribute, read, rotate, read");

    let clear = a
        .dms()
        .send_plaintext(&conv.id, "explicit plaintext")
        .await?;
    let rows = db.messages(&conv.id, &MessagesPage::default()).await?;
    let plain = rows
        .iter()
        .find(|m| m.id == clear.id)
        .ok_or("plaintext row")?;
    assert!(!plain.encrypted && text(plain)? == "explicit plaintext");
    println!("DM SMOKE OK");
    Ok(())
}
