//! An echo program over end-to-end encrypted DMs: whoever writes to it gets
//! their own text back, encrypted. Shows the three things a DM program does:
//! publish its DH key, learn of new messages from `dm` events, read them with
//! `poll`.
//!
//!   WAVVON_HUB=http://localhost:3000 WAVVON_SEED=<64 hex> [WAVVON_INVITE=code] \
//!   cargo run --example dm_echo

use wavvon_sdk::{Client, ConnectOptions, Event, EventsOptions, Identity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed_hex(&std::env::var("WAVVON_SEED")?)?;
    let opts = ConnectOptions {
        invite_code: std::env::var("WAVVON_INVITE").ok(),
        ..Default::default()
    };
    let client = Client::connect(&std::env::var("WAVVON_HUB")?, identity, opts).await?;
    let dms = client.dms();
    // Without a published key nobody can encrypt to this program.
    client.publish_dh_key().await?;
    println!("echoing DMs as {}", client.public_key());

    // Start from now: whatever is already there is not echoed.
    for conv in dms.conversations().await? {
        dms.skip_existing(&conv.id).await?;
    }

    let me = client.public_key();
    let mut events = client.events(EventsOptions::default());
    loop {
        let conv = match events.next().await.ok_or("event stream ended")?? {
            Event::Dm {
                conversation_id, ..
            } => conversation_id,
            other => {
                dms.handle_event(&other).await?;
                continue;
            }
        };
        for message in dms.poll(&conv).await? {
            if message.sender == me {
                continue;
            }
            match &message.content {
                Ok(body) => {
                    dms.send_text(&conv, &format!("echo: {}", body.content))
                        .await?;
                }
                Err(e) => eprintln!("cannot read {}: {e}", message.id),
            }
        }
    }
}
