//! Smoke test against a real hub: authenticate, post, register a slash command,
//! receive and answer its invocation.
//!
//!   WAVVON_SMOKE_HUB=http://localhost:3400 [WAVVON_SMOKE_INVITE=code] \
//!   [WAVVON_SMOKE_SEED=<64 hex>] cargo run --example smoke --features axum
//!
//! The identity must hold `apps.register` (a hub's owner does). The hub must
//! be allowed to call a loopback webhook (`WAVVON_ALLOW_PRIVATE_WEBHOOKS=true`).

use std::time::Duration;

use tokio::sync::mpsc;
use wavvon_sdk::apps::{Answer, AppCommand, AppProfile, Invocation, SlashResponse};
use wavvon_sdk::axum_handler::router;
use wavvon_sdk::{Client, ConnectOptions, Event, EventsOptions, Identity};

type Out = Result<(), Box<dyn std::error::Error>>;

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> Result<T, String> {
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .map_err(|_| format!("timed out waiting for {what}"))
}

#[tokio::main]
async fn main() -> Out {
    let hub = std::env::var("WAVVON_SMOKE_HUB").map_err(|_| "set WAVVON_SMOKE_HUB")?;
    let seed = std::env::var("WAVVON_SMOKE_SEED").unwrap_or_else(|_| "5a".repeat(32));
    let opts = ConnectOptions {
        invite_code: std::env::var("WAVVON_SMOKE_INVITE").ok(),
        ..Default::default()
    };
    let client = Client::connect(&hub, Identity::from_seed_hex(&seed)?, opts).await?;
    println!("authenticated as {}", client.public_key());
    println!("capabilities: {:?}", client.capabilities());

    let find_channel = || async {
        let channels = client
            .call(|api| async move { api.list_channels().send().await })
            .await?
            .into_inner();
        Ok::<_, wavvon_sdk::Error>(
            channels
                .iter()
                .find(|c| c.is_category != Some(true))
                .and_then(|c| c.id.clone()),
        )
    };
    let channel = match find_channel().await? {
        Some(id) => id,
        None => {
            client
                .call(|api| async move {
                    api.create_channel()
                        .body(wavvon_sdk::generated::types::CreateChannelBody {
                            name: "smoke".into(),
                            description: None,
                            is_category: None,
                            parent_id: None,
                        })
                        .send()
                        .await
                })
                .await?;
            find_channel()
                .await?
                .ok_or("created a channel but it is not listed")?
        }
    };

    let (seen_tx, mut seen_rx) = mpsc::channel(4);
    let app = router(client.hub_public_key(), move |inv| {
        let seen = seen_tx.clone();
        async move {
            if let Invocation::Slash(s) = inv {
                let _ = seen.send((s.command, s.args_raw)).await;
            }
            Answer::Slash(SlashResponse::text("smoke-ok"))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hook = format!("http://{}/", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });

    client
        .put_app_profile(&AppProfile {
            name: "sdk-smoke".into(),
            webhook_url: Some(hook),
            ..Default::default()
        })
        .await?;
    client
        .put_app_commands(&[AppCommand {
            name: "smokecmd".into(),
            description: "SDK smoke test".into(),
            cooldown_seconds: Some(0),
            ..Default::default()
        }])
        .await?;
    println!("registered profile and /smokecmd");

    let mut events = client.events(EventsOptions::default());
    within("hello", async {
        loop {
            if let Some(Ok(Event::Hello { .. })) = events.next().await {
                break;
            }
        }
    })
    .await?;

    client.send_message(&channel, "smoke ping", None).await?;
    within("our own message on the socket", async {
        loop {
            if let Some(Ok(Event::Message { message, .. })) = events.next().await {
                if message.content == "smoke ping" {
                    break;
                }
            }
        }
    })
    .await?;
    println!("posted and received");

    client
        .send_message(&channel, "/smokecmd hello", None)
        .await?;
    let (command, args) = within("the invocation", seen_rx.recv())
        .await?
        .ok_or("handler gone")?;
    assert_eq!((command.as_str(), args.as_str()), ("smokecmd", "hello"));
    within("the reply", async {
        loop {
            if let Some(Ok(Event::Message { message, .. })) = events.next().await {
                if message.content == "smoke-ok" {
                    break;
                }
            }
        }
    })
    .await?;
    println!("invocation verified, answered, reply received\nSMOKE OK");
    Ok(())
}
