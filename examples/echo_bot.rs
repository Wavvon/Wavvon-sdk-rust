//! Echoes what others say and answers `/shout`.
//!
//!   WAVVON_HUB=https://hub.example WAVVON_SEED=<64 hex> \
//!   WAVVON_WEBHOOK_URL=https://bot.example/hook [WAVVON_INVITE=code] \
//!   cargo run --example echo_bot --features axum
//!
//! The identity needs a role with `apps.register`. The seed is read here and
//! never sent anywhere.

use wavvon_sdk::apps::{Answer, AppCommand, AppProfile, Invocation, SlashResponse};
use wavvon_sdk::axum_handler::router;
use wavvon_sdk::{Client, ConnectOptions, Event, EventsOptions, Identity};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed_hex(&env("WAVVON_SEED"))?;
    let opts = ConnectOptions {
        invite_code: std::env::var("WAVVON_INVITE").ok(),
        ..Default::default()
    };
    let client = Client::connect(&env("WAVVON_HUB"), identity, opts).await?;

    client
        .put_app_profile(&AppProfile {
            name: "echo".into(),
            webhook_url: Some(env("WAVVON_WEBHOOK_URL")),
            ..Default::default()
        })
        .await?;
    client
        .put_app_commands(&[AppCommand {
            name: "shout".into(),
            description: "Repeat the arguments in capitals".into(),
            ..Default::default()
        }])
        .await?;

    let app = router(client.hub_public_key(), |inv| async move {
        match inv {
            Invocation::Slash(s) => Answer::Slash(SlashResponse::text(s.args_raw.to_uppercase())),
            _ => Answer::Slash(SlashResponse::default()),
        }
    });
    let bind = std::env::var("WAVVON_WEBHOOK_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tokio::spawn(async move { axum::serve(listener, app).await });

    let me = client.public_key();
    let mut events = client.events(EventsOptions::default());
    while let Some(event) = events.next().await {
        if let Event::Message {
            channel_id,
            message,
        } = event?
        {
            if message.sender != me && message.visible_to_pubkey.is_none() {
                client
                    .send_message(&channel_id, &message.content, None)
                    .await?;
            }
        }
    }
    Ok(())
}
