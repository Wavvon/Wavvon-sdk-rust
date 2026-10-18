#![cfg(feature = "axum")]

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use wavvon_sdk::apps::{Answer, Invocation, SlashResponse};
use wavvon_sdk::axum_handler::router;
use wavvon_sdk::webhooks::{delivery_signing_bytes, unix_now};

async fn serve() -> (String, SigningKey) {
    let key = SigningKey::from_bytes(&[3; 32]);
    let app = router(
        hex::encode(key.verifying_key().to_bytes()),
        |inv| async move {
            match inv {
                Invocation::Slash(s) => {
                    Answer::Slash(SlashResponse::text(format!("got {}", s.command)))
                }
                _ => Answer::Slash(SlashResponse::default()),
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, key)
}

fn body() -> String {
    json!({
        "type": "slash_command", "hub_url": "h", "channel_id": "c", "message_id_hint": "m",
        "author": {"pubkey": "p"}, "command": "echo", "args_raw": "", "args_tokens": []
    })
    .to_string()
}

async fn post(url: &str, key: &SigningKey, ts: u64, body: String) -> reqwest::Response {
    let sig = key.sign(&delivery_signing_bytes(ts, body.as_bytes()));
    reqwest::Client::new()
        .post(url)
        .header(
            "X-Wavvon-Hub-Pubkey",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .header("X-Wavvon-Signature-V1", hex::encode(sig.to_bytes()))
        .header("X-Wavvon-Timestamp", ts.to_string())
        .body(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_signed_slash_invocation_is_answered() {
    let (url, key) = serve().await;
    let resp = post(&url, &key, unix_now(), body()).await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v, json!({"reply": {"body": "got echo"}}));
}

#[tokio::test]
async fn replayed_and_forged_deliveries_never_reach_the_handler() {
    let (url, key) = serve().await;
    assert_eq!(
        post(&url, &key, unix_now() - 400, body()).await.status(),
        401
    );
    let stranger = SigningKey::from_bytes(&[4; 32]);
    assert_eq!(
        post(&url, &stranger, unix_now(), body()).await.status(),
        401
    );
}
