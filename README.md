# wavvon-sdk (Rust)

Tier 1 of the Wavvon SDK: write a **bot or app** that talks to a [Wavvon](https://github.com/Wavvon) hub.
A program is a client like any other: a keypair, the same challenge, the same session. There is no bot account.

Design and contract: <https://github.com/Wavvon/Wavvon-docs/blob/main/docs/sdk.md>

Licence: Apache-2.0. The signing primitives come from `wavvon-identity`, the hub's own wire-format crate (also
Apache-2.0), and are still checked against the shared conformance vectors.

## Install

Not published yet. Use a path or git dependency:

```toml
wavvon-sdk = { git = "https://github.com/Wavvon/Wavvon-sdk-rust", features = ["axum"] }
```

Feature `axum` adds a ready webhook endpoint (`wavvon_sdk::axum_handler`).

## Quick start

```rust
use wavvon_sdk::apps::AppProfile;
use wavvon_sdk::{Client, ConnectOptions, Event, EventsOptions, Identity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed_hex(&std::env::var("WAVVON_SEED")?)?; // never sent anywhere
    let opts = ConnectOptions { invite_code: std::env::var("WAVVON_INVITE").ok(), ..Default::default() };
    let client = Client::connect("https://hub.example", identity, opts).await?;

    // Register before opening the socket: hub_event is pushed only to a socket
    // whose identity already had a profile when it connected.
    client.put_app_profile(&AppProfile { name: "echo".into(), ..Default::default() }).await?;

    let me = client.public_key();
    let mut events = client.events(EventsOptions::default());
    while let Some(event) = events.next().await {
        if let Event::Message { channel_id, message } = event? {
            if message.sender != me {
                client.send_message(&channel_id, &message.content, None).await?;
            }
        }
    }
    Ok(())
}
```

A fuller bot with a slash command is `examples/echo_bot.rs`.

## What is in it

| Piece | Where |
|---|---|
| Generated REST client, whole API (`client.rest()`; wrap in `client.call(..)` for retry and re-auth) | `generated`, `Client::call` |
| Auth: `tagged-v1` signing, raw only for exactly 32 bytes, unknown scheme refused | `auth` |
| Retry: capped exponential backoff with jitter on 429/5xx/408/network; transient is `Error::Transient`, never an answer | `retry`, `Client` |
| Re-auth on 401, observable `ConnectionState` | `Client::state` |
| Capabilities from `GET /info`, typed `Error::UnsupportedByHub` | `caps`, `Client::require` |
| Keyset pager as a `Stream` (`Client::users`) | `pager` |
| WebSocket loop: seq tracking, `resume`, `replay_unavailable` surfaced, `Event::Unknown { raw }` | `Client::events` |
| HTTP polling `GET`/`DELETE /me/events` | `Client::poll_events`, `ack_events` |
| App registration | `Client::put_app_profile`, `put_app_commands`, `put_app_subscriptions` |
| Slash/component dispatch verifier, invocation decoding, reply shapes | `webhooks::verify_dispatch`, `apps` |
| Outgoing-webhook verifier (HKDF + HMAC) | `webhooks::verify_outgoing_webhook` |
| Mini-app host side | `EventSender::announce_mini_app`, `send_to_player`, `Event::MiniAppMessage` |

### Capabilities each feature needs

| Feature | Capability |
|---|---|
| `put_app_profile`, `put_app_commands`, `put_app_subscriptions`, `app_registration` | `apps.register` (and a role holding it) |
| `Client::users` paging | `list.cursor` |
| Other `limit` + `cursor` lists (via the generated client) | `list.cursor.lists` |
| A hub that sends `X-Wavvon-Signature-V1` (the verifiers require it) | `webhooks.signedtimestamp` |

The SDK never compares hub versions. A missing string is `Error::UnsupportedByHub`.

## Webhook verification (any framework)

```rust
use wavvon_sdk::webhooks::{verify_dispatch, DeliveryHeaders, unix_now};

let headers = DeliveryHeaders {
    hub_pubkey: header("x-wavvon-hub-pubkey"),
    signature_v1: header("x-wavvon-signature-v1"),
    timestamp: header("x-wavvon-timestamp"),
};
verify_dispatch(&client.hub_public_key(), &headers, raw_body_bytes, unix_now())?;
```

Pass the hub key *you* trust (`Client::hub_public_key`), not the one in the request: a signature checked against a key
the sender names proves nothing. Verify the raw bytes before parsing. The 300 s window is enforced.

## Conformance

`tests/conformance.rs` asserts the tier-1 vectors (`auth_challenge`, `webhook_delivery_hub`,
`webhook_delivery_outgoing`) from `wire-vectors.json`, owned by Wavvon-server
(`crates/identity/wire-vectors.json`). It reads `WAVVON_WIRE_VECTORS`, else
`../../server/crates/identity/wire-vectors.json`. A missing file fails when `CI` is set and prints a loud skip otherwise.

Pin: the CI workflow fetches the vectors at `WIRE_VECTORS_REF` (`.github/workflows/ci.yml`), currently Wavvon-server
`eb11d75657ee8362dd42a7982fc5b13a3dcc4e68`; bump it in the PR that takes new vectors. The generated REST code is pinned to the Wavvon-docs commit in `src/generated/SPEC_COMMIT`.

## Regenerating the REST client

```sh
cargo xtask generate [docs-path] [--ref <git-ref>]   # default docs-path ../../docs
```

It prints each spec fix it applies (see `CLAUDE.md`). Use `--ref` so the recorded commit is the spec you built from.

## Smoke test against a real hub

```sh
WAVVON_SMOKE_HUB=http://localhost:3400 cargo run --example smoke --features axum
```

The identity must hold `apps.register` (a hub owner does), and the hub must be allowed to call a loopback webhook
(`WAVVON_ALLOW_PRIVATE_WEBHOOKS=true`). It authenticates, posts, registers `/smokecmd`, then receives and answers its
invocation.

## Not here

Tier 2 (E2E DMs, multi-device, home hubs, voice) is a later layer. `/auth/*` always goes to the hub itself, not to a
farm in front of it.
