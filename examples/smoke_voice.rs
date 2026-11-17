//! Smoke test of voice against a real hub: the owner and a second SDK
//! instance share a room, and every assertion needs a decrypted, decoded
//! frame, never a roster row. Nothing is played; audio stays in memory.
//!
//!   WAVVON_SMOKE_HUB=http://localhost:3400 [WAVVON_SMOKE_SEED=<64 hex>] \
//!   cargo run --example smoke_voice --features voice-pcm
//!
//! The seed identity (default `5a` repeated) must be a hub owner, so it can
//! create the channel and mint the invite the second instance joins with.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngExt;
use wavvon_sdk::voice::{Voice, VoiceEvent};
use wavvon_sdk::{Client, ConnectOptions, Identity};

type Out = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Seen {
    /// (speaker pubkey, key_id) -> decoded 20 ms frames
    frames: HashMap<(String, u32), usize>,
    silent: usize,
    zones: Vec<String>,
    positions: Vec<Vec<f64>>,
    rejoining: usize,
    skipped: Vec<String>,
    refused: Vec<String>,
}

fn watch(voice: Voice) -> Arc<Mutex<Seen>> {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = seen.clone();
    tokio::spawn(async move {
        while let Some(ev) = voice.next().await {
            let mut s = sink.lock().unwrap();
            match ev {
                Ok(VoiceEvent::Audio(a)) => {
                    let pcm = a.pcm.as_deref().unwrap_or_default();
                    assert_eq!(pcm.len(), 960, "a decoded frame is 20 ms at 48 kHz");
                    let energy: f32 = pcm.iter().map(|x| x * x).sum::<f32>() / 960.0;
                    if energy < 1e-4 {
                        s.silent += 1;
                    }
                    *s.frames.entry((a.from, a.key_id)).or_default() += 1;
                }
                Ok(VoiceEvent::Zones(z)) => s.zones = z.into_iter().map(|z| z.zone_id).collect(),
                Ok(VoiceEvent::Position { position, .. }) => s.positions.push(position),
                Ok(VoiceEvent::PositionRefused { reason }) => s.refused.push(reason),
                Ok(VoiceEvent::Rejoining) => s.rejoining += 1,
                Ok(VoiceEvent::KeySkipped { public_key, .. }) => s.skipped.push(public_key),
                Ok(_) => {}
                Err(e) => eprintln!("voice error: {e}"),
            }
        }
    });
    seen
}

async fn until(what: &str, mut ok: impl FnMut() -> bool) -> Result<(), String> {
    for _ in 0..600 {
        if ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for {what}"))
}

fn frames_from(seen: &Arc<Mutex<Seen>>, from: &str, min_key: u32) -> usize {
    seen.lock()
        .unwrap()
        .frames
        .iter()
        .filter(|((f, k), _)| f == from && *k >= min_key)
        .map(|(_, n)| n)
        .sum()
}

fn tone(voice: Voice, frames: usize) -> tokio::task::JoinHandle<Result<(), wavvon_sdk::Error>> {
    tokio::spawn(async move {
        for i in 0..frames {
            let pcm: Vec<f32> = (0..960)
                .map(|n| {
                    let t = (i * 960 + n) as f32 / 48_000.0;
                    0.3 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
                })
                .collect();
            voice.send_pcm(&pcm).await?;
        }
        Ok(())
    })
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

#[tokio::main]
async fn main() -> Out {
    let hub = std::env::var("WAVVON_SMOKE_HUB").map_err(|_| "set WAVVON_SMOKE_HUB")?;
    let seed = std::env::var("WAVVON_SMOKE_SEED").unwrap_or_else(|_| "5a".repeat(32));
    let a = Client::connect(
        &hub,
        Identity::from_seed_hex(&seed)?,
        ConnectOptions::default(),
    )
    .await?;
    let b = join(&hub, &a).await?;
    let (a_key, b_key) = (a.public_key(), b.public_key());

    let name = format!("voice-smoke-{}", &b_key[..6]);
    let channel = {
        let name = name.clone();
        a.call(|api| {
            let name = name.clone();
            async move {
                api.create_channel()
                    .body_map(|x| x.name(name).channel_type("voice".to_string()))
                    .send()
                    .await
            }
        })
        .await?;
        let channels = a
            .call(|api| async move { api.list_channels().send().await })
            .await?
            .into_inner();
        channels
            .iter()
            .find(|c| c.name.as_deref() == Some(name.as_str()))
            .and_then(|c| c.id.clone())
            .ok_or("created voice channel is not listed")?
    };

    let va = a.join_voice(&channel).await?;
    let vb = b.join_voice(&channel).await?;
    println!(
        "both joined: A is sender {}, B is {}",
        va.sender_id(),
        vb.sender_id()
    );
    let (seen_a, seen_b) = (watch(va.clone()), watch(vb.clone()));

    // A speaks; B must decode what it hears.
    let sending = tone(va.clone(), 200);
    until("B to decode 100 frames from A", || {
        frames_from(&seen_b, &a_key, 1) >= 100
    })
    .await?;
    sending.await??;
    assert_eq!(
        seen_b.lock().unwrap().silent,
        0,
        "decoded frames carry the tone"
    );
    println!("B decoded >= 100 frames of A's 440 Hz tone");

    // The reverse direction.
    let sending = tone(vb.clone(), 200);
    until("A to decode 100 frames from B", || {
        frames_from(&seen_a, &b_key, 1) >= 100
    })
    .await?;
    sending.await??;
    println!("A decoded >= 100 frames from B");

    // A frame that is not 20 ms is refused before anything is sent.
    match va.send_opus(&[0xF9, 0, 0]).await {
        Err(wavvon_sdk::Error::Voice(wavvon_sdk::error::VoiceError::BadFrame(_))) => {
            println!("a 40 ms packet is refused")
        }
        other => return Err(format!("expected BadFrame, got {other:?}").into()),
    }

    // Rotation: B leaves, so A's key changes to 2; B rejoins and must decode it.
    vb.leave().await?;
    let vb2 = b.join_voice(&channel).await?;
    let seen_b2 = watch(vb2.clone());
    let sending = tone(va.clone(), 200);
    until("B's second session to decode key_id >= 2", || {
        frames_from(&seen_b2, &a_key, 2) >= 50
    })
    .await?;
    sending.await??;
    println!("after B left, A rotated to key_id >= 2 and B decoded it");

    // Proximity: ten positions in 100 ms end at the last one.
    va.create_zone(
        "smoke-zone",
        "smoke",
        "2d",
        serde_json::json!({}),
        "any_channel_member",
    )
    .await?;
    until("both to see the zone", || {
        seen_b2
            .lock()
            .unwrap()
            .zones
            .iter()
            .any(|z| z == "smoke-zone")
            && va.zones().iter().any(|z| z.zone_id == "smoke-zone")
    })
    .await?;
    for i in 0..10 {
        va.set_position("smoke-zone", &[10.0 + i as f64, 50.0])?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until("B to see the last position", || {
        seen_b2.lock().unwrap().positions.last() == Some(&vec![19.0, 50.0])
    })
    .await?;
    let n = seen_b2.lock().unwrap().positions.len();
    assert!(n <= 4, "coalescing let {n} of 10 positions through");
    println!("ten positions in 100 ms coalesced to {n}, ending at the last");

    // A position in someone else's creator-only zone is refused, as an event.
    va.create_zone(
        "own-zone",
        "own",
        "2d",
        serde_json::json!({}),
        "creator_only",
    )
    .await?;
    until("B to see the creator-only zone", || {
        vb2.zones().iter().any(|z| z.zone_id == "own-zone")
    })
    .await?;
    vb2.set_position("own-zone", &[1.0, 1.0])?;
    until("B to be refused", || {
        !seen_b2.lock().unwrap().refused.is_empty()
    })
    .await?;
    println!(
        "B's position was refused: {}",
        seen_b2.lock().unwrap().refused[0]
    );

    assert!(seen_a.lock().unwrap().skipped.is_empty());
    assert_eq!(seen_a.lock().unwrap().rejoining, 0);
    va.leave().await?;
    vb2.leave().await?;
    println!("VOICE SMOKE OK");
    Ok(())
}
