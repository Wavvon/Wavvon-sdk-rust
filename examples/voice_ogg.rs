//! Plays an Ogg Opus file into a voice channel. The packets are demuxed and
//! passed through as they are: no codec, no native library. Each must be a
//! single 20 ms frame (`opusenc --framesize 20`, its default); the SDK
//! refuses anything else, because desktop listeners could not play it.
//!
//!   WAVVON_HUB=http://localhost:3000 WAVVON_SEED=<64 hex> [WAVVON_INVITE=code] \
//!   cargo run --example voice_ogg --features voice -- <channel id> <file.opus>
//!
//! Only play what may be redistributed: public domain, CC0, or a Creative
//! Commons licence that allows it. The SDK carries audio and judges none of it.

use std::fs::File;

use ogg::reading::PacketReader;
use wavvon_sdk::{Client, ConnectOptions, Identity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (channel, path) = match (args.next(), args.next()) {
        (Some(c), Some(p)) => (c, p),
        _ => return Err("usage: voice_ogg <channel id> <file.opus>".into()),
    };
    let identity = Identity::from_seed_hex(&std::env::var("WAVVON_SEED")?)?;
    let opts = ConnectOptions {
        invite_code: std::env::var("WAVVON_INVITE").ok(),
        ..Default::default()
    };
    let client = Client::connect(&std::env::var("WAVVON_HUB")?, identity, opts).await?;
    let voice = client.join_voice(&channel).await?;

    // The room's events must be read or they pile up; this program only
    // watches for the floor being taken away.
    let events = voice.clone();
    tokio::spawn(async move {
        while let Some(ev) = events.next().await {
            if let Err(e) = ev {
                eprintln!("voice: {e}");
            }
        }
    });

    let mut reader = PacketReader::new(File::open(path)?);
    let mut sent = 0u64;
    while let Some(packet) = reader.read_packet()? {
        // OpusHead and OpusTags are the first two packets of the stream.
        if packet.data.starts_with(b"OpusHead") || packet.data.starts_with(b"OpusTags") {
            continue;
        }
        // Held to real time by the SDK: reading the file is not the clock.
        voice.send_opus(&packet.data).await?;
        sent += 1;
    }
    println!("sent {sent} packets ({} s)", sent / 50);
    voice.leave().await?;
    Ok(())
}
