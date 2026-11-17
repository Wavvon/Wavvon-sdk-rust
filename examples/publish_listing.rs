//! Lists this program in a directory's invite directory, so people can find
//! it and invite it to their hub. Run it again after changing the listing;
//! pass `--remove` to take it down.
//!
//!   WAVVON_DIRECTORY=https://directory.example WAVVON_SEED=<64 hex> \
//!   WAVVON_HUB=https://hub.example cargo run --example publish_listing [-- --remove]

use wavvon_sdk::directory::{ListingApp, ListingCommand};
use wavvon_sdk::{publish_listing, unpublish_listing, Contact, Identity, Listing};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::from_seed_hex(&env("WAVVON_SEED"))?;
    let directory = env("WAVVON_DIRECTORY");
    if std::env::args().any(|a| a == "--remove") {
        let removed = unpublish_listing(&identity, &directory).await?;
        println!(
            "{}",
            if removed {
                "removed"
            } else {
                "there was no listing"
            }
        );
        return Ok(());
    }
    let listing = Listing {
        tagline: "Repeats what you say".into(),
        tags: vec!["utility".into()],
        languages: vec!["en".into()],
        app: Some(ListingApp {
            commands: Some(vec![ListingCommand {
                name: "shout".into(),
                description: "Repeat it louder".into(),
            }]),
            mini_app: None,
        }),
        // Or Contact::Endpoint for a program that runs a server of its own.
        ..Listing::new("Echo", Contact::HomeHub(env("WAVVON_HUB")))
    };
    println!(
        "listed at {}",
        publish_listing(&identity, &listing, &directory).await?
    );
    Ok(())
}
