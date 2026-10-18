//! Rust SDK for Wavvon hubs, tier 1: programs (bots and apps).
//!
//! A program is a client like any other: a keypair, the same challenge, the
//! same session. See `docs/docs/sdk.md` in Wavvon-docs for the contract.

pub mod apps;
pub mod auth;
#[cfg(feature = "axum")]
pub mod axum_handler;
pub mod caps;
mod client;
pub mod error;
pub mod events;
#[rustfmt::skip]
#[allow(unused_variables, rustdoc::invalid_html_tags, clippy::all)]
pub mod generated;
pub mod pager;
pub mod retry;
pub mod session;
pub mod webhooks;
mod ws;

pub use auth::Identity;
pub use caps::Capabilities;
pub use client::{
    Client, ConnectOptions, ConnectionState, EventSender, EventStream, EventsOptions,
};
pub use error::{Error, Result};
pub use events::{ClientMessage, Event, HubEvent};
