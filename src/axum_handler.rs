//! A ready webhook endpoint for slash and component dispatch (feature `axum`).

use std::future::Future;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::apps::{Answer, Invocation};
use crate::webhooks::{
    unix_now, verify_dispatch, DeliveryHeaders, HEADER_HUB_PUBKEY, HEADER_SIGNATURE_V1,
    HEADER_TIMESTAMP,
};

#[derive(Clone)]
struct Config<F> {
    hub_pubkey: String,
    handler: F,
}

/// `POST /` verifies the delivery against `trusted_hub_pubkey` (see
/// [`crate::Client::hub_public_key`]), decodes it and answers with what
/// `handler` returns. A refused delivery is a 401 and never reaches the handler.
/// Nest the router at the path you registered as `webhook_url`.
pub fn router<F, Fut>(trusted_hub_pubkey: String, handler: F) -> Router
where
    F: Fn(Invocation) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Answer> + Send + 'static,
{
    Router::new()
        .route("/", post(receive::<F, Fut>))
        .with_state(Config {
            hub_pubkey: trusted_hub_pubkey,
            handler,
        })
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn receive<F, Fut>(State(cfg): State<Config<F>>, headers: HeaderMap, body: Bytes) -> Response
where
    F: Fn(Invocation) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Answer> + Send + 'static,
{
    let h = DeliveryHeaders {
        hub_pubkey: header(&headers, HEADER_HUB_PUBKEY),
        signature_v1: header(&headers, HEADER_SIGNATURE_V1),
        timestamp: header(&headers, HEADER_TIMESTAMP),
    };
    if let Err(e) = verify_dispatch(&cfg.hub_pubkey, &h, &body, unix_now()) {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    match Invocation::decode(&body) {
        Ok(inv) => Json((cfg.handler)(inv).await).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}
