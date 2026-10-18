//! The SDK's session behaviour against an in-process fake hub: retry, re-auth,
//! capability gating, paging and the WebSocket resume. The real-hub check is
//! `examples/smoke.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use serde_json::{json, Value};
use wavvon_sdk::apps::AppProfile;
use wavvon_sdk::retry::RetryPolicy;
use wavvon_sdk::{Client, ConnectOptions, Error, Event, EventsOptions, Identity};

struct Mock {
    caps: Vec<&'static str>,
    challenge_429s: AtomicU32,
    logins: AtomicU32,
    valid_token: Mutex<String>,
    me_app_503s: AtomicU32,
    ws_conns: AtomicU32,
    resumes: Mutex<Vec<i64>>,
}

type Shared = Arc<Mock>;

fn take_one(counter: &AtomicU32) -> bool {
    loop {
        let n = counter.load(Ordering::SeqCst);
        if n == 0 {
            return false;
        }
        if counter
            .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

fn authed(m: &Mock, h: &HeaderMap) -> bool {
    let want = format!("Bearer {}", m.valid_token.lock().unwrap());
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some(want.as_str())
}

async fn info(State(m): State<Shared>) -> Json<Value> {
    Json(json!({ "public_key": "ab".repeat(32), "capabilities": m.caps }))
}

async fn challenge(State(m): State<Shared>) -> Response {
    if take_one(&m.challenge_429s) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    Json(json!({ "challenge": "00".repeat(32), "scheme": "tagged-v1" })).into_response()
}

async fn verify(State(m): State<Shared>, Json(body): Json<Value>) -> Response {
    if body["signature"].as_str().map_or(0, str::len) != 128 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let n = m.logins.fetch_add(1, Ordering::SeqCst) + 1;
    let token = format!("tok-{n}");
    *m.valid_token.lock().unwrap() = token.clone();
    Json(json!({ "token": token })).into_response()
}

async fn me_app(State(m): State<Shared>, h: HeaderMap) -> Response {
    if !authed(&m, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if take_one(&m.me_app_503s) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (StatusCode::NOT_FOUND, "No app registered for this identity").into_response()
}

async fn always_503() -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

async fn post_message(State(m): State<Shared>, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !authed(&m, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({
        "id": "m1", "channel_id": "c", "sender": "s", "content": b["content"], "created_at": 1
    }))
    .into_response()
}

async fn users(
    State(m): State<Shared>,
    h: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !authed(&m, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let all: Vec<String> = (0..5).map(|i| format!("u{i}")).collect();
    let limit: usize = q.get("limit").map_or(200, |l| l.parse().unwrap());
    let start = q
        .get("cursor")
        .map_or(0, |c| all.iter().position(|u| u == c).unwrap() + 1);
    let page: Vec<Value> = all
        .iter()
        .skip(start)
        .take(limit)
        .map(|u| json!({ "public_key": u, "online": false, "avatar": null, "birthday": null, "display_name": null, "group_role": null, "name_color": null }))
        .collect();
    Json(page).into_response()
}

async fn ws(
    State(m): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
    up: WebSocketUpgrade,
) -> Response {
    if q.get("token") != Some(&*m.valid_token.lock().unwrap()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    up.on_upgrade(move |socket| serve_ws(m, socket))
}

fn hub_event(seq: i64) -> Message {
    Message::text(
        json!({ "type": "hub_event", "seq": seq, "event": "member.joined",
                "hub_url": "h", "at": 1, "payload": {} })
        .to_string(),
    )
}

async fn serve_ws(m: Shared, mut socket: WebSocket) {
    let conn = m.ws_conns.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = socket
        .send(Message::text(
            json!({ "type": "hello", "live_seq": 0 }).to_string(),
        ))
        .await;
    if conn == 1 {
        let _ = socket.send(hub_event(1)).await;
        let _ = socket.send(hub_event(2)).await;
        let _ = socket
            .send(Message::text(
                json!({ "type": "voice_joined", "channel_id": "c" }).to_string(),
            ))
            .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        return;
    }
    while let Some(Ok(Message::Text(t))) = socket.recv().await {
        let v: Value = serde_json::from_str(t.as_str()).unwrap();
        if v["type"] == "resume" {
            m.resumes
                .lock()
                .unwrap()
                .push(v["since_seq"].as_i64().unwrap());
            let _ = socket.send(hub_event(3)).await;
            let _ = socket
                .send(Message::text(
                    json!({ "type": "replay_unavailable", "earliest_seq": 9, "earliest_at": 1 })
                        .to_string(),
                ))
                .await;
        }
    }
}

async fn spawn(caps: &[&'static str], challenge_429s: u32, me_app_503s: u32) -> (String, Shared) {
    let mock = Arc::new(Mock {
        caps: caps.to_vec(),
        challenge_429s: AtomicU32::new(challenge_429s),
        logins: AtomicU32::new(0),
        valid_token: Mutex::new(String::new()),
        me_app_503s: AtomicU32::new(me_app_503s),
        ws_conns: AtomicU32::new(0),
        resumes: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/info", get(info))
        .route("/auth/challenge", post(challenge))
        .route("/auth/verify", post(verify))
        .route("/me/app", get(me_app))
        .route("/me/app/profile", axum::routing::put(always_503))
        .route("/me/events", get(always_503))
        .route("/channels/{id}/messages", post(post_message))
        .route("/users", get(users))
        .route("/ws", get(ws))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, mock)
}

fn fast() -> ConnectOptions {
    ConnectOptions {
        invite_code: None,
        retry: RetryPolicy {
            max_attempts: 4,
            base: Duration::from_millis(5),
            cap: Duration::from_millis(20),
        },
    }
}

async fn connect(url: &str) -> Client {
    Client::connect(url, Identity::from_seed([5; 32]), fast())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_429_on_the_challenge_is_retried_not_returned() {
    let (url, mock) = spawn(&["apps.register"], 2, 0).await;
    let client = connect(&url).await;
    assert_eq!(mock.logins.load(Ordering::SeqCst), 1);
    assert!(client.capabilities().has("apps.register"));
}

#[tokio::test]
async fn a_hub_that_never_answers_is_transient_never_an_answer() {
    let (url, _) = spawn(&["apps.register"], 0, 0).await;
    let client = connect(&url).await;
    let err = client.poll_events(None).await.unwrap_err();
    assert!(
        matches!(err, Error::Transient { attempts: 4, .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn transient_503s_then_a_definitive_404_is_none() {
    let (url, _) = spawn(&["apps.register"], 0, 2).await;
    let client = connect(&url).await;
    assert!(client.app_registration().await.unwrap().is_none());
}

#[tokio::test]
async fn missing_capability_is_a_typed_error_before_any_request() {
    let (url, _) = spawn(&[], 0, 0).await;
    let client = connect(&url).await;
    let err = client
        .put_app_profile(&AppProfile::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedByHub(c) if c == "apps.register"));
    assert!(matches!(client.users(2), Err(Error::UnsupportedByHub(_))));
}

#[tokio::test]
async fn a_dead_session_reauthenticates_by_itself() {
    let (url, mock) = spawn(&["apps.register"], 0, 0).await;
    let client = connect(&url).await;
    *mock.valid_token.lock().unwrap() = "revoked-elsewhere".into();
    let m = client.send_message("chan", "hi", None).await.unwrap();
    assert_eq!(m.content, "hi");
    assert_eq!(mock.logins.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn users_pager_walks_every_page_through_the_generated_client() {
    let (url, _) = spawn(&["list.cursor"], 0, 0).await;
    let client = connect(&url).await;
    let keys: Vec<String> = client
        .users(2)
        .unwrap()
        .map(|u| u.unwrap().public_key)
        .collect()
        .await;
    assert_eq!(keys, ["u0", "u1", "u2", "u3", "u4"]);
}

#[tokio::test]
async fn websocket_reconnects_and_resumes_from_the_last_seq() {
    let (url, mock) = spawn(&["apps.register"], 0, 0).await;
    let client = connect(&url).await;
    let mut events = client.events(EventsOptions::default());

    let mut seen = Vec::new();
    while seen.len() < 7 {
        let ev = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("event in time")
            .expect("stream open")
            .expect("no fatal error");
        seen.push(ev);
    }
    assert!(matches!(seen[0], Event::Hello { .. }));
    assert!(matches!(&seen[1], Event::Hub(h) if h.seq == 1));
    assert!(matches!(&seen[2], Event::Hub(h) if h.seq == 2));
    assert!(matches!(&seen[3], Event::Unknown { raw } if raw["type"] == "voice_joined"));
    assert!(matches!(seen[4], Event::Hello { .. }), "second connection");
    assert!(matches!(&seen[5], Event::Hub(h) if h.seq == 3));
    assert!(
        matches!(
            seen[6],
            Event::ReplayUnavailable {
                earliest_seq: 9,
                ..
            }
        ),
        "replay_unavailable must reach the program"
    );
    assert_eq!(*mock.resumes.lock().unwrap(), vec![2]);
    assert_eq!(events.last_seq(), Some(3));
}
