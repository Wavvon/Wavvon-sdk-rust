use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::stream::BoxStream;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch, Mutex};

use crate::apps::{AppCommand, AppProfile, AppRegistration, Subscription};
use crate::auth::Identity;
use crate::caps::{self, Capabilities};
use crate::error::{Error, Result};
use crate::events::{ChatMessage, ClientMessage, Event, HubEvent};
use crate::generated;
use crate::pager::pager;
use crate::retry::{classify, RetryPolicy, Verdict};
use crate::session::Session;

#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    /// Spent only when the hub is `invite_only` and this identity is new.
    pub invite_code: Option<String>,
    pub retry: RetryPolicy,
}

/// What a program can observe about its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    /// The session or socket died and is being re-established.
    Reconnecting {
        attempt: u32,
    },
    /// The hub refused this identity outright; nothing will be retried.
    Closed,
}

#[derive(Deserialize)]
struct HubInfo {
    public_key: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
    #[serde(default)]
    scheme: Option<String>,
}

struct Inner {
    base: String,
    http: reqwest::Client,
    identity: Identity,
    invite_code: Option<String>,
    retry: RetryPolicy,
    session: Session,
    api: generated::Client,
    info: RwLock<(String, Capabilities)>,
    reauth: Mutex<()>,
    state: watch::Sender<ConnectionState>,
}

/// A session with one hub. Cheap to clone; clones share the session.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Reads `GET /info`, then authenticates. Both retry transient failures.
    pub async fn connect(
        hub_url: &str,
        identity: Identity,
        opts: ConnectOptions,
    ) -> Result<Client> {
        let base = hub_url.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(Error::Url(format!("{hub_url} is not an http(s) url")));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("wavvon-sdk-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Request(e.to_string()))?;
        let session = Session::default();
        let api = generated::Client::new_with_client(&base, http.clone(), session.clone());
        let (state, _) = watch::channel(ConnectionState::Connected);
        let client = Client {
            inner: Arc::new(Inner {
                base,
                http,
                identity,
                invite_code: opts.invite_code,
                retry: opts.retry,
                session,
                api,
                info: RwLock::new((String::new(), Capabilities::default())),
                reauth: Mutex::new(()),
                state,
            }),
        };
        client.refresh_info().await?;
        client.login().await?;
        Ok(client)
    }

    pub fn public_key(&self) -> String {
        self.inner.identity.public_key_hex()
    }

    /// The hub's own Ed25519 key, from `/info`: what a webhook verifier trusts.
    pub fn hub_public_key(&self) -> String {
        self.inner
            .info
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    pub fn capabilities(&self) -> Capabilities {
        self.inner
            .info
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .clone()
    }

    /// `Err(UnsupportedByHub)` unless `/info` listed exactly this string.
    pub fn require(&self, capability: &str) -> Result<()> {
        self.capabilities().require(capability)
    }

    pub async fn refresh_info(&self) -> Result<()> {
        let info: HubInfo = self.json(Method::GET, "/info", &[], None, false).await?;
        *self.inner.info.write().unwrap_or_else(|e| e.into_inner()) =
            (info.public_key, Capabilities::new(info.capabilities));
        Ok(())
    }

    pub fn state(&self) -> watch::Receiver<ConnectionState> {
        self.inner.state.subscribe()
    }

    pub(crate) fn set_state(&self, s: ConnectionState) {
        self.inner.state.send_replace(s);
    }

    pub(crate) fn token(&self) -> Option<String> {
        self.inner.session.get()
    }

    pub(crate) fn base(&self) -> &str {
        &self.inner.base
    }

    pub(crate) fn retry_policy(&self) -> &RetryPolicy {
        &self.inner.retry
    }

    /// The generated REST client for the whole API, carrying this session's
    /// token. Calls made directly have no retry; wrap them in [`Client::call`].
    pub fn rest(&self) -> generated::Client {
        self.inner.api.clone()
    }

    /// Runs a generated call with the SDK's retry and re-auth rules:
    ///
    /// ```ignore
    /// client.call(|api| async move { api.list_channels().send().await }).await?;
    /// ```
    pub async fn call<T, E, F, Fut>(&self, f: F) -> Result<generated::ResponseValue<T>>
    where
        F: Fn(generated::Client) -> Fut,
        Fut: Future<Output = std::result::Result<generated::ResponseValue<T>, generated::Error<E>>>,
        E: std::fmt::Debug,
    {
        let policy = self.retry_policy();
        let mut reauthed = false;
        let mut last = String::new();
        for attempt in 0..policy.max_attempts {
            let used = self.token();
            let (status, detail) = match f(self.rest()).await {
                Ok(v) => return Ok(v),
                Err(generated::Error::ErrorResponse(rv)) => {
                    (rv.status().as_u16(), format!("{:?}", rv.into_inner()))
                }
                Err(generated::Error::UnexpectedResponse(resp)) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Err(Error::Decode(format!("unexpected success status {status}")));
                    }
                    (status.as_u16(), resp.text().await.unwrap_or_default())
                }
                Err(generated::Error::InvalidRequest(m) | generated::Error::Custom(m)) => {
                    return Err(Error::Request(m))
                }
                Err(generated::Error::InvalidResponsePayload(_, e)) => {
                    return Err(Error::Decode(e.to_string()))
                }
                Err(
                    generated::Error::CommunicationError(e)
                    | generated::Error::ResponseBodyError(e)
                    | generated::Error::InvalidUpgrade(e),
                ) => {
                    if e.is_builder() {
                        return Err(Error::Request(e.to_string()));
                    }
                    last = e.to_string();
                    self.backoff(attempt).await;
                    continue;
                }
            };
            match classify(status) {
                Verdict::Answer => {
                    return Err(Error::Status {
                        status,
                        body: detail,
                    })
                }
                Verdict::Reauth if !reauthed => {
                    reauthed = true;
                    self.reauth(used).await?;
                }
                Verdict::Reauth => {
                    return Err(Error::Status {
                        status,
                        body: detail,
                    })
                }
                Verdict::Retry => {
                    last = format!("HTTP {status}");
                    self.backoff(attempt).await;
                }
            }
        }
        Err(Error::Transient {
            attempts: policy.max_attempts,
            last,
        })
    }

    async fn backoff(&self, attempt: u32) {
        tokio::time::sleep(self.inner.retry.delay(attempt)).await;
    }

    /// One request with the retry rules. A 429 or 5xx never comes back as an
    /// answer; a 401 on an authenticated call re-authenticates once.
    async fn execute(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        authed: bool,
    ) -> Result<reqwest::Response> {
        let policy = &self.inner.retry;
        let url = format!("{}{}", self.inner.base, path);
        let mut reauthed = false;
        let mut last = String::new();
        for attempt in 0..policy.max_attempts {
            let used = self.token();
            let mut req = self.inner.http.request(method.clone(), &url).query(query);
            if authed {
                if let Some(t) = &used {
                    req = req.bearer_auth(t);
                }
            }
            if let Some(b) = body {
                req = req.json(b);
            }
            match req.send().await {
                Err(e) if e.is_builder() => return Err(Error::Request(e.to_string())),
                Err(e) => {
                    last = e.to_string();
                    self.backoff(attempt).await;
                }
                Ok(resp) => match classify(resp.status().as_u16()) {
                    Verdict::Answer => return Ok(resp),
                    Verdict::Reauth if !authed || reauthed => return Ok(resp),
                    Verdict::Reauth => {
                        reauthed = true;
                        self.reauth(used).await?;
                    }
                    Verdict::Retry => {
                        last = format!("HTTP {}", resp.status().as_u16());
                        self.backoff(attempt).await;
                    }
                },
            }
        }
        Err(Error::Transient {
            attempts: policy.max_attempts,
            last,
        })
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        authed: bool,
    ) -> Result<T> {
        let resp = self.execute(method, path, query, body, authed).await?;
        let resp = ok_or_status(resp).await?;
        resp.json().await.map_err(|e| Error::Decode(e.to_string()))
    }

    /// Re-authenticates unless another caller already did since `stale` was
    /// read.
    pub(crate) async fn reauth(&self, stale: Option<String>) -> Result<()> {
        let _guard = self.inner.reauth.lock().await;
        if self.token() != stale {
            return Ok(());
        }
        self.set_state(ConnectionState::Reconnecting { attempt: 1 });
        match Box::pin(self.login()).await {
            Ok(()) => Ok(()),
            Err(e @ Error::Status { .. } | e @ Error::Auth(_)) => {
                self.set_state(ConnectionState::Closed);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// challenge, sign, verify. A 401 on verify (a challenge that expired or
    /// was spent by a request whose answer was lost) gets one fresh round.
    async fn login(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct Verified {
            token: String,
        }
        let pubkey = self.public_key();
        for round in 0..2 {
            let ch: ChallengeResponse = self
                .json(
                    Method::POST,
                    "/auth/challenge",
                    &[],
                    Some(&json!({ "public_key": pubkey })),
                    false,
                )
                .await?;
            let signature = self
                .inner
                .identity
                .sign_challenge(&ch.challenge, ch.scheme.as_deref())?;
            let mut body = json!({
                "public_key": pubkey,
                "challenge": ch.challenge,
                "signature": signature,
            });
            if let Some(code) = &self.inner.invite_code {
                body["invite_code"] = json!(code);
            }
            let resp = self
                .execute(Method::POST, "/auth/verify", &[], Some(&body), false)
                .await?;
            if resp.status().as_u16() == 401 && round == 0 {
                continue;
            }
            let verified: Verified = ok_or_status(resp)
                .await?
                .json()
                .await
                .map_err(|e| Error::Decode(e.to_string()))?;
            self.inner.session.set(Some(verified.token));
            self.set_state(ConnectionState::Connected);
            return Ok(());
        }
        unreachable!("second round always returns")
    }

    // ---- messages ----

    pub async fn send_message(
        &self,
        channel_id: &str,
        content: &str,
        reply_to: Option<&str>,
    ) -> Result<ChatMessage> {
        let mut body = json!({ "content": content });
        if let Some(r) = reply_to {
            body["reply_to"] = json!(r);
        }
        self.json(
            Method::POST,
            &format!("/channels/{}/messages", encode(channel_id)),
            &[],
            Some(&body),
            true,
        )
        .await
    }

    /// Every member, paging `GET /users` to exhaustion. Needs `list.cursor`:
    /// without it the hub ignores the cursor and one page is all there is.
    pub fn users(
        &self,
        limit: u64,
    ) -> Result<BoxStream<'static, Result<generated::types::UserInfo>>> {
        self.require(caps::LIST_CURSOR)?;
        let me = self.clone();
        Ok(pager(
            limit,
            |u: &generated::types::UserInfo| Some(u.public_key.clone()),
            move |cursor, limit| {
                let me = me.clone();
                async move {
                    let rv = me
                        .call(|api| {
                            let cursor = cursor.clone();
                            async move {
                                let mut req = api.list_users();
                                if let Some(n) = std::num::NonZeroU64::new(limit) {
                                    req = req.limit(n);
                                }
                                if let Some(c) = cursor {
                                    req = req.cursor(c);
                                }
                                req.send().await
                            }
                        })
                        .await?;
                    Ok(rv.into_inner())
                }
            },
        ))
    }

    // ---- app registration (apps.register) ----

    /// `None` when this identity has registered nothing yet.
    pub async fn app_registration(&self) -> Result<Option<AppRegistration>> {
        self.require(caps::APPS_REGISTER)?;
        match self.json(Method::GET, "/me/app", &[], None, true).await {
            Ok(r) => Ok(Some(r)),
            Err(Error::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Register before opening the event stream: the hub pushes `hub_event`
    /// only to a socket whose identity already had a profile when it connected.
    pub async fn put_app_profile(&self, profile: &AppProfile) -> Result<AppRegistration> {
        self.require(caps::APPS_REGISTER)?;
        self.json(
            Method::PUT,
            "/me/app/profile",
            &[],
            Some(&to_value(profile)?),
            true,
        )
        .await
    }

    pub async fn put_app_commands(&self, commands: &[AppCommand]) -> Result<()> {
        self.require(caps::APPS_REGISTER)?;
        let resp = self
            .execute(
                Method::PUT,
                "/me/app/commands",
                &[],
                Some(&json!({ "commands": to_value(&commands)? })),
                true,
            )
            .await?;
        ok_or_status(resp).await.map(|_| ())
    }

    /// Returns how many rows the hub stored.
    pub async fn put_app_subscriptions(&self, subscriptions: &[Subscription]) -> Result<u64> {
        self.require(caps::APPS_REGISTER)?;
        let v: Value = self
            .json(
                Method::PUT,
                "/me/app/subscriptions",
                &[],
                Some(&json!({ "subscriptions": to_value(&subscriptions)? })),
                true,
            )
            .await?;
        v.get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Decode("subscriptions response has no count".into()))
    }

    // ---- polling transport ----

    /// `GET /me/events`: the same `hub_event` envelopes the socket replays,
    /// oldest first, after `cursor` (the last `seq` handled). Nothing is
    /// acknowledged. No cursor starts at the beginning of the 72-hour window;
    /// a cursor older than it is [`Error::ReplayUnavailable`].
    pub async fn poll_events(
        &self,
        cursor: Option<i64>,
        limit: Option<u32>,
    ) -> Result<Vec<HubEvent>> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor", c.to_string()));
        }
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        let resp = self
            .execute(Method::GET, "/me/events", &query, None, true)
            .await?;
        if resp.status() == reqwest::StatusCode::GONE {
            #[derive(Deserialize)]
            struct Gone {
                earliest_seq: i64,
                earliest_at: i64,
            }
            let g: Gone = resp
                .json()
                .await
                .map_err(|e| Error::Decode(e.to_string()))?;
            return Err(Error::ReplayUnavailable {
                earliest_seq: g.earliest_seq,
                earliest_at: g.earliest_at,
            });
        }
        ok_or_status(resp)
            .await?
            .json()
            .await
            .map_err(|e| Error::Decode(e.to_string()))
    }

    // ---- websocket ----

    /// Opens the event loop on a background task. It reconnects on its own,
    /// re-authenticating when the token is refused and sending `resume` from
    /// the last `seq` it saw. Progress is visible on [`Client::state`].
    pub fn events(&self, opts: EventsOptions) -> EventStream {
        let (out_tx, out_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let last_seq = Arc::new(AtomicI64::new(opts.resume_from.unwrap_or(-1)));
        tokio::spawn(crate::ws::run(
            self.clone(),
            out_tx,
            cmd_rx,
            last_seq.clone(),
        ));
        EventStream {
            rx: out_rx,
            last_seq,
            sender: EventSender {
                tx: cmd_tx,
                app_id: self.public_key(),
            },
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EventsOptions {
    /// Replay from this `seq` on the first connect (the last one you processed).
    pub resume_from: Option<i64>,
}

/// Events from the hub. `next` returns `None` only after a definitive refusal
/// (yielded just before as `Err`) or when the stream is dropped.
pub struct EventStream {
    rx: mpsc::Receiver<Result<Event>>,
    last_seq: Arc<AtomicI64>,
    sender: EventSender,
}

impl EventStream {
    pub async fn next(&mut self) -> Option<Result<Event>> {
        self.rx.recv().await
    }

    /// The last `hub_event` `seq` seen; persist it to resume after a restart.
    pub fn last_seq(&self) -> Option<i64> {
        Some(self.last_seq.load(Ordering::Relaxed)).filter(|s| *s >= 0)
    }

    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }
}

/// Writes to the socket. Messages queue while the socket is reconnecting.
#[derive(Clone)]
pub struct EventSender {
    pub(crate) tx: mpsc::Sender<ClientMessage>,
    app_id: String,
}

impl EventSender {
    pub async fn send(&self, msg: ClientMessage) -> Result<()> {
        self.tx.send(msg).await.map_err(|_| Error::Closed)
    }

    /// Needed only for channels created after the socket connected.
    pub async fn subscribe(&self, channel_id: &str) -> Result<()> {
        self.send(ClientMessage::Subscribe {
            channel_id: channel_id.into(),
        })
        .await
    }

    /// Mini-app host: post a launch card in a channel. The hub answers the
    /// players' `app_join` itself.
    pub async fn announce_mini_app(
        &self,
        channel_id: &str,
        title: &str,
        description: &str,
    ) -> Result<()> {
        self.send(ClientMessage::AppAnnounce {
            title: title.into(),
            description: description.into(),
            channel_id: channel_id.into(),
        })
        .await
    }

    pub async fn dismiss_mini_app(&self, channel_id: &str) -> Result<()> {
        self.send(ClientMessage::AppDismiss {
            channel_id: channel_id.into(),
        })
        .await
    }

    /// Mini-app host: relay a payload to one joined player (there is no
    /// channel-wide broadcast). The payload travels as a JSON-encoded string.
    pub async fn send_to_player<T: Serialize>(
        &self,
        channel_id: &str,
        player_pubkey: &str,
        payload: &T,
    ) -> Result<()> {
        self.send(ClientMessage::MiniAppMessage {
            app_id: self.app_id.clone(),
            channel_id: channel_id.into(),
            payload: serde_json::to_string(payload).map_err(|e| Error::Request(e.to_string()))?,
            to_pubkey: Some(player_pubkey.into()),
        })
        .await
    }
}

fn to_value<T: Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Request(e.to_string()))
}

fn encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn ok_or_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status().as_u16();
    Err(Error::Status {
        status,
        body: resp.text().await.unwrap_or_default(),
    })
}
