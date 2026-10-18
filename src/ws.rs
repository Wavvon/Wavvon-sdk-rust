//! The background task behind `Client::events`.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::client::{Client, ConnectionState};
use crate::error::{Error, Result};
use crate::events::{ClientMessage, Event};
use crate::retry::{classify, Verdict};

const PING_EVERY: Duration = Duration::from_secs(30);
const SILENCE_LIMIT: Duration = Duration::from_secs(90);

enum Ended {
    /// The program dropped the stream.
    Dropped,
    /// The socket went away; connect again.
    Lost,
}

pub(crate) async fn run(
    client: Client,
    out: mpsc::Sender<Result<Event>>,
    mut cmds: mpsc::Receiver<ClientMessage>,
    last_seq: Arc<AtomicI64>,
) {
    let mut attempt = 0u32;
    let mut pending: Option<ClientMessage> = None;
    loop {
        let token = client.token();
        let url = format!(
            "{}/ws?token={}",
            client.base().replacen("http", "ws", 1),
            token.clone().unwrap_or_default()
        );
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _)) => {
                client.set_state(ConnectionState::Connected);
                attempt = 0;
                match pump(ws, &out, &mut cmds, &last_seq, &mut pending).await {
                    Ended::Dropped => return,
                    Ended::Lost => {}
                }
            }
            Err(tungstenite::Error::Http(resp)) => {
                let status = resp.status().as_u16();
                match classify(status) {
                    Verdict::Reauth => {
                        if let Err(e) = client.reauth(token).await {
                            if !matches!(e, Error::Transient { .. }) {
                                let _ = out.send(Err(e)).await;
                                return;
                            }
                        }
                    }
                    Verdict::Retry => {}
                    Verdict::Answer => {
                        client.set_state(ConnectionState::Closed);
                        let _ = out
                            .send(Err(Error::Status {
                                status,
                                body: "websocket upgrade refused".into(),
                            }))
                            .await;
                        return;
                    }
                }
            }
            Err(_) => {}
        }
        attempt += 1;
        client.set_state(ConnectionState::Reconnecting { attempt });
        tokio::select! {
            _ = tokio::time::sleep(client.retry_policy().delay(attempt)) => {}
            _ = out.closed() => return,
        }
    }
}

async fn pump(
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    out: &mpsc::Sender<Result<Event>>,
    cmds: &mut mpsc::Receiver<ClientMessage>,
    last_seq: &AtomicI64,
    pending: &mut Option<ClientMessage>,
) -> Ended {
    let (mut tx, mut rx) = ws.split();
    let resume = last_seq.load(Ordering::Relaxed);
    if resume >= 0
        && send_json(&mut tx, &ClientMessage::Resume { since_seq: resume })
            .await
            .is_err()
    {
        return Ended::Lost;
    }
    let mut last_rx = Instant::now();
    let mut tick = tokio::time::interval(PING_EVERY);
    loop {
        if let Some(msg) = pending.take() {
            if send_json(&mut tx, &msg).await.is_err() {
                *pending = Some(msg);
                return Ended::Lost;
            }
        }
        tokio::select! {
            _ = out.closed() => return Ended::Dropped,
            frame = rx.next() => match frame {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return Ended::Lost,
                Some(Ok(Message::Text(text))) => {
                    last_rx = Instant::now();
                    let event = match serde_json::from_str(text.as_str()) {
                        Ok(raw) => Event::from_value(raw),
                        Err(e) => Event::Unknown { raw: serde_json::json!({ "undecodable": e.to_string(), "text": text.as_str() }) },
                    };
                    if let Event::Hub(h) = &event {
                        last_seq.store(h.seq, Ordering::Relaxed);
                    }
                    if out.send(Ok(event)).await.is_err() {
                        return Ended::Dropped;
                    }
                }
                Some(Ok(_)) => last_rx = Instant::now(),
            },
            cmd = cmds.recv() => match cmd {
                Some(c) => *pending = Some(c),
                None => return Ended::Dropped,
            },
            _ = tick.tick() => {
                if last_rx.elapsed() > SILENCE_LIMIT {
                    return Ended::Lost;
                }
                if tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return Ended::Lost;
                }
            }
        }
    }
}

async fn send_json<S>(tx: &mut S, msg: &ClientMessage) -> std::result::Result<(), ()>
where
    S: futures::Sink<Message> + Unpin,
{
    let text = serde_json::to_string(msg).map_err(|_| ())?;
    tx.send(Message::text(text)).await.map_err(|_| ())
}
