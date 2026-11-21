//! A program in a voice channel (sdk-voice.md). It does exactly what the
//! desktop and web clients do: voice signalling rides one chat WebSocket, the
//! audio rides a WebRTC data channel, and every packet is sealed with a
//! per-sender key wrapped to each listener's DH key.
//!
//! The SDK owns the mechanisms (key distribution and rotation, 20 ms pacing,
//! the replay watermark, the proximity rate limit). It decides nothing for the
//! program: mute, deafen, AFK moves and what to do with a changed DH key are
//! events and calls.

mod opus;
mod transport;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngExt;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Instant;
use wavvon_identity::{voice_key_unwrap, voice_key_wrap, voice_packet_open, voice_packet_seal};

use crate::client::{Client, EventSender, EventStream, EventsOptions};
use crate::dm::per_message;
use crate::error::{Error, Result, VoiceError};
use crate::events::{ClientMessage, Event, VoiceKeyBundle};

const FRAME: Duration = Duration::from_millis(20);
const FRAME_SAMPLES: u32 = 960;
/// A program this far behind is re-anchored instead of bursting to catch up.
const MAX_LAG_FRAMES: u32 = 3;
/// More than one position every 50 ms risks the hub's silent 30 ms rate drop.
const POSITION_EVERY: Duration = Duration::from_millis(50);
const SPEAKING_IDLE: Duration = Duration::from_millis(200);
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Default)]
pub struct VoiceOptions {
    /// `voice-pcm` only: encode with the `audio` application (music) instead
    /// of `voip`.
    pub music: bool,
    /// `voice-pcm` only: encoder bitrate in bits per second; the encoder's own
    /// choice when unset.
    pub bitrate: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Participant {
    pub public_key: String,
    pub sender_id: u16,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Zone {
    pub zone_id: String,
    pub name: String,
    /// `"2d"` or `"3d"`.
    pub coordinate_system: String,
    pub attenuation: Value,
    pub positions: HashMap<String, Vec<f64>>,
}

/// One decrypted 20 ms packet from one speaker. Jitter buffering is the
/// program's: frames arrive as they come, with `ts` and `ctr` to order by.
#[derive(Clone, Debug)]
pub struct AudioFrame {
    pub from: String,
    pub sender_id: u16,
    pub key_id: u32,
    /// 48 kHz sample clock, +960 per frame.
    pub ts: u32,
    pub ctr: u64,
    pub whisper: bool,
    pub opus: Vec<u8>,
    /// Decoded 48 kHz mono PCM, with `voice-pcm`.
    pub pcm: Option<Vec<f32>>,
}

#[derive(Clone, Debug)]
pub enum VoiceEvent {
    Audio(AudioFrame),
    /// Who is in the room, after any change.
    Roster(Vec<Participant>),
    Speaking {
        public_key: String,
        speaking: bool,
    },
    /// The room's zones, after any change.
    Zones(Vec<Zone>),
    Position {
        zone_id: String,
        public_key: String,
        position: Vec<f64>,
    },
    /// The hub refused a position update (unknown zone, or a creator-only
    /// zone this program did not create). The program decides what to do.
    PositionRefused {
        reason: String,
    },
    /// A moderator gave this program the floor; `may_speak` is now true.
    TalkGranted,
    /// A moderator, or the AFK sweep (`auto`), asks the program to move. The
    /// hub moves no one: the program decides.
    MoveRequested {
        target_channel_id: String,
        target_channel_name: String,
        source_channel_id: Option<String>,
        event_id: Option<String>,
        auto: bool,
    },
    /// The socket dropped, which ended the room on the hub; the SDK is
    /// joining again with a fresh key.
    Rejoining,
    /// A participant could not be given this program's key (no DH key
    /// published, or a changed one), so it cannot hear the program.
    KeySkipped {
        public_key: String,
        reason: String,
    },
    /// A `voice_*` message this SDK does not model.
    Unknown {
        raw: Value,
    },
}

struct OwnKey {
    key: [u8; 32],
    salt: [u8; 4],
    key_id: u32,
    ctr: u64,
}

struct Pacing {
    next: Instant,
    ts: u32,
}

struct State {
    channel_id: String,
    sender_id: u16,
    in_room: bool,
    may_speak: bool,
    muted: bool,
    deafened: bool,
    roster: HashMap<u16, Participant>,
    own: OwnKey,
    remote: HashMap<(String, u32), ([u8; 32], [u8; 4])>,
    marks: HashMap<(u16, u32), u64>,
    zones: Vec<Zone>,
    conn: Option<Arc<transport::Link>>,
    pacing: Option<Pacing>,
    speaking: bool,
    last_send: Instant,
    position: Option<(String, Vec<f64>)>,
    last_position: Instant,
}

#[cfg(feature = "voice-pcm")]
type Decoders = HashMap<u16, audiopus::coder::Decoder>;
#[cfg(not(feature = "voice-pcm"))]
type Decoders = ();

enum Cmd {
    Leave,
}

struct Core {
    client: Client,
    sender: EventSender,
    state: Mutex<State>,
    out: mpsc::UnboundedSender<Result<VoiceEvent>>,
    cmd: mpsc::UnboundedSender<Cmd>,
    dh: Mutex<HashMap<String, [u8; 32]>>,
    #[cfg(feature = "voice-pcm")]
    encoder: Mutex<audiopus::coder::Encoder>,
}

/// A joined voice room. Cheap to clone: one task can `send_*` while another
/// reads `next`.
#[derive(Clone)]
pub struct Voice {
    core: Arc<Core>,
    events: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Result<VoiceEvent>>>>,
}

impl Client {
    /// Publishes the DH key, joins the channel's voice room and opens the
    /// audio session. One room per client: the hub allows one per identity.
    pub async fn join_voice(&self, channel_id: &str) -> Result<Voice> {
        self.join_voice_with(channel_id, VoiceOptions::default())
            .await
    }

    pub async fn join_voice_with(&self, channel_id: &str, opts: VoiceOptions) -> Result<Voice> {
        self.require("channels.voice")?;
        // Voice transport v3: a hub without it speaks only WebTransport, which
        // this SDK no longer carries.
        self.require("voice.webrtc")?;
        // Without a published key nobody wraps a voice key to this program and
        // it cannot unwrap theirs: it would be deaf and mute.
        self.publish_dh_key().await?;
        // A socket of its own: the hub ties the room to the connection, so
        // this one carries voice and nothing else the program reads.
        let mut events = self.events(EventsOptions::default());
        let sender = events.sender();
        step(wait_hello(&mut events)).await??;

        let (out, out_rx) = mpsc::unbounded_channel();
        let (cmd, cmd_rx) = mpsc::unbounded_channel();
        let core = Arc::new(Core {
            client: self.clone(),
            sender,
            state: Mutex::new(State::new(channel_id)),
            out,
            cmd,
            dh: Mutex::new(HashMap::new()),
            #[cfg(feature = "voice-pcm")]
            encoder: Mutex::new(new_encoder(&opts)?),
        });
        let _ = &opts;
        establish(&core, &mut events, channel_id).await?;
        tokio::spawn(run(core.clone(), events, cmd_rx));
        Ok(Voice {
            core,
            events: Arc::new(tokio::sync::Mutex::new(out_rx)),
        })
    }
}

impl State {
    fn new(channel_id: &str) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            sender_id: 0,
            in_room: false,
            may_speak: true,
            muted: false,
            deafened: false,
            roster: HashMap::new(),
            own: OwnKey {
                key: [0; 32],
                salt: [0; 4],
                key_id: 0,
                ctr: 0,
            },
            remote: HashMap::new(),
            marks: HashMap::new(),
            zones: Vec::new(),
            conn: None,
            pacing: None,
            speaking: false,
            last_send: Instant::now(),
            position: None,
            last_position: Instant::now() - POSITION_EVERY,
        }
    }
}

async fn step<T>(f: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::time::timeout(STEP_TIMEOUT, f)
        .await
        .map_err(|_| VoiceError::Transport("timed out waiting for the hub".into()).into())
}

async fn wait_hello(events: &mut EventStream) -> Result<()> {
    loop {
        match events.next().await {
            Some(Ok(Event::Hello { .. })) => return Ok(()),
            Some(Err(e)) => return Err(e),
            None => return Err(Error::Closed),
            Some(Ok(_)) => {}
        }
    }
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_default()
}

fn participant(v: &Value) -> Option<Participant> {
    Some(Participant {
        public_key: v["public_key"].as_str()?.to_string(),
        sender_id: u16::try_from(v["sender_id"].as_u64()?).ok()?,
        display_name: v["display_name"].as_str().map(str::to_string),
    })
}

fn zone(v: &Value) -> Option<Zone> {
    Some(Zone {
        zone_id: v["zone_id"].as_str()?.to_string(),
        name: str_of(v, "name").to_string(),
        coordinate_system: str_of(v, "coordinate_system").to_string(),
        attenuation: v["attenuation"].clone(),
        positions: v["positions"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, p)| {
                        let p: Vec<f64> = p.as_array()?.iter().filter_map(Value::as_f64).collect();
                        Some((k.clone(), p))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// `voice_join` to an open session: joined, audio connected, key offered.
/// Used for the first join and again after every dropped socket.
async fn establish(core: &Arc<Core>, events: &mut EventStream, channel_id: &str) -> Result<()> {
    core.sender
        .send(ClientMessage::VoiceJoin {
            channel_id: channel_id.to_string(),
        })
        .await?;
    let joined = step(async {
        loop {
            match events.next().await {
                Some(Ok(Event::Unknown { raw })) if raw["type"] == "voice_joined" => {
                    return Ok(raw)
                }
                Some(Ok(Event::Error { context, message })) if context == "voice_join" => {
                    return Err(VoiceError::Refused(message).into())
                }
                Some(Err(e)) => return Err(e),
                None => return Err(Error::Closed),
                Some(Ok(_)) => {}
            }
        }
    })
    .await??;

    let token = str_of(&joined, "voice_token").to_string();
    let (link, deferred) = connect_transport(core, events, &token).await?;
    let conn = Arc::new(link);

    let participants: Vec<Participant> = joined["participants"]
        .as_array()
        .map(|a| a.iter().filter_map(participant).collect())
        .unwrap_or_default();
    let me = core.client.public_key();
    let mut key = [0u8; 32];
    let mut salt = [0u8; 4];
    rand::rng().fill(&mut key);
    rand::rng().fill(&mut salt);
    let others: Vec<String> = participants
        .iter()
        .filter(|p| p.public_key != me)
        .map(|p| p.public_key.clone())
        .collect();
    {
        let mut st = lock(&core.state);
        // The key id never goes back: a rejoin must not reuse a (sender,
        // key_id) pair whose replay watermark listeners still hold.
        let key_id = st.own.key_id + 1;
        st.channel_id = str_of(&joined, "channel_id").to_string();
        st.sender_id = u16::try_from(joined["sender_id"].as_u64().unwrap_or_default())
            .map_err(|_| Error::Decode("sender_id out of range".into()))?;
        st.own = OwnKey {
            key,
            salt,
            key_id,
            ctr: 0,
        };
        // A hub without `voice.talk` omits the field; absence is not "muted".
        st.may_speak = joined["may_speak"].as_bool().unwrap_or(true);
        st.roster = participants.into_iter().map(|p| (p.sender_id, p)).collect();
        st.remote.clear();
        st.marks.clear();
        st.pacing = None;
        st.speaking = false;
        st.conn = Some(conn);
        st.in_room = true;
    }
    spawn_offer(core, others);
    // What arrived while the answer was awaited, a key bundle above all:
    // dropping it would leave this room unable to open that speaker.
    for ev in deferred {
        handle_event(core, ev);
    }
    Ok(())
}

/// Offers a WebRTC session bound by the voice token and waits for the hub's
/// answer on the same socket, keeping every other event that arrives meanwhile.
async fn connect_transport(
    core: &Arc<Core>,
    events: &mut EventStream,
    token: &str,
) -> Result<(transport::Link, Vec<Event>)> {
    let bad = |e: String| -> Error { VoiceError::Transport(e).into() };
    let host = url::Url::parse(core.client.base())
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or_else(|| bad("hub URL has no host".into()))?;
    let (offer, sdp) = transport::Offer::new(&host).await.map_err(bad)?;
    core.sender
        .send(ClientMessage::VoiceRtcOffer {
            token: token.to_string(),
            sdp,
        })
        .await?;
    let mut deferred = Vec::new();
    let answer = step(async {
        loop {
            match events.next().await {
                Some(Ok(Event::Unknown { raw })) if raw["type"] == "voice_rtc_answer" => {
                    return Ok(str_of(&raw, "sdp").to_string())
                }
                Some(Ok(Event::Error { context, message })) if context == "voice_rtc_offer" => {
                    return Err(VoiceError::Refused(message).into())
                }
                Some(Err(e)) => return Err(e),
                None => return Err(Error::Closed),
                Some(Ok(ev)) => deferred.push(ev),
            }
        }
    })
    .await??;
    Ok((offer.accept(&answer).map_err(bad)?, deferred))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Core {
    fn emit(&self, ev: VoiceEvent) {
        let _ = self.out.send(Ok(ev));
    }

    fn fail(&self, e: Error) {
        let _ = self.out.send(Err(e));
    }

    /// A peer's DH key, looked up once per session: it is pinned, so a second
    /// answer would be the same or a refusal.
    async fn dh_for(&self, pubkey: &str) -> Result<[u8; 32]> {
        if let Some(k) = lock(&self.dh).get(pubkey) {
            return Ok(*k);
        }
        let k = self.client.peer_dh_key(pubkey).await?;
        lock(&self.dh).insert(pubkey.to_string(), k);
        Ok(k)
    }
}

/// Wraps the current sender key to each of `to` and sends one offer. A peer
/// without a usable DH key is skipped and reported, as every client does.
fn spawn_offer(core: &Arc<Core>, to: Vec<String>) {
    if to.is_empty() {
        return;
    }
    let core = core.clone();
    tokio::spawn(async move {
        let (channel, key, salt, key_id) = {
            let st = lock(&core.state);
            (
                st.channel_id.clone(),
                st.own.key,
                st.own.salt,
                st.own.key_id,
            )
        };
        let seed = core.client.identity().seed();
        let mut bundles = Vec::new();
        for pubkey in to {
            let dh = match core.dh_for(&pubkey).await {
                Ok(k) => k,
                Err(e) if per_message(&e) => {
                    core.emit(VoiceEvent::KeySkipped {
                        public_key: pubkey,
                        reason: e.to_string(),
                    });
                    continue;
                }
                Err(e) => {
                    core.fail(e);
                    return;
                }
            };
            match voice_key_wrap(&seed, &dh, &channel, &key, &salt, key_id) {
                Ok((ct, nonce)) => bundles.push(VoiceKeyBundle {
                    recipient_pubkey: pubkey,
                    ciphertext_hex: hex::encode(ct),
                    nonce_hex: hex::encode(nonce),
                }),
                Err(e) => core.fail(VoiceError::Codec(e.to_string()).into()),
            }
        }
        if bundles.is_empty() {
            return;
        }
        let offer = ClientMessage::VoiceKeyOffer {
            channel_id: channel,
            bundles,
        };
        if let Err(e) = core.sender.send(offer).await {
            core.fail(e);
        }
    });
}

fn spawn_unwrap(core: &Arc<Core>, raw: Value) {
    let core = core.clone();
    tokio::spawn(async move {
        let from = str_of(&raw, "from_pubkey").to_string();
        let channel = lock(&core.state).channel_id.clone();
        let (Ok(ct), Ok(nonce)) = (
            hex::decode(str_of(&raw, "ciphertext_hex")),
            hex::decode(str_of(&raw, "nonce_hex")),
        ) else {
            return;
        };
        let Ok(nonce) = <[u8; 12]>::try_from(nonce) else {
            return;
        };
        let dh = match core.dh_for(&from).await {
            Ok(k) => k,
            Err(e) if per_message(&e) => {
                core.emit(VoiceEvent::KeySkipped {
                    public_key: from,
                    reason: e.to_string(),
                });
                return;
            }
            Err(e) => {
                core.fail(e);
                return;
            }
        };
        // A bundle that does not open is dropped: there is no key to use.
        let Ok((key, salt, key_id)) =
            voice_key_unwrap(&core.client.identity().seed(), &dh, &channel, &ct, &nonce)
        else {
            return;
        };
        let mut st = lock(&core.state);
        // A new key for this pair restarts its counter.
        let ids: Vec<u16> = st
            .roster
            .values()
            .filter(|p| p.public_key == from)
            .map(|p| p.sender_id)
            .collect();
        for id in ids {
            st.marks.remove(&(id, key_id));
        }
        st.remote.insert((from, key_id), (key, salt));
    });
}

async fn run(core: Arc<Core>, mut events: EventStream, mut cmds: mpsc::UnboundedReceiver<Cmd>) {
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    #[cfg_attr(not(feature = "voice-pcm"), allow(clippy::let_unit_value))]
    let mut decoders = Decoders::default();
    loop {
        let conn = lock(&core.state).conn.clone();
        tokio::select! {
            biased;
            _ = cmds.recv() => break,
            _ = core.out.closed() => break,
            ev = events.next() => match ev {
                None => break,
                Some(Err(e)) => core.fail(e),
                Some(Ok(Event::Hello { .. })) => rejoin(&core, &mut events).await,
                Some(Ok(ev)) => handle_event(&core, ev),
            },
            dg = receive(&conn) => match dg {
                Ok(payload) => handle_datagram(&core, &payload, &mut decoders),
                Err(e) => {
                    let mut st = lock(&core.state);
                    st.conn = None;
                    // After leave or during a rejoin the close is ours.
                    if st.in_room {
                        drop(st);
                        core.fail(VoiceError::Transport(e).into());
                    }
                }
            },
            _ = tick.tick() => housekeeping(&core),
        }
    }
}

async fn receive(conn: &Option<Arc<transport::Link>>) -> std::result::Result<Vec<u8>, String> {
    match conn {
        Some(c) => c.recv().await,
        None => std::future::pending().await,
    }
}

/// A second `hello` means the socket dropped and came back: the hub already
/// ran `leave_voice`, so the old session is dead. Join again.
async fn rejoin(core: &Arc<Core>, events: &mut EventStream) {
    let channel = {
        let mut st = lock(&core.state);
        st.in_room = false;
        // Dropping the link ends its session.
        st.conn = None;
        st.channel_id.clone()
    };
    core.emit(VoiceEvent::Rejoining);
    if let Err(e) = establish(core, events, &channel).await {
        core.fail(e);
    }
}

fn handle_event(core: &Arc<Core>, ev: Event) {
    let me = core.client.public_key();
    match ev {
        Event::Error { context, message } if context == "voice_position_update" => {
            core.emit(VoiceEvent::PositionRefused { reason: message });
        }
        Event::Error { context, message } if context.starts_with("voice") => {
            core.fail(VoiceError::Refused(format!("{context}: {message}")).into());
        }
        Event::Unknown { raw } => {
            let Some(kind) = raw["type"].as_str() else {
                return;
            };
            if !kind.starts_with("voice_") {
                return;
            }
            let ours = {
                let st = lock(&core.state);
                // Messages about another room are not this session's.
                raw["channel_id"]
                    .as_str()
                    .is_none_or(|c| c == st.channel_id)
            };
            if !ours {
                return;
            }
            match kind {
                "voice_participant_joined" => {
                    if let Some(p) = participant(&raw["participant"]) {
                        let mut st = lock(&core.state);
                        st.roster.insert(p.sender_id, p);
                        let list = roster_list(&st);
                        drop(st);
                        core.emit(VoiceEvent::Roster(list));
                    }
                }
                "voice_participant_left" => {
                    let left = str_of(&raw, "public_key").to_string();
                    let (list, remaining) = {
                        let mut st = lock(&core.state);
                        let ids: Vec<u16> = st
                            .roster
                            .values()
                            .filter(|p| p.public_key == left)
                            .map(|p| p.sender_id)
                            .collect();
                        for id in ids {
                            st.roster.remove(&id);
                            st.marks.retain(|(s, _), _| *s != id);
                        }
                        st.remote.retain(|(pk, _), _| *pk != left);
                        // Whoever left kept the key: a new one for the rest.
                        let mut key = [0u8; 32];
                        let mut salt = [0u8; 4];
                        rand::rng().fill(&mut key);
                        rand::rng().fill(&mut salt);
                        st.own = OwnKey {
                            key,
                            salt,
                            key_id: st.own.key_id + 1,
                            ctr: 0,
                        };
                        let remaining: Vec<String> = st
                            .roster
                            .values()
                            .filter(|p| p.public_key != me)
                            .map(|p| p.public_key.clone())
                            .collect();
                        (roster_list(&st), remaining)
                    };
                    core.emit(VoiceEvent::Roster(list));
                    spawn_offer(core, remaining);
                }
                "voice_roster_update" => {
                    let entries: Vec<Participant> = raw["participants"]
                        .as_array()
                        .map(|a| a.iter().filter_map(participant).collect())
                        .unwrap_or_default();
                    let mut st = lock(&core.state);
                    st.roster = entries.into_iter().map(|p| (p.sender_id, p)).collect();
                    let list = roster_list(&st);
                    drop(st);
                    core.emit(VoiceEvent::Roster(list));
                }
                "voice_participant_speaking" => core.emit(VoiceEvent::Speaking {
                    public_key: str_of(&raw, "public_key").to_string(),
                    speaking: raw["speaking"].as_bool().unwrap_or(false),
                }),
                "voice_key_request" => {
                    let newcomer = str_of(&raw, "new_pubkey").to_string();
                    if let Some(id) = raw["new_sender_id"]
                        .as_u64()
                        .and_then(|v| u16::try_from(v).ok())
                    {
                        lock(&core.state)
                            .roster
                            .entry(id)
                            .or_insert_with(|| Participant {
                                public_key: newcomer.clone(),
                                sender_id: id,
                                display_name: None,
                            });
                    }
                    if newcomer != me {
                        spawn_offer(core, vec![newcomer]);
                    }
                }
                "voice_key_received" => {
                    if let Some(id) = raw["from_sender_id"]
                        .as_u64()
                        .and_then(|v| u16::try_from(v).ok())
                    {
                        lock(&core.state)
                            .roster
                            .entry(id)
                            .or_insert_with(|| Participant {
                                public_key: str_of(&raw, "from_pubkey").to_string(),
                                sender_id: id,
                                display_name: None,
                            });
                    }
                    spawn_unwrap(core, raw);
                }
                "voice_talk_granted" if str_of(&raw, "public_key") == me => {
                    lock(&core.state).may_speak = true;
                    core.emit(VoiceEvent::TalkGranted);
                }
                "voice_move" => core.emit(VoiceEvent::MoveRequested {
                    target_channel_id: str_of(&raw, "target_channel_id").to_string(),
                    target_channel_name: str_of(&raw, "target_channel_name").to_string(),
                    source_channel_id: raw["source_channel_id"].as_str().map(str::to_string),
                    event_id: raw["event_id"].as_str().map(str::to_string),
                    auto: raw["auto"].as_bool().unwrap_or(false),
                }),
                "voice_zone_state" => {
                    let zones: Vec<Zone> = raw["zones"]
                        .as_array()
                        .map(|a| a.iter().filter_map(zone).collect())
                        .unwrap_or_default();
                    lock(&core.state).zones = zones.clone();
                    core.emit(VoiceEvent::Zones(zones));
                }
                "voice_zone_created" => {
                    if let Some(z) = zone(&raw) {
                        let mut st = lock(&core.state);
                        st.zones.retain(|x| x.zone_id != z.zone_id);
                        st.zones.push(z);
                        let zones = st.zones.clone();
                        drop(st);
                        core.emit(VoiceEvent::Zones(zones));
                    }
                }
                "voice_zone_destroyed" => {
                    let mut st = lock(&core.state);
                    st.zones.retain(|z| z.zone_id != str_of(&raw, "zone_id"));
                    let zones = st.zones.clone();
                    drop(st);
                    core.emit(VoiceEvent::Zones(zones));
                }
                "voice_position_updated" => {
                    let position: Vec<f64> = raw["position"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_f64).collect())
                        .unwrap_or_default();
                    let (zone_id, who) = (
                        str_of(&raw, "zone_id").to_string(),
                        str_of(&raw, "pubkey").to_string(),
                    );
                    if let Some(z) = lock(&core.state)
                        .zones
                        .iter_mut()
                        .find(|z| z.zone_id == zone_id)
                    {
                        z.positions.insert(who.clone(), position.clone());
                    }
                    core.emit(VoiceEvent::Position {
                        zone_id,
                        public_key: who,
                        position,
                    });
                }
                "voice_joined" => {}
                _ => core.emit(VoiceEvent::Unknown { raw }),
            }
        }
        _ => {}
    }
}

fn roster_list(st: &State) -> Vec<Participant> {
    let mut v: Vec<Participant> = st.roster.values().cloned().collect();
    v.sort_by_key(|p| p.sender_id);
    v
}

fn handle_datagram(core: &Arc<Core>, payload: &[u8], decoders: &mut Decoders) {
    // sender_id[2] || packet_type[1] || key_id[4] || ctr[8] || ts[4] || AEAD
    if payload.len() < 3 + 32 {
        return;
    }
    let sender_id = u16::from_be_bytes([payload[0], payload[1]]);
    let whisper = payload[2] == 1;
    let sealed = &payload[3..];
    let key_id = u32::from_be_bytes(sealed[0..4].try_into().expect("4 bytes"));
    let ctr = u64::from_be_bytes(sealed[4..12].try_into().expect("8 bytes"));
    let mut st = lock(&core.state);
    if st.deafened {
        return;
    }
    let Some(from) = st.roster.get(&sender_id).map(|p| p.public_key.clone()) else {
        return;
    };
    let Some(&(key, salt)) = st.remote.get(&(from.clone(), key_id)) else {
        return;
    };
    if st
        .marks
        .get(&(sender_id, key_id))
        .is_some_and(|m| ctr <= *m)
    {
        return;
    }
    // The watermark moves only for a packet that opened: a forged one must
    // not be able to lock the real sender out.
    let Ok((_, _, ts, opus)) = voice_packet_open(&key, &salt, sealed) else {
        return;
    };
    st.marks.insert((sender_id, key_id), ctr);
    drop(st);
    #[cfg(feature = "voice-pcm")]
    let pcm = decode(core, decoders, sender_id, &opus);
    #[cfg(not(feature = "voice-pcm"))]
    let pcm = {
        let _ = decoders;
        None
    };
    core.emit(VoiceEvent::Audio(AudioFrame {
        from,
        sender_id,
        key_id,
        ts,
        ctr,
        whisper,
        opus,
        pcm,
    }));
}

#[cfg(feature = "voice-pcm")]
fn decode(core: &Core, decoders: &mut Decoders, sender_id: u16, opus: &[u8]) -> Option<Vec<f32>> {
    use audiopus::{Channels, SampleRate};
    let dec = match decoders.entry(sender_id) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => {
            match audiopus::coder::Decoder::new(SampleRate::Hz48000, Channels::Mono) {
                Ok(d) => e.insert(d),
                Err(err) => {
                    core.fail(VoiceError::Codec(err.to_string()).into());
                    return None;
                }
            }
        }
    };
    let mut pcm = vec![0f32; FRAME_SAMPLES as usize];
    match dec.decode_float(Some(opus), &mut pcm, false) {
        Ok(n) => {
            pcm.truncate(n);
            Some(pcm)
        }
        Err(err) => {
            core.fail(VoiceError::Codec(err.to_string()).into());
            None
        }
    }
}

#[cfg(feature = "voice-pcm")]
fn new_encoder(opts: &VoiceOptions) -> Result<audiopus::coder::Encoder> {
    use audiopus::{Application, Bitrate, Channels, SampleRate};
    let app = if opts.music {
        Application::Audio
    } else {
        Application::Voip
    };
    let mut enc = audiopus::coder::Encoder::new(SampleRate::Hz48000, Channels::Mono, app)
        .map_err(|e| VoiceError::Codec(e.to_string()))?;
    if let Some(bps) = opts.bitrate {
        enc.set_bitrate(Bitrate::BitsPerSecond(bps as i32))
            .map_err(|e| VoiceError::Codec(e.to_string()))?;
    }
    Ok(enc)
}

/// Every 25 ms: end a transmission that went quiet, and send the trailing
/// position if one is waiting and the hub's 30 ms limit is safely behind.
fn housekeeping(core: &Arc<Core>) {
    let mut msgs = Vec::new();
    {
        let mut st = lock(&core.state);
        if !st.in_room {
            return;
        }
        if st.speaking && st.last_send.elapsed() > SPEAKING_IDLE {
            st.speaking = false;
            msgs.push(ClientMessage::VoiceSpeaking {
                channel_id: st.channel_id.clone(),
                speaking: false,
            });
        }
        if st.position.is_some() && st.last_position.elapsed() >= POSITION_EVERY {
            if let Some((zone_id, position)) = st.position.take() {
                st.last_position = Instant::now();
                msgs.push(ClientMessage::VoicePositionUpdate { zone_id, position });
            }
        }
    }
    for m in msgs {
        if let Err(e) = core.sender.try_send(m) {
            core.fail(e);
        }
    }
}

impl Voice {
    /// The next thing that happened in the room. `None` after `leave`.
    pub async fn next(&self) -> Option<Result<VoiceEvent>> {
        self.events.lock().await.recv().await
    }

    pub fn channel_id(&self) -> String {
        lock(&self.core.state).channel_id.clone()
    }

    /// This program's relay id in the room.
    pub fn sender_id(&self) -> u16 {
        lock(&self.core.state).sender_id
    }

    pub fn roster(&self) -> Vec<Participant> {
        roster_list(&lock(&self.core.state))
    }

    pub fn zones(&self) -> Vec<Zone> {
        lock(&self.core.state).zones.clone()
    }

    /// False means the relay drops what this program sends; `send_*` then
    /// fails with `MayNotSpeak` until `VoiceEvent::TalkGranted`.
    pub fn may_speak(&self) -> bool {
        lock(&self.core.state).may_speak
    }

    /// Local: the hub has no self-mute. Stops sending (calls to `send_*`
    /// still wait their slot and return) and ends the speaking indication.
    pub fn set_muted(&self, muted: bool) {
        let msg = {
            let mut st = lock(&self.core.state);
            st.muted = muted;
            (muted && st.speaking).then(|| {
                st.speaking = false;
                ClientMessage::VoiceSpeaking {
                    channel_id: st.channel_id.clone(),
                    speaking: false,
                }
            })
        };
        if let Some(m) = msg {
            let _ = self.core.sender.try_send(m);
        }
    }

    /// Local: stops delivering `Audio`. Key distribution keeps running, so
    /// undeafening is instant.
    pub fn set_deafened(&self, deafened: bool) {
        lock(&self.core.state).deafened = deafened;
    }

    /// One 20 ms Opus packet, held until its slot on a monotonic clock. A
    /// source that runs faster than real time is slowed to it; one that falls
    /// more than three frames behind is re-anchored, `ts` jumping by the
    /// slots it missed.
    pub async fn send_opus(&self, packet: &[u8]) -> Result<()> {
        opus::check_20ms(packet).map_err(VoiceError::BadFrame)?;
        let (slot, ts) = {
            let mut st = lock(&self.core.state);
            if !st.in_room {
                return Err(VoiceError::NotInRoom.into());
            }
            if !st.may_speak {
                return Err(VoiceError::MayNotSpeak.into());
            }
            // 3 relay prefix bytes are added by the hub, not by us.
            if 16 + packet.len() + 16 + 3 > transport::MAX_PACKET {
                return Err(VoiceError::PacketTooLarge(packet.len()).into());
            }
            let now = Instant::now();
            let p = st.pacing.get_or_insert(Pacing { next: now, ts: 0 });
            if now > p.next + FRAME * MAX_LAG_FRAMES {
                let missed = ((now - p.next).as_millis() / FRAME.as_millis()) as u32;
                p.ts = p.ts.wrapping_add(FRAME_SAMPLES * missed);
                p.next = now;
            }
            let out = (p.next, p.ts);
            p.next += FRAME;
            p.ts = p.ts.wrapping_add(FRAME_SAMPLES);
            out
        };
        tokio::time::sleep_until(slot).await;
        let (sealed, conn, started) = {
            let mut st = lock(&self.core.state);
            if !st.in_room {
                return Err(VoiceError::NotInRoom.into());
            }
            if st.muted {
                return Ok(());
            }
            let Some(conn) = st.conn.clone() else {
                return Err(VoiceError::NotInRoom.into());
            };
            let (key, salt, key_id, ctr) = (st.own.key, st.own.salt, st.own.key_id, st.own.ctr);
            st.own.ctr += 1;
            let started = !st.speaking;
            st.speaking = true;
            st.last_send = Instant::now();
            (
                voice_packet_seal(&key, &salt, key_id, ctr, ts, packet),
                conn,
                started,
            )
        };
        if started {
            let channel_id = self.channel_id();
            self.core
                .sender
                .send(ClientMessage::VoiceSpeaking {
                    channel_id,
                    speaking: true,
                })
                .await?;
        }
        conn.send(&sealed).map_err(VoiceError::Transport)?;
        Ok(())
    }

    /// One 20 ms frame of 48 kHz mono PCM (960 samples), encoded and sent as
    /// [`Voice::send_opus`].
    #[cfg(feature = "voice-pcm")]
    pub async fn send_pcm(&self, frame: &[f32]) -> Result<()> {
        if frame.len() != FRAME_SAMPLES as usize {
            return Err(VoiceError::BadFrame(format!("{} samples, not 960", frame.len())).into());
        }
        let mut buf = [0u8; 1275];
        let n = lock_enc(&self.core)
            .encode_float(frame, &mut buf)
            .map_err(|e| VoiceError::Codec(e.to_string()))?;
        self.send_opus(&buf[..n]).await
    }

    /// Latest position in a zone of this room. At most one reaches the hub
    /// every 50 ms (it silently drops one under 30 ms after the last); the
    /// newest is always the one sent. Checked here, because the hub drops a
    /// bad one without an answer.
    pub fn set_position(&self, zone_id: &str, position: &[f64]) -> Result<()> {
        let mut st = lock(&self.core.state);
        let z = st
            .zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .ok_or_else(|| VoiceError::UnknownZone(zone_id.to_string()))?;
        let want = match z.coordinate_system.as_str() {
            "2d" => 2,
            "3d" => 3,
            _ => position.len().clamp(1, 3),
        };
        if position.len() != want {
            return Err(VoiceError::BadPosition {
                got: position.len(),
                want,
            }
            .into());
        }
        st.position = Some((zone_id.to_string(), position.to_vec()));
        Ok(())
    }

    /// Needs `channels.manage` on the channel. `attenuation` is the hub's
    /// `{model, max_radius, ref_dist, rolloff}` object; `{}` takes the
    /// defaults. `auth_mode` is `creator_only` or `any_channel_member`.
    pub async fn create_zone(
        &self,
        zone_id: &str,
        name: &str,
        coordinate_system: &str,
        attenuation: Value,
        auth_mode: &str,
    ) -> Result<()> {
        self.core
            .sender
            .send(ClientMessage::VoiceZoneCreate {
                zone_id: zone_id.into(),
                name: name.into(),
                coordinate_system: coordinate_system.into(),
                attenuation,
                auth_mode: auth_mode.into(),
            })
            .await
    }

    pub async fn destroy_zone(&self, zone_id: &str) -> Result<()> {
        self.core
            .sender
            .send(ClientMessage::VoiceZoneDestroy {
                zone_id: zone_id.into(),
            })
            .await
    }

    /// `voice_leave`, then the audio session closes. Closing the session alone
    /// would not leave the roster.
    pub async fn leave(&self) -> Result<()> {
        let (channel_id, was_speaking, conn) = {
            let mut st = lock(&self.core.state);
            st.in_room = false;
            (st.channel_id.clone(), st.speaking, st.conn.take())
        };
        if was_speaking {
            self.core
                .sender
                .send(ClientMessage::VoiceSpeaking {
                    channel_id: channel_id.clone(),
                    speaking: false,
                })
                .await?;
        }
        self.core
            .sender
            .send(ClientMessage::VoiceLeave { channel_id })
            .await?;
        drop(conn);
        // Lets the hub read voice_leave before the socket closes.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = self.core.cmd.send(Cmd::Leave);
        Ok(())
    }
}

#[cfg(feature = "voice-pcm")]
fn lock_enc(core: &Core) -> std::sync::MutexGuard<'_, audiopus::coder::Encoder> {
    core.encoder.lock().unwrap_or_else(|e| e.into_inner())
}
