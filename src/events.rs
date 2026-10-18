use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `hub_event` envelope: live WebSocket push, replay, and outgoing webhooks
/// (ws-protocol.md). `event` stays a string so a type this SDK has never heard
/// of still arrives intact.
#[derive(Clone, Debug, Deserialize)]
pub struct HubEvent {
    pub seq: i64,
    pub event: String,
    pub hub_url: String,
    pub at: i64,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub actor_pubkey: Option<String>,
    #[serde(default)]
    pub target_pubkey: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub replayed: bool,
    /// Outgoing webhooks only.
    #[serde(default)]
    pub webhook_id: Option<String>,
    /// Outgoing webhooks only: `payload` was cut to the size cap.
    #[serde(default)]
    pub truncated: bool,
}

/// A chat message as pushed over the socket (the REST `Message` shape).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChatMessage {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    #[serde(default)]
    pub sender_name: Option<String>,
    pub content: String,
    pub created_at: i64,
    #[serde(default)]
    pub edited_at: Option<i64>,
    /// Set on ephemeral replies: only that member should see the message.
    #[serde(default)]
    pub visible_to_pubkey: Option<String>,
}

/// One server-to-client WebSocket message. Anything this tier does not model
/// (voice, screen share, typing, forum...) arrives as `Unknown` with the raw
/// JSON; nothing is dropped on the floor.
#[derive(Clone, Debug)]
pub enum Event {
    Hello {
        live_seq: i64,
    },
    Hub(HubEvent),
    ReplayComplete {
        replayed: i64,
        live_from_seq: i64,
    },
    /// `resume` asked for a sequence older than the hub's 72-hour retention:
    /// events were lost and the program must decide what that means.
    ReplayUnavailable {
        earliest_seq: i64,
        earliest_at: i64,
    },
    Message {
        channel_id: String,
        message: ChatMessage,
    },
    Error {
        context: String,
        message: String,
    },
    AppLaunch {
        app_id: String,
        title: String,
        description: String,
        channel_id: String,
    },
    AppOpen {
        app_id: String,
        channel_id: String,
        mini_app_url: String,
        session_token: String,
        requires_camera: bool,
    },
    AppClose {
        app_id: String,
        channel_id: String,
    },
    /// A player's mini-app session talking to this program (`from_pubkey` set).
    MiniAppMessage(MiniAppMessage),
    Unknown {
        raw: Value,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct MiniAppMessage {
    pub app_id: String,
    pub channel_id: String,
    /// Opaque JSON-encoded string; the hub never reads it.
    pub payload: String,
    #[serde(default)]
    pub from_pubkey: Option<String>,
}

impl MiniAppMessage {
    pub fn payload_json<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_str(&self.payload)
    }
}

impl Event {
    /// Decodes one text frame. A known `type` whose fields do not fit is
    /// `Unknown` too, so a hub that drifts is visible rather than skipped.
    pub fn from_value(raw: Value) -> Event {
        #[derive(Deserialize)]
        struct Hello {
            live_seq: i64,
        }
        #[derive(Deserialize)]
        struct ReplayComplete {
            replayed: i64,
            live_from_seq: i64,
        }
        #[derive(Deserialize)]
        struct ReplayUnavailable {
            earliest_seq: i64,
            earliest_at: i64,
        }
        #[derive(Deserialize)]
        struct Message {
            channel_id: String,
            message: ChatMessage,
        }
        #[derive(Deserialize)]
        struct Error {
            context: String,
            message: String,
        }
        #[derive(Deserialize)]
        struct AppLaunch {
            app_id: String,
            title: String,
            description: String,
            channel_id: String,
        }
        #[derive(Deserialize)]
        struct AppOpen {
            app_id: String,
            channel_id: String,
            mini_app_url: String,
            session_token: String,
            #[serde(default)]
            requires_camera: bool,
        }
        #[derive(Deserialize)]
        struct AppClose {
            app_id: String,
            channel_id: String,
        }

        fn parse<T: serde::de::DeserializeOwned>(v: &Value) -> Option<T> {
            serde_json::from_value(v.clone()).ok()
        }
        let decoded = match raw.get("type").and_then(Value::as_str) {
            Some("hello") => parse::<Hello>(&raw).map(|m| Event::Hello {
                live_seq: m.live_seq,
            }),
            Some("hub_event") => parse::<HubEvent>(&raw).map(Event::Hub),
            Some("replay_complete") => {
                parse::<ReplayComplete>(&raw).map(|m| Event::ReplayComplete {
                    replayed: m.replayed,
                    live_from_seq: m.live_from_seq,
                })
            }
            Some("replay_unavailable") => {
                parse::<ReplayUnavailable>(&raw).map(|m| Event::ReplayUnavailable {
                    earliest_seq: m.earliest_seq,
                    earliest_at: m.earliest_at,
                })
            }
            Some("message") => parse::<Message>(&raw).map(|m| Event::Message {
                channel_id: m.channel_id,
                message: m.message,
            }),
            Some("error") => parse::<Error>(&raw).map(|m| Event::Error {
                context: m.context,
                message: m.message,
            }),
            Some("app_launch") => parse::<AppLaunch>(&raw).map(|m| Event::AppLaunch {
                app_id: m.app_id,
                title: m.title,
                description: m.description,
                channel_id: m.channel_id,
            }),
            Some("app_open") => parse::<AppOpen>(&raw).map(|m| Event::AppOpen {
                app_id: m.app_id,
                channel_id: m.channel_id,
                mini_app_url: m.mini_app_url,
                session_token: m.session_token,
                requires_camera: m.requires_camera,
            }),
            Some("app_close") => parse::<AppClose>(&raw).map(|m| Event::AppClose {
                app_id: m.app_id,
                channel_id: m.channel_id,
            }),
            Some("mini_app_message") => parse::<MiniAppMessage>(&raw).map(Event::MiniAppMessage),
            _ => None,
        };
        decoded.unwrap_or(Event::Unknown { raw })
    }
}

/// What a program may send on its socket (tier 1).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { channel_id: String },
    #[serde(rename = "resume")]
    Resume { since_seq: i64 },
    #[serde(rename = "app_announce")]
    AppAnnounce {
        title: String,
        description: String,
        channel_id: String,
    },
    #[serde(rename = "app_dismiss")]
    AppDismiss { channel_id: String },
    #[serde(rename = "mini_app_message")]
    MiniAppMessage {
        app_id: String,
        channel_id: String,
        payload: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        to_pubkey: Option<String>,
    },
}

/// One polled event from `GET /me/events`. `payload` is a JSON string.
#[derive(Clone, Debug, Deserialize)]
pub struct PolledEvent {
    pub id: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

impl PolledEvent {
    pub fn payload_json<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_str(&self.payload)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn known_events_decode() {
        let e = Event::from_value(json!({"type":"hello","live_seq":9}));
        assert!(matches!(e, Event::Hello { live_seq: 9 }));
        let e = Event::from_value(json!({
            "type":"hub_event","seq":4,"event":"member.joined","hub_url":"h","at":1,
            "payload":{"a":1},"replayed":true
        }));
        assert!(
            matches!(e, Event::Hub(h) if h.seq == 4 && h.replayed && h.event == "member.joined")
        );
        let e = Event::from_value(
            json!({"type":"replay_unavailable","earliest_seq":5,"earliest_at":2}),
        );
        assert!(matches!(
            e,
            Event::ReplayUnavailable {
                earliest_seq: 5,
                ..
            }
        ));
    }

    #[test]
    fn unknown_type_keeps_the_raw_payload() {
        let raw = json!({"type":"voice_joined","channel_id":"c"});
        match Event::from_value(raw.clone()) {
            Event::Unknown { raw: got } => assert_eq!(got, raw),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn known_type_with_a_drifted_shape_is_unknown_not_dropped() {
        let raw = json!({"type":"hub_event","seq":"not a number"});
        assert!(matches!(Event::from_value(raw), Event::Unknown { .. }));
        assert!(matches!(
            Event::from_value(json!({"no":"type"})),
            Event::Unknown { .. }
        ));
    }

    #[test]
    fn unknown_hub_event_name_still_arrives() {
        let e = Event::from_value(json!({
            "type":"hub_event","seq":1,"event":"something.new","hub_url":"h","at":1,"payload":null
        }));
        assert!(matches!(e, Event::Hub(h) if h.event == "something.new"));
    }

    #[test]
    fn client_messages_serialize_tagged() {
        let m = ClientMessage::Resume { since_seq: 3 };
        assert_eq!(
            serde_json::to_value(m).unwrap(),
            json!({"type":"resume","since_seq":3})
        );
        let m = ClientMessage::MiniAppMessage {
            app_id: "a".into(),
            channel_id: "c".into(),
            payload: "{}".into(),
            to_pubkey: None,
        };
        assert!(serde_json::to_value(m).unwrap().get("to_pubkey").is_none());
    }
}
