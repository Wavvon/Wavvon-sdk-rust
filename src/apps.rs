//! App registration, and the shapes of slash/component dispatch (apps.md).
//! Mirrors crates/hub/src/routes/app_models.rs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GameLaunchCard {
    pub entry_url: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
}

/// `PUT /me/app/profile` body. `webhook_url` receives slash and component
/// dispatch.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AppProfile {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mini_app_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_camera: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game: Option<GameLaunchCard>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppCommand {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    /// `channel` (default) or `hub`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<i64>,
}

/// One entry of `PUT /me/app/subscriptions`. A `message.*` event must name its
/// channels.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Subscription {
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
}

/// `GET /me/app`: what the hub holds about this program.
#[derive(Clone, Debug, Deserialize)]
pub struct AppRegistration {
    pub pubkey: String,
    pub name: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub homepage_url: Option<String>,
    #[serde(default)]
    pub commands: Vec<AppCommand>,
}

// ---- what the hub POSTs to webhook_url ----

#[derive(Clone, Debug, Deserialize)]
pub struct Author {
    pub pubkey: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SlashInvocation {
    pub hub_url: String,
    pub channel_id: String,
    pub message_id_hint: String,
    pub author: Author,
    pub command: String,
    pub args_raw: String,
    pub args_tokens: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ComponentInteraction {
    pub hub_url: String,
    pub channel_id: String,
    pub message_id: String,
    pub custom_id: String,
    #[serde(default)]
    pub values: Vec<String>,
    pub user: Author,
}

#[derive(Clone, Debug)]
pub enum Invocation {
    Slash(SlashInvocation),
    Component(ComponentInteraction),
    /// A `type` this SDK does not know, or a known one that does not fit.
    Unknown {
        raw: Value,
    },
}

impl Invocation {
    /// Decode a body. Verify it first ([`crate::webhooks::verify_dispatch`]).
    pub fn decode(body: &[u8]) -> Result<Invocation, serde_json::Error> {
        let raw: Value = serde_json::from_slice(body)?;
        let decoded = match raw.get("type").and_then(Value::as_str) {
            Some("slash_command") => serde_json::from_value(raw.clone())
                .ok()
                .map(Invocation::Slash),
            Some("component_interaction") => serde_json::from_value(raw.clone())
                .ok()
                .map(Invocation::Component),
            _ => None,
        };
        Ok(decoded.unwrap_or(Invocation::Unknown { raw }))
    }
}

// ---- what the program answers ----

#[derive(Clone, Debug, Default, Serialize)]
pub struct EmbedField {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Embed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<EmbedField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct EmbedFooter {
    pub text: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SelectOption {
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A button or select. `kind` is `"button"` or `"select"`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub kind: String,
    pub custom_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOption>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentRow {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub components: Vec<Component>,
}

impl ComponentRow {
    pub fn new(components: Vec<Component>) -> Self {
        Self {
            kind: "row",
            components,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Reply {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeds: Option<Vec<Embed>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Reaction {
    pub message_id: String,
    pub emoji: String,
}

/// The answer to a slash command.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SlashResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<Reply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<Reaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
    /// A "Play" card attached to `reply`'s message; ignored without a reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game: Option<GameLaunchCard>,
}

impl SlashResponse {
    pub fn text(body: impl Into<String>) -> Self {
        Self {
            reply: Some(Reply {
                body: body.into(),
                ..Reply::default()
            }),
            ..Self::default()
        }
    }

    /// Only the invoker sees it.
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = Some(true);
        self
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ComponentUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
}

/// The answer to a button or select click.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ComponentResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<ComponentUpdate>,
    /// Text shown only to the member who clicked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_reply: Option<EphemeralReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EphemeralReply {
    pub body: String,
}

/// What a dispatch handler answers with; serializes to the bare shape the hub
/// expects for either kind of invocation.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Answer {
    Slash(SlashResponse),
    Component(ComponentResponse),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn decodes_both_invocations_and_keeps_unknown() {
        let slash =
            br#"{"type":"slash_command","hub_url":"h","channel_id":"c","message_id_hint":"m",
            "author":{"pubkey":"p"},"command":"echo","args_raw":"a b","args_tokens":["a","b"]}"#;
        assert!(
            matches!(Invocation::decode(slash).unwrap(), Invocation::Slash(s) if s.command == "echo")
        );
        let comp =
            br#"{"type":"component_interaction","hub_url":"h","channel_id":"c","message_id":"m",
            "custom_id":"x","values":[],"user":{"pubkey":"p","display_name":"n"}}"#;
        assert!(
            matches!(Invocation::decode(comp).unwrap(), Invocation::Component(c) if c.custom_id == "x")
        );
        assert!(matches!(
            Invocation::decode(br#"{"type":"future"}"#).unwrap(),
            Invocation::Unknown { .. }
        ));
    }

    #[test]
    fn reply_shapes_serialize_like_the_hub_expects() {
        let v = serde_json::to_value(Answer::Slash(SlashResponse::text("hi").ephemeral())).unwrap();
        assert_eq!(v, json!({"reply":{"body":"hi"},"ephemeral":true}));
        let v = serde_json::to_value(Answer::Component(ComponentResponse {
            defer: Some(true),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(v, json!({"defer":true}));
    }
}
