/// Everything the SDK can refuse with.
///
/// `Status` is a definitive answer from the hub; `Transient` is the absence of
/// one. They are separate variants so a caller can never read "the hub was
/// unreachable" as "no".
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("hub answered {status}: {body}")]
    Status { status: u16, body: String },
    #[error("no answer from the hub after {attempts} attempts (last: {last})")]
    Transient { attempts: u32, last: String },
    #[error("this hub does not advertise the `{0}` capability")]
    UnsupportedByHub(String),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("bad hub url: {0}")]
    Url(String),
    #[error("could not build the request: {0}")]
    Request(String),
    #[error("unexpected response: {0}")]
    Decode(String),
    #[error("the event stream is closed")]
    Closed,
    /// The peer has published no DH key on this hub, so nothing can be
    /// encrypted or wrapped to it. Never sent in the clear instead.
    #[error("{pubkey} has published no DH key on this hub")]
    RecipientHasNoKey { pubkey: String },
    /// The peer's DH key differs from the one pinned on first use. Nothing is
    /// encrypted to it until the program accepts it
    /// ([`Client::accept_dh_key`](crate::Client::accept_dh_key)).
    #[error("DH key of {pubkey} changed (pinned {pinned}, hub now has {fetched})")]
    DhKeyChanged {
        pubkey: String,
        pinned: String,
        fetched: String,
    },
    /// The hub holds a DH record for `pubkey` that `pubkey` did not sign.
    #[error("DH key record for {pubkey} is not signed by its owner")]
    DhKeyUnsigned { pubkey: String },
    #[error(transparent)]
    Dm(#[from] DmError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Voice(#[from] VoiceError),
    /// A poll cursor is older than the hub's 72-hour window: events after it
    /// were missed. Resynchronise from REST, then poll without a cursor.
    #[error("events before seq {earliest_seq} are outside the hub's replay window")]
    ReplayUnavailable { earliest_seq: i64, earliest_at: i64 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why one DM could not be read or sent. Per message: a program keeps going.
#[derive(Debug, thiserror::Error)]
pub enum DmError {
    /// The envelope is not signed by the member the hub names as its sender
    /// (directly or through a cert that member issued). Not decrypted.
    #[error("envelope is not signed by its sender")]
    NotSignedBySender,
    /// A ratchet cannot read what it sent itself. Keeping a copy is the
    /// program's business.
    #[error("this program sent the message; a ratchet cannot decrypt its own output")]
    OwnMessage,
    #[error("malformed envelope: {0}")]
    Malformed(String),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("no ratchet session for this conversation")]
    NoSession,
    #[error("more than 1000 skipped messages")]
    TooManySkipped,
    #[error("no sender key from {sender} at version {version}")]
    KeyNotFound { sender: String, version: u32 },
    #[error("the sender's chain was already advanced past this message")]
    ChainAdvancedPastMessage,
    #[error("{0}")]
    Crypto(String),
}

/// Why a voice call could not proceed.
#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    /// `voice_joined` carried no `voice_wt_url`: a hub older than voice
    /// transport v2.
    #[error("the hub offers no WebTransport voice endpoint")]
    NoTransport,
    /// Talk power is below the channel's threshold, so the relay would drop
    /// every datagram. Lifted by `VoiceEvent::TalkGranted`.
    #[error("may_speak is false in this channel")]
    MayNotSpeak,
    /// Anything but exactly 20 ms of Opus: the desktop decoder cannot play it.
    #[error("opus packet is not a single 20 ms frame: {0}")]
    BadFrame(String),
    #[error("a {0}-byte packet does not fit a datagram")]
    PacketTooLarge(usize),
    /// After `leave`, or between a dropped socket and the rejoin.
    #[error("not in a voice room right now")]
    NotInRoom,
    #[error("the hub refused: {0}")]
    Refused(String),
    #[error("zone {0} is not in this room")]
    UnknownZone(String),
    #[error("position has {got} coordinates, the zone takes {want}")]
    BadPosition { got: usize, want: usize },
    #[error("transport: {0}")]
    Transport(String),
    #[error("opus codec: {0}")]
    Codec(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The hub named no scheme, or one this SDK does not sign. Never answered raw.
    #[error("hub named no supported challenge scheme (got {0:?})")]
    UnknownScheme(Option<String>),
    #[error("challenge is not hex")]
    ChallengeNotHex,
    #[error("challenge is {0} bytes, expected 32")]
    BadChallengeLength(usize),
    #[error("seed must be 32 bytes of hex")]
    BadSeed,
}

/// Why a webhook delivery was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("missing header {0}")]
    MissingHeader(&'static str),
    #[error("malformed header {0}")]
    BadHeader(&'static str),
    #[error("delivery names a different hub than the one this program trusts")]
    WrongHub,
    #[error("signature does not match")]
    BadSignature,
    #[error("timestamp is {skew} s from now, outside the 300 s window")]
    Stale { skew: u64 },
    #[error("webhook secret must be base64url (no padding) of 32 bytes")]
    BadSecret,
}
