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
    /// A poll cursor is older than the hub's 72-hour window: events after it
    /// were missed. Resynchronise from REST, then poll without a cursor.
    #[error("events before seq {earliest_seq} are outside the hub's replay window")]
    ReplayUnavailable { earliest_seq: i64, earliest_at: i64 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The hub named no scheme, or one this SDK does not sign. Never answered raw.
    #[error("hub named no supported challenge scheme (got {0:?})")]
    UnknownScheme(Option<String>),
    #[error("challenge is not hex")]
    ChallengeNotHex,
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
