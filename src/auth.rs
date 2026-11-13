use ed25519_dalek::{Signer, SigningKey};

use crate::error::AuthError;

pub use wavvon_identity::AUTH_CHALLENGE_SCHEME;

/// The scheme a current hub or farm names: the answer is bound to its key.
pub const BOUND_AUTH_CHALLENGE_SCHEME: &str = "tagged-v2";

/// The length of a challenge a Wavvon server issues; nothing else is signed.
pub const AUTH_CHALLENGE_LEN: usize = 32;

/// The program's keypair. The seed stays in this process: nothing here sends
/// it anywhere.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, AuthError> {
        let bytes = hex::decode(seed_hex.trim()).map_err(|_| AuthError::BadSeed)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| AuthError::BadSeed)?;
        Ok(Self::from_seed(seed))
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Answers `POST /auth/challenge`: returns the hex signature for
    /// `POST /auth/verify`. `server_pubkey` is the key the server's own
    /// `GET /info` presented, never one from the challenge response.
    pub fn sign_challenge(
        &self,
        challenge_hex: &str,
        scheme: Option<&str>,
        server_pubkey: &str,
    ) -> Result<String, AuthError> {
        let challenge = hex::decode(challenge_hex).map_err(|_| AuthError::ChallengeNotHex)?;
        let bytes = challenge_signing_bytes(&challenge, scheme, server_pubkey)?;
        Ok(hex::encode(self.key.sign(&bytes).to_bytes()))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.public_key_hex())
    }
}

/// The bytes signed for a challenge. `tagged-v2` binds the answer to the
/// server signed in to, so a hostile hub cannot relay another server's
/// challenge and sign in there with the answer (Wavvon-server#294);
/// `tagged-v1` is still answered for older hubs. A missing or unknown scheme
/// is refused, never signed raw, so the SDK cannot be used as a signing oracle
/// for arbitrary bytes.
pub fn challenge_signing_bytes(
    challenge: &[u8],
    scheme: Option<&str>,
    server_pubkey: &str,
) -> Result<Vec<u8>, AuthError> {
    let bound = match scheme {
        Some(BOUND_AUTH_CHALLENGE_SCHEME) => true,
        Some(AUTH_CHALLENGE_SCHEME) => false,
        other => return Err(AuthError::UnknownScheme(other.map(str::to_string))),
    };
    if challenge.len() != AUTH_CHALLENGE_LEN {
        return Err(AuthError::BadChallengeLength(challenge.len()));
    }
    if !bound {
        return Ok(wavvon_identity::auth_challenge_signing_bytes(challenge));
    }
    // Mirrors wavvon_identity::bound_auth_challenge_signing_bytes (0.4.0),
    // which is not on crates.io yet; the conformance vector pins the bytes.
    let key = server_pubkey.as_bytes();
    let mut buf = b"wavvon/auth-challenge/v2\0".to_vec();
    buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
    buf.extend_from_slice(key);
    buf.extend_from_slice(challenge);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_scheme_prefixes() {
        let b = challenge_signing_bytes(&[3; 32], Some("tagged-v1"), "ab").unwrap();
        assert_eq!(
            b,
            [b"wavvon/auth-challenge/v1\0".as_slice(), &[3; 32]].concat()
        );
    }

    #[test]
    fn bound_scheme_names_the_server() {
        let b = challenge_signing_bytes(&[3; 32], Some("tagged-v2"), "ab").unwrap();
        assert_eq!(
            b,
            [
                b"wavvon/auth-challenge/v2\0".as_slice(),
                &[2, 0, 0, 0],
                b"ab",
                &[3; 32]
            ]
            .concat()
        );
    }

    #[test]
    fn challenge_must_be_32_bytes() {
        for scheme in ["tagged-v1", "tagged-v2"] {
            assert_eq!(
                challenge_signing_bytes(&[3; 31], Some(scheme), "ab"),
                Err(AuthError::BadChallengeLength(31))
            );
        }
    }

    #[test]
    fn missing_scheme_is_refused_not_raw() {
        assert_eq!(
            challenge_signing_bytes(&[7; 32], None, "ab"),
            Err(AuthError::UnknownScheme(None))
        );
    }

    #[test]
    fn unknown_scheme_is_an_error_not_raw() {
        assert_eq!(
            challenge_signing_bytes(&[7; 32], Some("tagged-v3"), "ab"),
            Err(AuthError::UnknownScheme(Some("tagged-v3".into())))
        );
    }

    #[test]
    fn challenge_must_be_hex() {
        let id = Identity::from_seed([1; 32]);
        assert_eq!(
            id.sign_challenge("zz", Some(AUTH_CHALLENGE_SCHEME), "ab"),
            Err(AuthError::ChallengeNotHex)
        );
    }

    #[test]
    fn seed_validation() {
        assert!(Identity::from_seed_hex("00").is_err());
        assert!(Identity::from_seed_hex(&"ab".repeat(32)).is_ok());
    }
}
