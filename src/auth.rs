use ed25519_dalek::{Signer, SigningKey};

use crate::error::AuthError;

pub use wavvon_identity::AUTH_CHALLENGE_SCHEME;
/// Length of a challenge a Wavvon hub issues; the only length signed raw.
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
    /// `POST /auth/verify`.
    pub fn sign_challenge(
        &self,
        challenge_hex: &str,
        scheme: Option<&str>,
    ) -> Result<String, AuthError> {
        let challenge = hex::decode(challenge_hex).map_err(|_| AuthError::ChallengeNotHex)?;
        let bytes = challenge_signing_bytes(&challenge, scheme)?;
        Ok(hex::encode(self.key.sign(&bytes).to_bytes()))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.public_key_hex())
    }
}

/// The bytes signed for a challenge. A named scheme is tagged; no scheme (an
/// older hub) signs the raw challenge, and only at the length a hub issues, so
/// the SDK cannot be used as a signing oracle for arbitrary bytes.
pub fn challenge_signing_bytes(
    challenge: &[u8],
    scheme: Option<&str>,
) -> Result<Vec<u8>, AuthError> {
    match scheme {
        Some(AUTH_CHALLENGE_SCHEME) => Ok(wavvon_identity::auth_challenge_signing_bytes(challenge)),
        Some(other) => Err(AuthError::UnknownScheme(other.to_string())),
        None if challenge.len() == AUTH_CHALLENGE_LEN => Ok(challenge.to_vec()),
        None => Err(AuthError::RawChallengeLength(challenge.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_scheme_prefixes() {
        let b = challenge_signing_bytes(&[1, 2, 3], Some("tagged-v1")).unwrap();
        assert_eq!(
            b,
            [b"wavvon/auth-challenge/v1\0".as_slice(), &[1, 2, 3]].concat()
        );
    }

    #[test]
    fn no_scheme_signs_raw_only_at_32_bytes() {
        assert_eq!(
            challenge_signing_bytes(&[7; 32], None).unwrap(),
            vec![7; 32]
        );
        assert_eq!(
            challenge_signing_bytes(&[7; 31], None),
            Err(AuthError::RawChallengeLength(31))
        );
        assert_eq!(
            challenge_signing_bytes(&[], None),
            Err(AuthError::RawChallengeLength(0))
        );
    }

    #[test]
    fn unknown_scheme_is_an_error_not_raw() {
        assert_eq!(
            challenge_signing_bytes(&[7; 32], Some("tagged-v2")),
            Err(AuthError::UnknownScheme("tagged-v2".into()))
        );
    }

    #[test]
    fn challenge_must_be_hex() {
        let id = Identity::from_seed([1; 32]);
        assert_eq!(
            id.sign_challenge("zz", None),
            Err(AuthError::ChallengeNotHex)
        );
    }

    #[test]
    fn seed_validation() {
        assert!(Identity::from_seed_hex("00").is_err());
        assert!(Identity::from_seed_hex(&"ab".repeat(32)).is_ok());
    }
}
