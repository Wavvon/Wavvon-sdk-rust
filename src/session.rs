use std::sync::{Arc, RwLock};

/// The bearer token every generated call carries. Shared, so a re-auth is
/// seen by clients that were cloned before it happened.
#[derive(Clone, Default)]
pub struct Session {
    token: Arc<RwLock<Option<String>>>,
}

impl Session {
    pub(crate) fn set(&self, token: Option<String>) {
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = token;
    }

    pub(crate) fn get(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Pre-hook of the generated client: adds `Authorization: Bearer`.
pub(crate) async fn attach_bearer(
    session: &Session,
    request: &mut reqwest::Request,
) -> Result<(), String> {
    if let Some(token) = session.get() {
        let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| e.to_string())?;
        request
            .headers_mut()
            .insert(reqwest::header::AUTHORIZATION, value);
    }
    Ok(())
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session(..)")
    }
}
