//! Where the SDK keeps state it must not lose: DH pins, DM ratchet sessions
//! and group sender chains. The default is in memory; a program that wants the
//! state to survive a restart plugs in its own storage.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
#[error("state store: {0}")]
pub struct StoreError(pub String);

/// A byte-valued key/value store. Keys are opaque strings the SDK chooses
/// (`dh-pin/<pubkey>`, `dr/<conv>`, `group-own/<conv>`,
/// `group-peer/<conv>/<sender>/<version>`); values are JSON.
///
/// Losing DM ratchet state leaves the conversations it belongs to unreadable,
/// so a persistent implementation should make `put` durable before it returns.
pub trait StateStore: Send + Sync + std::fmt::Debug {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// The default: lost when the process ends.
#[derive(Debug, Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl StateStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock().get(key).cloned())
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.lock().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.lock().remove(key);
        Ok(())
    }
}

pub(crate) fn get_json<T: serde::de::DeserializeOwned>(
    store: &dyn StateStore,
    key: &str,
) -> crate::Result<Option<T>> {
    match store.get(key)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| crate::Error::Store(StoreError(format!("{key} is not valid state: {e}")))),
    }
}

pub(crate) fn put_json<T: serde::Serialize>(
    store: &dyn StateStore,
    key: &str,
    value: &T,
) -> crate::Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| crate::Error::Store(StoreError(e.to_string())))?;
    Ok(store.put(key, &bytes)?)
}
