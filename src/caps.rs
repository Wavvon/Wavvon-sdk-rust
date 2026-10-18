use std::collections::HashSet;

use crate::error::{Error, Result};

/// Capability strings this SDK branches on (crates/hub/src/capabilities.rs).
pub const APPS_REGISTER: &str = "apps.register";
pub const LIST_CURSOR: &str = "list.cursor";
pub const LIST_CURSOR_LISTS: &str = "list.cursor.lists";
pub const WEBHOOKS_SIGNEDTIMESTAMP: &str = "webhooks.signedtimestamp";

/// What `GET /info` said the hub can do. Membership only, never a version.
#[derive(Clone, Debug, Default)]
pub struct Capabilities(HashSet<String>);

impl Capabilities {
    pub fn new(caps: impl IntoIterator<Item = String>) -> Self {
        Self(caps.into_iter().collect())
    }

    pub fn has(&self, cap: &str) -> bool {
        self.0.contains(cap)
    }

    pub fn require(&self, cap: &str) -> Result<()> {
        if self.has(cap) {
            Ok(())
        } else {
            Err(Error::UnsupportedByHub(cap.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_is_exact_membership() {
        let c = Capabilities::new(["list.cursor".to_string()]);
        assert!(c.require("list.cursor").is_ok());
        assert!(matches!(
            c.require("list.cursor.lists"),
            Err(Error::UnsupportedByHub(s)) if s == "list.cursor.lists"
        ));
        assert!(Capabilities::default().require("apps.register").is_err());
    }
}
