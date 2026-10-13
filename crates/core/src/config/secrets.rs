use crate::AuthError;
use indexmap::IndexMap;

/// Versioned persistence keys. New ciphertext uses the current version;
/// retained versions read existing ciphertext without rewriting it. Removing
/// a retained version retires it immediately. Signed cookies use only the
/// current key and are invalidated when that key changes.
#[derive(Clone)]
pub struct ManagedSecrets {
    current_version: u64,
    keys: IndexMap<u64, String>,
}

impl ManagedSecrets {
    #[must_use]
    pub fn new(version: u64, secret: impl Into<String>) -> Self {
        Self {
            current_version: version,
            keys: IndexMap::from([(version, secret.into())]),
        }
    }

    /// Retain a previous version for reads. Replacing the current version's
    /// key changes its key material; it does not change the selected version.
    #[must_use]
    pub fn retain(mut self, version: u64, secret: impl Into<String>) -> Self {
        _ = self.keys.insert(version, secret.into());
        self
    }

    /// Retire a reader. The current version cannot be retired; rotate by
    /// constructing a new configuration with a new current version instead.
    #[must_use]
    pub fn retire(mut self, version: u64) -> Self {
        if version != self.current_version {
            _ = self.keys.shift_remove(&version);
        }
        self
    }

    #[must_use]
    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    #[must_use]
    pub fn current_secret(&self) -> &str {
        self.key(self.current_version).unwrap_or_default()
    }

    #[must_use]
    pub fn key(&self, version: u64) -> Option<&str> {
        self.keys.get(&version).map(String::as_str)
    }

    pub fn verification_secrets(&self) -> impl Iterator<Item = &str> {
        self.keys.values().map(String::as_str)
    }

    /// # Errors
    /// Rejects invalid versions, empty readers and an insecure current key.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self
            .keys
            .iter()
            .any(|(version, key)| *version > 9_007_199_254_740_991 || key.is_empty())
        {
            return Err(AuthError::config(
                "Secret versions must be safe nonnegative integers with nonempty keys",
            ));
        }
        if self.current_secret().len() < 32 {
            return Err(AuthError::config(
                "Current secret key must be at least 32 characters",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for ManagedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedSecrets")
            .field("current_version", &self.current_version)
            .field("versions", &self.keys.keys())
            .finish_non_exhaustive()
    }
}
