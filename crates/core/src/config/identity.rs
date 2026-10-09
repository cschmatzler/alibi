use std::sync::Arc;
#[derive(Debug, Clone, Default)]
pub struct UserConfig {
    pub additional_fields: crate::field_policy::FieldConfigs,
}

/// Initialized identifier, persistence and cleanup policy for verification values.
#[derive(Clone, Default)]
pub struct VerificationConfig {
    /// Keep globally expired verification rows during lookup. Default: false.
    /// An atomic consume still invalidates an expired proof it selects.
    pub disable_cleanup: bool,
    /// Persist verification values alongside secondary storage. Without a
    /// secondary backend, verification values always use the database.
    pub store_in_database: bool,
    /// Global identifier policy, applied after a plugin's own value codec.
    pub store_identifier: crate::verification::VerificationIdentifierPolicy,
    /// Optional shared secondary backend. Single-use values require its atomic
    /// `get_and_delete` operation. This config does not change session storage.
    pub secondary_storage: Option<Arc<dyn crate::store::CacheAdapter>>,
}

impl std::fmt::Debug for VerificationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationConfig")
            .field("disable_cleanup", &self.disable_cleanup)
            .field("store_in_database", &self.store_in_database)
            .field("store_identifier", &self.store_identifier)
            .field("secondary_storage", &self.secondary_storage.is_some())
            .finish()
    }
}

/// Password strength rules. Length limits belong to the email/password plugin
/// (`password_min_length`, `password_max_length`). Built-in hashing uses
/// pinned scrypt parameters.
#[derive(Debug, Clone, Default)]
pub struct PasswordConfig {
    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special: bool,
}
