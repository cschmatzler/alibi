//! Ephemeral no-database identity provisioning and cookie-only sessions.
//!
//! This store has no database connection. The initialized store wrapper keeps
//! ephemeral session records for cookie bypass and instance-local logout.
//! User/account/verification provisioning is instance-local, as in the pinned
//! no-database memory adapter. Native two-factor/passkey/API-key/device-code/JWK/organization records share that
//! instance-local lifetime; other optional records require an application store.
//! Applications can also use cookie-only sessions with durable SQL user storage.
mod accounts;
mod sessions;
mod users;
mod verifications;

mod api_keys;
mod device_codes;
mod invitations;
mod jwks;
mod members;
mod optional_records;
mod organizations;
mod roles;
mod teams;
mod transaction;

use super::*;
use crate::{AccountView, SessionView, UserView, VerificationView};
use chrono::{DateTime, Utc};

/// Wire schema for deployments that do not configure a database.
pub struct StatelessSchema;
impl AuthSchema for StatelessSchema {
    fn user_from_cookie_cache(user: UserView) -> Option<UserView> {
        Some(user)
    }
    type User = UserView;
    type Session = SessionView;
    type Account = AccountView;
    type Verification = VerificationView;
}

/// Instance-local provisioning without durable persistence. Session ownership
/// comes from trusted issuance; the initialized wrapper retains ephemeral sessions.
pub struct StatelessStore {
    state: std::sync::Mutex<IdentityState>,
    organizations: std::sync::Mutex<OrganizationState>,
    find_many_limit: usize,
}

#[derive(Default)]
struct IdentityState {
    users: indexmap::IndexMap<String, UserView>,
    accounts: indexmap::IndexMap<String, AccountView>,
    verifications: indexmap::IndexMap<String, VerificationView>,
    two_factors: indexmap::IndexMap<String, TwoFactor>,
    passkeys: indexmap::IndexMap<String, Passkey>,
    api_keys: indexmap::IndexMap<String, ApiKey>,
    device_codes: indexmap::IndexMap<String, DeviceCode>,
    device_code_fields: indexmap::IndexMap<String, serde_json::Map<String, serde_json::Value>>,
    jwks: indexmap::IndexMap<String, Jwk>,
}

#[derive(Default, Clone)]
struct OrganizationState {
    organizations: indexmap::IndexMap<String, Organization>,
    members: indexmap::IndexMap<String, Member>,
    invitations: indexmap::IndexMap<String, Invitation>,
    teams: indexmap::IndexMap<String, Team>,
    team_members: indexmap::IndexMap<String, TeamMember>,
    roles: indexmap::IndexMap<String, OrganizationRole>,
}

impl Default for StatelessStore {
    fn default() -> Self {
        Self::with_find_many_limit(100)
    }
}

impl StatelessStore {
    /// Use the configured adapter page bound for native organization rows.
    #[must_use]
    pub fn with_find_many_limit(find_many_limit: usize) -> Self {
        Self {
            state: Default::default(),
            organizations: Default::default(),
            find_many_limit,
        }
    }

    fn organization_state(&self) -> AuthResult<std::sync::MutexGuard<'_, OrganizationState>> {
        self.organizations
            .lock()
            .map_err(|_| AuthError::internal("No-database organization state poisoned"))
    }

    fn lock(&self) -> AuthResult<std::sync::MutexGuard<'_, IdentityState>> {
        self.state
            .lock()
            .map_err(|_| AuthError::internal("No-database identity state poisoned"))
    }
}

impl WalletAddressStore for StatelessStore {}
