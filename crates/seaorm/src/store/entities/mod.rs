//! Internal `SeaORM` entity models for the built-in auth schema.

pub mod account;
pub mod api_key;
pub mod api_key_start;
pub mod device_code;
pub mod invitation;
pub mod jwk;
pub mod member;
pub mod organization;
pub mod organization_role;
pub mod passkey;
pub mod session;
pub mod team;
pub mod team_member;
pub mod two_factor;
pub mod user;
pub mod verification;
pub mod wallet_address;

pub mod oauth_access_token;
pub mod oauth_client;
pub mod oauth_client_assertion;
pub mod oauth_client_resource;
pub mod oauth_consent;
pub mod oauth_refresh_token;
pub mod oauth_resource;

pub mod sso_provider;
