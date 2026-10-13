use alibi::AuthSchema;
use alibi::seaorm::sea_orm;
use alibi::seaorm::sea_orm::entity::prelude::*;
use alibi::seaorm::sea_orm::ConnectionTrait;
use alibi::seaorm::{AuthEntity, DatabaseConnection};
mod user {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub email: String,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "isAnonymous")]
        pub is_anonymous: Option<bool>,
        #[sea_orm(column_name = "phoneNumber")]
        pub phone_number: Option<String>,
        #[sea_orm(column_name = "phoneNumberVerified")]
        pub phone_number_verified: Option<bool>,
        #[sea_orm(column_name = "lastLoginMethod")]
        pub last_login_method: Option<String>,
        pub username: Option<String>,
        #[sea_orm(column_name = "displayUsername")]
        pub display_username: Option<String>,
        #[sea_orm(column_name = "twoFactorEnabled")]
        pub two_factor_enabled: Option<bool>,
        pub role: Option<String>,
        pub banned: Option<bool>,
        #[sea_orm(column_name = "banReason")]
        pub ban_reason: Option<String>,
        #[sea_orm(column_name = "banExpires")]
        pub ban_expires: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "session")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        pub token: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "ipAddress")]
        pub ip_address: Option<String>,
        #[sea_orm(column_name = "userAgent")]
        pub user_agent: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "activeTeamId")]
        pub active_team_id: Option<String>,
        #[sea_orm(column_name = "impersonatedBy")]
        pub impersonated_by: Option<String>,
        #[sea_orm(column_name = "activeOrganizationId")]
        pub active_organization_id: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod account {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "account")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "accountId")]
        pub account_id: String,
        #[sea_orm(column_name = "providerId")]
        pub provider_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "accessToken")]
        pub access_token: Option<String>,
        #[sea_orm(column_name = "refreshToken")]
        pub refresh_token: Option<String>,
        #[sea_orm(column_name = "idToken")]
        pub id_token: Option<String>,
        #[sea_orm(column_name = "accessTokenExpiresAt")]
        pub access_token_expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "refreshTokenExpiresAt")]
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod verification {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verification")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod wallet_address {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "walletAddress")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        pub address: String,
        #[sea_orm(column_name = "chainId")]
        pub chain_id: alibi::seaorm::Number,
        #[sea_orm(column_name = "isPrimary")]
        pub is_primary: bool,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod jwk {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "jwks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "publicKey")]
        pub public_key: String,
        #[sea_orm(column_name = "privateKey")]
        pub private_key: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: Option<DateTimeUtc>,
        pub alg: Option<String>,
        pub crv: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod team {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "team")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        #[sea_orm(column_name = "memberCount")]
        pub member_count: alibi::seaorm::Integer,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod team_member {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "teamMember")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "teamId")]
        pub team_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "membershipKey")]
        pub membership_key: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod organization_role {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "organizationRole")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        pub role: String,
        pub permission: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod two_factor {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "twoFactor")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub secret: String,
        #[sea_orm(column_name = "backupCodes")]
        pub backup_codes: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        pub verified: Option<bool>,
        #[sea_orm(column_name = "failedVerificationCount")]
        pub failed_verification_count: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "lockedUntil")]
        pub locked_until: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod device_code {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "deviceCode")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "deviceCode")]
        pub device_code: String,
        #[sea_orm(column_name = "userCode")]
        pub user_code: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: Option<String>,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        pub status: String,
        #[sea_orm(column_name = "lastPolledAt")]
        pub last_polled_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "pollingInterval")]
        pub polling_interval: Option<alibi::seaorm::Integer>,
        #[sea_orm(column_name = "clientId")]
        pub client_id: Option<String>,
        pub scope: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod organization {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "organization")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        #[sea_orm(column_type = "Text", save_as = "text")]
        pub metadata: Option<Json>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod member {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        pub role: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod invitation {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "invitation")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        pub email: String,
        pub role: Option<String>,
        #[sea_orm(column_name = "teamId")]
        pub team_id: Option<String>,
        pub status: String,
        #[sea_orm(column_name = "inviterId")]
        pub inviter_id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod api_key {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "apikey")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub start: Option<String>,
        pub prefix: Option<String>,
        #[sea_orm(column_name = "key")]
        pub key_hash: String,
        #[sea_orm(column_name = "referenceId")]
        pub reference_id: String,
        #[sea_orm(column_name = "configId")]
        pub config_id: String,
        #[sea_orm(column_name = "refillInterval")]
        pub refill_interval: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "refillAmount")]
        pub refill_amount: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "lastRefillAt")]
        pub last_refill_at: Option<DateTimeUtc>,
        pub enabled: Option<bool>,
        #[sea_orm(column_name = "rateLimitEnabled")]
        pub rate_limit_enabled: Option<bool>,
        #[sea_orm(column_name = "rateLimitTimeWindow")]
        pub rate_limit_time_window: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "rateLimitMax")]
        pub rate_limit_max: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "requestCount")]
        pub request_count: Option<alibi::seaorm::Number>,
        pub remaining: Option<alibi::seaorm::Number>,
        #[sea_orm(column_name = "lastRequest")]
        pub last_request: Option<DateTimeUtc>,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        pub permissions: Option<String>,
        pub metadata: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod passkey {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "passkey")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        #[sea_orm(column_name = "publicKey")]
        pub public_key: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "credentialID")]
        pub credential_id: String,
        pub counter: alibi::seaorm::Integer,
        #[sea_orm(column_name = "deviceType")]
        pub device_type: String,
        #[sea_orm(column_name = "backedUp")]
        pub backed_up: bool,
        pub transports: Option<String>,
        pub aaguid: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_client {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthClient")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "clientId")]
        pub client_id: String,
        #[sea_orm(column_name = "clientSecret")]
        pub client_secret: Option<String>,
        #[sea_orm(column_name = "clientDiscoveryId")]
        pub client_discovery_id: Option<String>,
        #[sea_orm(column_name = "disabled")]
        pub disabled: Option<bool>,
        #[sea_orm(column_name = "skipConsent")]
        pub skip_consent: Option<bool>,
        #[sea_orm(column_name = "enableEndSession")]
        pub enable_end_session: Option<bool>,
        #[sea_orm(column_name = "subjectType")]
        pub subject_type: Option<String>,
        #[sea_orm(column_name = "scopes")]
        pub scopes: Option<Json>,
        #[sea_orm(column_name = "clientCredentialsScopes")]
        pub client_credentials_scopes: Option<Json>,
        #[sea_orm(column_name = "userId")]
        pub user_id: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "name")]
        pub name: Option<String>,
        #[sea_orm(column_name = "uri")]
        pub uri: Option<String>,
        #[sea_orm(column_name = "icon")]
        pub icon: Option<String>,
        #[sea_orm(column_name = "contacts")]
        pub contacts: Option<Json>,
        #[sea_orm(column_name = "tos")]
        pub tos: Option<String>,
        #[sea_orm(column_name = "policy")]
        pub policy: Option<String>,
        #[sea_orm(column_name = "softwareId")]
        pub software_id: Option<String>,
        #[sea_orm(column_name = "softwareVersion")]
        pub software_version: Option<String>,
        #[sea_orm(column_name = "softwareStatement")]
        pub software_statement: Option<String>,
        #[sea_orm(column_name = "redirectUris")]
        pub redirect_uris: Json,
        #[sea_orm(column_name = "postLogoutRedirectUris")]
        pub post_logout_redirect_uris: Option<Json>,
        #[sea_orm(column_name = "backchannelLogoutUri")]
        pub backchannel_logout_uri: Option<String>,
        #[sea_orm(column_name = "backchannelLogoutSessionRequired")]
        pub backchannel_logout_session_required: Option<bool>,
        #[sea_orm(column_name = "tokenEndpointAuthMethod")]
        pub token_endpoint_auth_method: Option<String>,
        #[sea_orm(column_name = "applicationType")]
        pub application_type: Option<String>,
        #[sea_orm(column_name = "jwks")]
        pub jwks: Option<String>,
        #[sea_orm(column_name = "jwksUri")]
        pub jwks_uri: Option<String>,
        #[sea_orm(column_name = "grantTypes")]
        pub grant_types: Option<Json>,
        #[sea_orm(column_name = "responseTypes")]
        pub response_types: Option<Json>,
        #[sea_orm(column_name = "requirePKCE")]
        pub require_pkce: Option<bool>,
        #[sea_orm(column_name = "dpopBoundAccessTokens")]
        pub dpop_bound_access_tokens: Option<bool>,
        #[sea_orm(column_name = "referenceId")]
        pub reference_id: Option<String>,
        #[sea_orm(column_name = "metadata")]
        pub metadata: Option<Json>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_resource {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthResource")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "identifier")]
        pub identifier: String,
        #[sea_orm(column_name = "name")]
        pub name: String,
        #[sea_orm(column_name = "accessTokenTtl")]
        pub access_token_ttl: Option<alibi::seaorm::Integer>,
        #[sea_orm(column_name = "refreshTokenTtl")]
        pub refresh_token_ttl: Option<alibi::seaorm::Integer>,
        #[sea_orm(column_name = "signingAlgorithm")]
        pub signing_algorithm: Option<String>,
        #[sea_orm(column_name = "signingKeyId")]
        pub signing_key_id: Option<String>,
        #[sea_orm(column_name = "allowedScopes")]
        pub allowed_scopes: Option<Json>,
        #[sea_orm(column_name = "customClaims")]
        pub custom_claims: Option<Json>,
        #[sea_orm(column_name = "dpopBoundAccessTokensRequired")]
        pub dpop_bound_access_tokens_required: Option<bool>,
        #[sea_orm(column_name = "disabled")]
        pub disabled: Option<bool>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "policyVersion")]
        pub policy_version: Option<alibi::seaorm::Integer>,
        #[sea_orm(column_name = "metadata")]
        pub metadata: Option<Json>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_client_resource {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthClientResource")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "clientId")]
        pub client_id: String,
        #[sea_orm(column_name = "resourceId")]
        pub resource_id: String,
        #[sea_orm(column_name = "metadata")]
        pub metadata: Option<Json>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_refresh_token {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthRefreshToken")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "token")]
        pub token: String,
        #[sea_orm(column_name = "clientId")]
        pub client_id: String,
        #[sea_orm(column_name = "sessionId")]
        pub session_id: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "referenceId")]
        pub reference_id: Option<String>,
        #[sea_orm(column_name = "authorizationCodeId")]
        pub authorization_code_id: Option<String>,
        #[sea_orm(column_name = "resources")]
        pub resources: Option<Json>,
        #[sea_orm(column_name = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<Json>,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "revoked")]
        pub revoked: Option<DateTimeUtc>,
        #[sea_orm(column_name = "rotatedAt")]
        pub rotated_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "rotationReplayResponse")]
        pub rotation_replay_response: Option<String>,
        #[sea_orm(column_name = "rotationReplayExpiresAt")]
        pub rotation_replay_expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "authTime")]
        pub auth_time: Option<DateTimeUtc>,
        #[sea_orm(column_name = "confirmation")]
        pub confirmation: Option<Json>,
        #[sea_orm(column_name = "scopes")]
        pub scopes: Json,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_access_token {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthAccessToken")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "token")]
        pub token: String,
        #[sea_orm(column_name = "clientId")]
        pub client_id: String,
        #[sea_orm(column_name = "sessionId")]
        pub session_id: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: Option<String>,
        #[sea_orm(column_name = "referenceId")]
        pub reference_id: Option<String>,
        #[sea_orm(column_name = "authorizationCodeId")]
        pub authorization_code_id: Option<String>,
        #[sea_orm(column_name = "resources")]
        pub resources: Option<Json>,
        #[sea_orm(column_name = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<Json>,
        #[sea_orm(column_name = "refreshId")]
        pub refresh_id: Option<String>,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "revoked")]
        pub revoked: Option<DateTimeUtc>,
        #[sea_orm(column_name = "confirmation")]
        pub confirmation: Option<Json>,
        #[sea_orm(column_name = "scopes")]
        pub scopes: Json,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_consent {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthConsent")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "clientId")]
        pub client_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: Option<String>,
        #[sea_orm(column_name = "referenceId")]
        pub reference_id: Option<String>,
        #[sea_orm(column_name = "resources")]
        pub resources: Option<Json>,
        #[sea_orm(column_name = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<Json>,
        #[sea_orm(column_name = "scopes")]
        pub scopes: Json,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod oauth_client_assertion {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "oauthClientAssertion")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod rate_limit {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "rateLimit")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub key: String,
        pub count: i32,
        #[sea_orm(column_name = "lastRequest")]
        pub last_request: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
pub async fn run_app_migrations(
    database: &DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    let statements: &[&str] = match database.get_database_backend() {
        sea_orm::DbBackend::Sqlite => {
            &[
                "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" integer not null, \"image\" text, \"createdAt\" date not null, \"updatedAt\" date not null, \"role\" text, \"banned\" integer, \"banReason\" text, \"banExpires\" date, \"isAnonymous\" integer, \"phoneNumber\" text unique, \"phoneNumberVerified\" integer, \"lastLoginMethod\" text, \"username\" text unique, \"displayUsername\" text, \"twoFactorEnabled\" integer)",
                "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" date not null, \"token\" text not null unique, \"createdAt\" date not null, \"updatedAt\" date not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"impersonatedBy\" text, \"activeOrganizationId\" text, \"activeTeamId\" text)",
                "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" date, \"refreshTokenExpiresAt\" date, \"scope\" text, \"password\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
                "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" text not null primary key, \"name\" text not null, \"slug\" text not null unique, \"logo\" text, \"createdAt\" date not null, \"metadata\" text)",
                "CREATE TABLE IF NOT EXISTS \"organizationRole\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"role\" text not null, \"permission\" text not null, \"createdAt\" date not null, \"updatedAt\" date)",
                "create index IF NOT EXISTS \"organizationRole_organizationId_idx\" on \"organizationRole\" (\"organizationId\")",
                "create index IF NOT EXISTS \"organizationRole_role_idx\" on \"organizationRole\" (\"role\")",
                "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" text not null primary key, \"name\" text not null, \"memberCount\" integer not null, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"createdAt\" date not null, \"updatedAt\" date)",
                "create index IF NOT EXISTS \"team_organizationId_idx\" on \"team\" (\"organizationId\")",
                "CREATE TABLE IF NOT EXISTS \"teamMember\" (\"id\" text not null primary key, \"teamId\" text not null references \"team\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"membershipKey\" text unique, \"createdAt\" date)",
                "create index IF NOT EXISTS \"teamMember_teamId_idx\" on \"teamMember\" (\"teamId\")",
                "create index IF NOT EXISTS \"teamMember_userId_idx\" on \"teamMember\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"role\" text not null, \"createdAt\" date not null)",
                "create index IF NOT EXISTS \"member_organizationId_idx\" on \"member\" (\"organizationId\")",
                "create index IF NOT EXISTS \"member_userId_idx\" on \"member\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"email\" text not null, \"role\" text, \"teamId\" text, \"status\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"inviterId\" text not null references \"user\" (\"id\") on delete cascade)",
                "create index IF NOT EXISTS \"invitation_organizationId_idx\" on \"invitation\" (\"organizationId\")",
                "create index IF NOT EXISTS \"invitation_email_idx\" on \"invitation\" (\"email\")",
                "CREATE TABLE IF NOT EXISTS \"twoFactor\" (\"id\" text not null primary key, \"secret\" text not null, \"backupCodes\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"verified\" integer, \"failedVerificationCount\" integer, \"lockedUntil\" date)",
                "create index IF NOT EXISTS \"twoFactor_secret_idx\" on \"twoFactor\" (\"secret\")",
                "create index IF NOT EXISTS \"twoFactor_userId_idx\" on \"twoFactor\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"deviceCode\" (\"id\" text not null primary key, \"deviceCode\" text not null, \"userCode\" text not null, \"userId\" text, \"expiresAt\" date not null, \"status\" text not null, \"lastPolledAt\" date, \"pollingInterval\" integer, \"clientId\" text, \"scope\" text)",
                "create unique index IF NOT EXISTS \"deviceCode_deviceCode_uidx\" on \"deviceCode\" (\"deviceCode\")",
                "create unique index IF NOT EXISTS \"deviceCode_userCode_uidx\" on \"deviceCode\" (\"userCode\")",
                "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" text not null primary key, \"publicKey\" text not null, \"privateKey\" text not null, \"createdAt\" date not null, \"expiresAt\" date, \"alg\" text, \"crv\" text)",
                "CREATE TABLE IF NOT EXISTS \"walletAddress\" (\"id\" text not null primary key, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"address\" text not null, \"chainId\" integer not null, \"isPrimary\" integer not null, \"createdAt\" date not null)",
                "create index IF NOT EXISTS \"walletAddress_userId_idx\" on \"walletAddress\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"apikey\" (\"id\" text not null primary key, \"configId\" text not null, \"name\" text, \"start\" text, \"referenceId\" text not null, \"prefix\" text, \"key\" text not null, \"refillInterval\" integer, \"refillAmount\" integer, \"lastRefillAt\" date, \"enabled\" integer, \"rateLimitEnabled\" integer, \"rateLimitTimeWindow\" integer, \"rateLimitMax\" integer, \"requestCount\" integer, \"remaining\" integer, \"lastRequest\" date, \"expiresAt\" date, \"createdAt\" date not null, \"updatedAt\" date not null, \"permissions\" text, \"metadata\" text)",
                "create index IF NOT EXISTS \"apikey_configId_idx\" on \"apikey\" (\"configId\")",
                "create index IF NOT EXISTS \"apikey_referenceId_idx\" on \"apikey\" (\"referenceId\")",
                "create index IF NOT EXISTS \"apikey_key_idx\" on \"apikey\" (\"key\")",
                "CREATE TABLE IF NOT EXISTS \"passkey\" (\"id\" text not null primary key, \"name\" text, \"publicKey\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"credentialID\" text not null, \"counter\" integer not null, \"deviceType\" text not null, \"backedUp\" integer not null, \"transports\" text, \"createdAt\" date, \"aaguid\" text)",
                "create index IF NOT EXISTS \"passkey_userId_idx\" on \"passkey\" (\"userId\")",
                "create index IF NOT EXISTS \"passkey_credentialID_idx\" on \"passkey\" (\"credentialID\")",
                "CREATE TABLE IF NOT EXISTS \"oauthClient\" (\"id\" text not null primary key, \"clientId\" text not null unique, \"clientSecret\" text, \"clientDiscoveryId\" text, \"disabled\" integer, \"skipConsent\" integer, \"enableEndSession\" integer, \"subjectType\" text, \"scopes\" text, \"clientCredentialsScopes\" text, \"userId\" text references \"user\" (\"id\") on delete cascade, \"createdAt\" date, \"updatedAt\" date, \"name\" text, \"uri\" text, \"icon\" text, \"contacts\" text, \"tos\" text, \"policy\" text, \"softwareId\" text, \"softwareVersion\" text, \"softwareStatement\" text, \"redirectUris\" text not null, \"postLogoutRedirectUris\" text, \"backchannelLogoutUri\" text, \"backchannelLogoutSessionRequired\" integer, \"tokenEndpointAuthMethod\" text, \"applicationType\" text, \"jwks\" text, \"jwksUri\" text, \"grantTypes\" text, \"responseTypes\" text, \"requirePKCE\" integer, \"dpopBoundAccessTokens\" integer, \"referenceId\" text, \"metadata\" text)",
                "create index IF NOT EXISTS \"oauthClient_userId_idx\" on \"oauthClient\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthResource\" (\"id\" text not null primary key, \"identifier\" text not null unique, \"name\" text not null, \"accessTokenTtl\" integer, \"refreshTokenTtl\" integer, \"signingAlgorithm\" text, \"signingKeyId\" text, \"allowedScopes\" text, \"customClaims\" text, \"dpopBoundAccessTokensRequired\" integer, \"disabled\" integer, \"createdAt\" date, \"updatedAt\" date, \"policyVersion\" integer, \"metadata\" text)",
                "CREATE TABLE IF NOT EXISTS \"oauthClientResource\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"resourceId\" text not null references \"oauthResource\" (\"identifier\") on delete cascade, \"metadata\" text, \"createdAt\" date)",
                "create index IF NOT EXISTS \"oauthClientResource_clientId_idx\" on \"oauthClientResource\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthClientResource_resourceId_idx\" on \"oauthClientResource\" (\"resourceId\")",
                "create unique index IF NOT EXISTS \"oauthClientResource_clientId_resourceId_uidx\" on \"oauthClientResource\" (\"clientId\", \"resourceId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthRefreshToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"expiresAt\" date not null, \"createdAt\" date not null, \"revoked\" date, \"rotatedAt\" date, \"rotationReplayResponse\" text, \"rotationReplayExpiresAt\" date, \"authTime\" date, \"confirmation\" text, \"scopes\" text not null)",
                "create index IF NOT EXISTS \"oauthRefreshToken_clientId_idx\" on \"oauthRefreshToken\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_sessionId_idx\" on \"oauthRefreshToken\" (\"sessionId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_userId_idx\" on \"oauthRefreshToken\" (\"userId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_authorizationCodeId_idx\" on \"oauthRefreshToken\" (\"authorizationCodeId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthAccessToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"refreshId\" text references \"oauthRefreshToken\" (\"id\") on delete cascade, \"expiresAt\" date not null, \"createdAt\" date not null, \"revoked\" date, \"confirmation\" text, \"scopes\" text not null)",
                "create index IF NOT EXISTS \"oauthAccessToken_clientId_idx\" on \"oauthAccessToken\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_sessionId_idx\" on \"oauthAccessToken\" (\"sessionId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_userId_idx\" on \"oauthAccessToken\" (\"userId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_authorizationCodeId_idx\" on \"oauthAccessToken\" (\"authorizationCodeId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_refreshId_idx\" on \"oauthAccessToken\" (\"refreshId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthConsent\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"scopes\" text not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "create index IF NOT EXISTS \"oauthConsent_clientId_idx\" on \"oauthConsent\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthConsent_userId_idx\" on \"oauthConsent\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthClientAssertion\" (\"id\" text not null primary key, \"expiresAt\" date not null)",
                "CREATE TABLE IF NOT EXISTS \"rateLimit\" (\"id\" text not null primary key, \"key\" text not null unique, \"count\" integer not null, \"lastRequest\" bigint not null)",
            ]
        }
        sea_orm::DbBackend::Postgres => {
            &[
                "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" boolean not null, \"image\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null, \"role\" text, \"banned\" boolean, \"banReason\" text, \"banExpires\" timestamptz, \"isAnonymous\" boolean, \"phoneNumber\" text unique, \"phoneNumberVerified\" boolean, \"lastLoginMethod\" text, \"username\" text unique, \"displayUsername\" text, \"twoFactorEnabled\" boolean)",
                "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null, \"token\" text not null unique, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"impersonatedBy\" text, \"activeOrganizationId\" text, \"activeTeamId\" text)",
                "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" timestamptz, \"refreshTokenExpiresAt\" timestamptz, \"scope\" text, \"password\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null)",
                "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
                "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
                "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" text not null primary key, \"name\" text not null, \"slug\" text not null unique, \"logo\" text, \"createdAt\" timestamptz not null, \"metadata\" text)",
                "CREATE TABLE IF NOT EXISTS \"organizationRole\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"role\" text not null, \"permission\" text not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz)",
                "create index IF NOT EXISTS \"organizationRole_organizationId_idx\" on \"organizationRole\" (\"organizationId\")",
                "create index IF NOT EXISTS \"organizationRole_role_idx\" on \"organizationRole\" (\"role\")",
                "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" text not null primary key, \"name\" text not null, \"memberCount\" integer not null, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz)",
                "create index IF NOT EXISTS \"team_organizationId_idx\" on \"team\" (\"organizationId\")",
                "CREATE TABLE IF NOT EXISTS \"teamMember\" (\"id\" text not null primary key, \"teamId\" text not null references \"team\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"membershipKey\" text unique, \"createdAt\" timestamptz)",
                "create index IF NOT EXISTS \"teamMember_teamId_idx\" on \"teamMember\" (\"teamId\")",
                "create index IF NOT EXISTS \"teamMember_userId_idx\" on \"teamMember\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"role\" text not null, \"createdAt\" timestamptz not null)",
                "create index IF NOT EXISTS \"member_organizationId_idx\" on \"member\" (\"organizationId\")",
                "create index IF NOT EXISTS \"member_userId_idx\" on \"member\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"email\" text not null, \"role\" text, \"teamId\" text, \"status\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"inviterId\" text not null references \"user\" (\"id\") on delete cascade)",
                "create index IF NOT EXISTS \"invitation_organizationId_idx\" on \"invitation\" (\"organizationId\")",
                "create index IF NOT EXISTS \"invitation_email_idx\" on \"invitation\" (\"email\")",
                "CREATE TABLE IF NOT EXISTS \"twoFactor\" (\"id\" text not null primary key, \"secret\" text not null, \"backupCodes\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"verified\" boolean, \"failedVerificationCount\" integer, \"lockedUntil\" timestamptz)",
                "create index IF NOT EXISTS \"twoFactor_secret_idx\" on \"twoFactor\" (\"secret\")",
                "create index IF NOT EXISTS \"twoFactor_userId_idx\" on \"twoFactor\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"deviceCode\" (\"id\" text not null primary key, \"deviceCode\" text not null, \"userCode\" text not null, \"userId\" text, \"expiresAt\" timestamptz not null, \"status\" text not null, \"lastPolledAt\" timestamptz, \"pollingInterval\" integer, \"clientId\" text, \"scope\" text)",
                "create unique index IF NOT EXISTS \"deviceCode_deviceCode_uidx\" on \"deviceCode\" (\"deviceCode\")",
                "create unique index IF NOT EXISTS \"deviceCode_userCode_uidx\" on \"deviceCode\" (\"userCode\")",
                "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" text not null primary key, \"publicKey\" text not null, \"privateKey\" text not null, \"createdAt\" timestamptz not null, \"expiresAt\" timestamptz, \"alg\" text, \"crv\" text)",
                "CREATE TABLE IF NOT EXISTS \"walletAddress\" (\"id\" text not null primary key, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"address\" text not null, \"chainId\" integer not null, \"isPrimary\" boolean not null, \"createdAt\" timestamptz not null)",
                "create index IF NOT EXISTS \"walletAddress_userId_idx\" on \"walletAddress\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"apikey\" (\"id\" text not null primary key, \"configId\" text not null, \"name\" text, \"start\" text, \"referenceId\" text not null, \"prefix\" text, \"key\" text not null, \"refillInterval\" integer, \"refillAmount\" integer, \"lastRefillAt\" timestamptz, \"enabled\" boolean, \"rateLimitEnabled\" boolean, \"rateLimitTimeWindow\" integer, \"rateLimitMax\" integer, \"requestCount\" integer, \"remaining\" integer, \"lastRequest\" timestamptz, \"expiresAt\" timestamptz, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz not null, \"permissions\" text, \"metadata\" text)",
                "create index IF NOT EXISTS \"apikey_configId_idx\" on \"apikey\" (\"configId\")",
                "create index IF NOT EXISTS \"apikey_referenceId_idx\" on \"apikey\" (\"referenceId\")",
                "create index IF NOT EXISTS \"apikey_key_idx\" on \"apikey\" (\"key\")",
                "CREATE TABLE IF NOT EXISTS \"passkey\" (\"id\" text not null primary key, \"name\" text, \"publicKey\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"credentialID\" text not null, \"counter\" integer not null, \"deviceType\" text not null, \"backedUp\" boolean not null, \"transports\" text, \"createdAt\" timestamptz, \"aaguid\" text)",
                "create index IF NOT EXISTS \"passkey_userId_idx\" on \"passkey\" (\"userId\")",
                "create index IF NOT EXISTS \"passkey_credentialID_idx\" on \"passkey\" (\"credentialID\")",
                "CREATE TABLE IF NOT EXISTS \"oauthClient\" (\"id\" text not null primary key, \"clientId\" text not null unique, \"clientSecret\" text, \"clientDiscoveryId\" text, \"disabled\" boolean, \"skipConsent\" boolean, \"enableEndSession\" boolean, \"subjectType\" text, \"scopes\" jsonb, \"clientCredentialsScopes\" jsonb, \"userId\" text references \"user\" (\"id\") on delete cascade, \"createdAt\" timestamptz, \"updatedAt\" timestamptz, \"name\" text, \"uri\" text, \"icon\" text, \"contacts\" jsonb, \"tos\" text, \"policy\" text, \"softwareId\" text, \"softwareVersion\" text, \"softwareStatement\" text, \"redirectUris\" jsonb not null, \"postLogoutRedirectUris\" jsonb, \"backchannelLogoutUri\" text, \"backchannelLogoutSessionRequired\" boolean, \"tokenEndpointAuthMethod\" text, \"applicationType\" text, \"jwks\" text, \"jwksUri\" text, \"grantTypes\" jsonb, \"responseTypes\" jsonb, \"requirePKCE\" boolean, \"dpopBoundAccessTokens\" boolean, \"referenceId\" text, \"metadata\" jsonb)",
                "create index IF NOT EXISTS \"oauthClient_userId_idx\" on \"oauthClient\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthResource\" (\"id\" text not null primary key, \"identifier\" text not null unique, \"name\" text not null, \"accessTokenTtl\" integer, \"refreshTokenTtl\" integer, \"signingAlgorithm\" text, \"signingKeyId\" text, \"allowedScopes\" jsonb, \"customClaims\" jsonb, \"dpopBoundAccessTokensRequired\" boolean, \"disabled\" boolean, \"createdAt\" timestamptz, \"updatedAt\" timestamptz, \"policyVersion\" integer, \"metadata\" jsonb)",
                "CREATE TABLE IF NOT EXISTS \"oauthClientResource\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"resourceId\" text not null references \"oauthResource\" (\"identifier\") on delete cascade, \"metadata\" jsonb, \"createdAt\" timestamptz)",
                "create index IF NOT EXISTS \"oauthClientResource_clientId_idx\" on \"oauthClientResource\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthClientResource_resourceId_idx\" on \"oauthClientResource\" (\"resourceId\")",
                "create unique index IF NOT EXISTS \"oauthClientResource_clientId_resourceId_uidx\" on \"oauthClientResource\" (\"clientId\", \"resourceId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthRefreshToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz not null, \"revoked\" timestamptz, \"rotatedAt\" timestamptz, \"rotationReplayResponse\" text, \"rotationReplayExpiresAt\" timestamptz, \"authTime\" timestamptz, \"confirmation\" jsonb, \"scopes\" jsonb not null)",
                "create index IF NOT EXISTS \"oauthRefreshToken_clientId_idx\" on \"oauthRefreshToken\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_sessionId_idx\" on \"oauthRefreshToken\" (\"sessionId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_userId_idx\" on \"oauthRefreshToken\" (\"userId\")",
                "create index IF NOT EXISTS \"oauthRefreshToken_authorizationCodeId_idx\" on \"oauthRefreshToken\" (\"authorizationCodeId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthAccessToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"refreshId\" text references \"oauthRefreshToken\" (\"id\") on delete cascade, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz not null, \"revoked\" timestamptz, \"confirmation\" jsonb, \"scopes\" jsonb not null)",
                "create index IF NOT EXISTS \"oauthAccessToken_clientId_idx\" on \"oauthAccessToken\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_sessionId_idx\" on \"oauthAccessToken\" (\"sessionId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_userId_idx\" on \"oauthAccessToken\" (\"userId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_authorizationCodeId_idx\" on \"oauthAccessToken\" (\"authorizationCodeId\")",
                "create index IF NOT EXISTS \"oauthAccessToken_refreshId_idx\" on \"oauthAccessToken\" (\"refreshId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthConsent\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"scopes\" jsonb not null, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz not null)",
                "create index IF NOT EXISTS \"oauthConsent_clientId_idx\" on \"oauthConsent\" (\"clientId\")",
                "create index IF NOT EXISTS \"oauthConsent_userId_idx\" on \"oauthConsent\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"oauthClientAssertion\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null)",
                "CREATE TABLE IF NOT EXISTS \"rateLimit\" (\"id\" text not null primary key, \"key\" text not null unique, \"count\" integer not null, \"lastRequest\" bigint not null)",
            ]
        }
        _ => {
            return Err(
                sea_orm::DbErr::Custom(
                    "Generated migrations support SQLite and PostgreSQL".into(),
                ),
            );
        }
    };
    for statement in statements {
        let _ = database.execute_unprepared(statement).await?;
    }
    Ok(())
}
