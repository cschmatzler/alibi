//! Plugin initialization, HTTP dispatch and persisted effects on both adapters.
//! Validation tables remain owned by plugin units; these exercise composition.
mod account_fields;
mod account_sessions;
mod admin;
mod admin_matrix;
mod admin_policy;
mod anonymous_flows;
mod api_key_callbacks;
mod api_key_matrix;
mod api_key_policy;
mod auth_probe;
mod cookie_cache;
mod credentials;
mod crypto;
mod device_callbacks;
mod device_grant;
mod email_otp_matrix;
mod email_password_matrix;
mod email_verification_matrix;
mod factor_policy;
mod identity_policy;
mod jwt_matrix;
mod last_login_flows;
mod magic_link_matrix;
mod oauth_configuration;
mod oauth_grant_profiles;
mod oauth_id_token_claims;
mod oauth_profile_edges;
mod oauth_profiles;
mod oauth_provider_policies;
mod oauth_refresh;
mod oauth_remote;
mod oauth_signed;
mod oidc;
mod one_time_token_matrix;
mod organization;
mod organization_callbacks;
mod organization_invitations;
mod organization_matrix;
mod organization_members;
mod otp_callbacks;
mod passkey_attestation;
mod passkey_hooks;
mod passkey_matrix;
mod password_management_matrix;
mod passwordless;
mod passwordless_fields_matrix;
mod phone_number_matrix;
mod providers;
mod screening_matrix;
mod secondary_sessions;
mod server_account_listing;
mod server_account_unlink;
mod server_admin_ban_user;
mod server_admin_create_user;
mod server_admin_get_user;
mod server_admin_impersonate_user;
mod server_admin_list_user_sessions;
mod server_admin_list_users;
mod server_admin_permission;
mod server_admin_remove_user;
mod server_admin_revoke_user_session;
mod server_admin_revoke_user_sessions;
mod server_admin_session_cache;
mod server_admin_set_role;
mod server_admin_set_user_password;
mod server_admin_stop_impersonating;
mod server_admin_support;
mod server_admin_unban_user;
mod server_admin_update_user;
mod server_api_key_get;
mod server_api_key_list;
mod server_change_password;
mod server_email_otp_check;
mod server_email_otp_reset;
mod server_email_otp_sign_in;
mod server_email_otp_verify;
mod server_endpoints;
mod server_link_social_account;
mod server_list_sessions;
mod server_revocation_support;
mod server_revoke_other_sessions;
mod server_revoke_sessions;
mod server_set_password;
mod server_sign_in_email;
mod server_sign_in_social;
mod server_sign_out;
mod server_sign_up_email;
mod server_siwe_nonce;
mod server_siwe_verify;
mod server_update_session;
mod server_update_user;
mod server_verify_password;
#[cfg(all(feature = "sqlx", feature = "seaorm"))]
mod session_fields;
mod session_plugin_matrix;
mod session_plugins;
mod signup_privacy;
mod siwe_matrix;
mod social_account_api;
mod social_accounts;
mod social_flows;
mod social_grants;
mod social_logout;
mod social_one_tap;
mod social_popup;
mod social_proxy;
mod two_factor;
mod two_factor_matrix;
mod user_defaults;
mod user_lifecycle;
mod user_management_matrix;
mod verification_cache;

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthSchema};
use alibi::{AuthRequest, AuthResponse, HttpMethod};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const SECRET: &str = "native-plugin-composition-secret-at-least-32";
const ORIGIN: &str = "http://localhost:43219";
const PASSWORD: &str = "a-native-password-123";

fn builder<B: Backend>(connection: &B::Connection) -> AuthBuilder<B::Schema> {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
}

fn request(path: &str, body: Option<Value>, cookie: &str) -> AuthRequest {
    let mut request = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        format!("/api/auth{path}"),
    );
    request.headers.extend([
        ("origin".into(), ORIGIN.into()),
        ("content-type".into(), "application/json".into()),
        ("cookie".into(), cookie.into()),
    ]);
    request.body = body.map(|body| body.to_string().into_bytes());
    request
}

async fn call<S: AuthSchema>(auth: &Alibi<S>, request: AuthRequest, status: u16) -> AuthResponse {
    let path = request.path.clone();
    let response = Box::pin(auth.handle_request(request)).await.unwrap();
    assert_eq!(
        response.status,
        status,
        "{path}: {}",
        String::from_utf8_lossy(&response.body)
    );
    response
}

fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

fn cookies(response: &AuthResponse) -> String {
    // Apply repeated Set-Cookie fields in wire order, as a browser does. In
    // particular, impersonation clears the old session before publishing a new one.
    let mut jar = std::collections::BTreeMap::new();
    for header in response.headers.get_all("set-cookie") {
        let (name, value) = header.split(';').next().unwrap().split_once('=').unwrap();
        if value.is_empty() {
            let _ = jar.remove(name);
        } else {
            let _ = jar.insert(name, value);
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn signup<S: AuthSchema>(auth: &Alibi<S>, email: &str) -> AuthResponse {
    call(
        auth,
        request(
            "/sign-up/email",
            Some(json!({"email":email,"password":PASSWORD,"name":"Native owner"})),
            "",
        ),
        200,
    )
    .await
}

async fn authenticated<S: AuthSchema>(auth: &Alibi<S>, cookie: &str, email: &str) {
    let session = call(auth, request("/get-session", None, cookie), 200).await;
    assert_eq!(body(&session)["user"]["email"], email);
    assert!(
        body(&session)["session"]["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[derive(Clone)]
struct Exchange {
    method: axum::http::Method,
    path: String,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

type ProviderReply = (u16, &'static str, String);

/// Only the remote protocol is replaced. Auth handlers, crypto and stores stay real.
struct Provider {
    url: url::Url,
    requests: Arc<Mutex<Vec<Exchange>>>,
    reply: Arc<Mutex<ProviderReply>>,
    routes: Arc<Mutex<std::collections::HashMap<String, ProviderReply>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Provider {
    async fn start(content_type: &'static str, body: impl Into<String>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reply = Arc::new(Mutex::new((200, content_type, body.into())));
        let routes = Arc::new(Mutex::new(std::collections::HashMap::<
            String,
            (u16, &'static str, String),
        >::new()));
        let route_replies = Arc::clone(&routes);
        let captured = Arc::clone(&requests);
        let served = Arc::clone(&reply);
        let router = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let route_replies = Arc::clone(&route_replies);
            let captured = Arc::clone(&captured);
            let served = Arc::clone(&served);
            async move {
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, 16_384).await.unwrap();
                captured.lock().unwrap().push(Exchange {
                    method: parts.method,
                    path: parts.uri.to_string(),
                    headers: parts.headers,
                    body: bytes.to_vec(),
                });
                let (status, content_type, body) = route_replies
                    .lock()
                    .unwrap()
                    .get(parts.uri.path())
                    .cloned()
                    .unwrap_or_else(|| served.lock().unwrap().clone());
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    [("content-type", content_type)],
                    body,
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            requests,
            reply,
            routes,
            task,
        }
    }

    fn respond(&self, status: u16, content_type: &'static str, body: impl Into<String>) {
        *self.reply.lock().unwrap() = (status, content_type, body.into());
    }

    fn respond_at(&self, path: &str, status: u16, body: Value) {
        drop(
            self.routes
                .lock()
                .unwrap()
                .insert(path.into(), (status, "application/json", body.to_string())),
        );
    }

    fn take(&self) -> Vec<Exchange> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

mod server_revoke_session;

mod server_reset_password;

mod server_request_password_reset;

mod server_reset_password_callback;

mod server_verify_email;

mod server_send_verification_email;

mod server_ok;

mod server_delete_user;

mod server_delete_user_callback;

mod server_change_email;

mod server_callback_oauth;
mod server_oauth_support;

mod server_organization_create_invitation;

mod server_organization_check_slug;

mod server_organization_add_team_member;
mod server_organization_create_team;
mod server_organization_list_team_members;
mod server_organization_list_teams;
mod server_organization_list_user_teams;
mod server_organization_remove_team;
mod server_organization_set_active_team;
mod server_organization_update_team;

mod server_organization_create_role;

mod server_organization_get_role;

mod oauth_server_metadata;

mod oauth_client_authentication;
mod oauth_client_creation;

mod oauth_client_read;

mod oauth_client_public_read;

mod oauth_client_list;

mod oauth_client_delete;

mod oauth_client_secret_rotation;

mod oauth_client_update;

mod oauth_client_registration;

mod oauth_admin_client_creation;

mod oauth_admin_client_update;

mod oauth_authorization;
mod oauth_authorization_signup;
mod oauth_max_age;

mod oauth_prelogin_client;

mod oauth_consent;

mod oauth_consent_list;

mod oauth_consent_read;

mod oauth_consent_update;

mod oauth_consent_delete;

mod oauth_resource_creation;

mod oauth_resource_list;

mod oauth_resource_read;

mod oauth_resource_update;

mod oauth_resource_delete;

mod oauth_resource_link;

mod oauth_resource_unlink;

mod oauth_continuation;

mod oauth_token;

mod oauth_offline_tokens;

mod oauth_introspection;

mod oauth_revocation;

mod oauth_id_token;

mod oauth_userinfo;

mod oauth_logout;

mod oauth_logout_confirmation;

mod oauth_session_retirement;

mod oauth_refresh_grant;

mod oauth_client_credentials;

mod oauth_protocol_forms;

mod oauth_refresh_reuse;

mod sso_registration;
mod sso_sp_metadata;

mod sso_provider_read;

mod sso_provider_list;

mod sso_provider_delete;

mod sso_provider_update;

mod sso_domain_request;

mod sso_domain_verify;

mod sso_saml_acs;
mod sso_saml_logout;
mod sso_saml_sign_in;
mod sso_sign_in;

mod sso_callback;

#[path = "../../../support/sso_saml_grant.rs"]
mod saml_idp;

#[path = "../../../support/sso_dns.rs"]
mod sso_dns;

#[path = "../../../support/sso_configured_providers.rs"]
mod sso_configured_providers;

#[path = "../../../support/sso_key_resolver.rs"]
mod sso_key_resolver;

#[path = "../../../support/sso_provisioning_policy.rs"]
mod sso_provisioning_policy;

mod sso_domain_membership;

#[path = "../../../support/sso_oidc_peer.rs"]
mod sso_oidc_peer;

#[path = "../../../support/sso_saml_encryption.rs"]
mod sso_saml_encryption;

mod sso_endpoint_admission;

mod sso_oidc_mapping;

mod sso_mutation_guard;
#[path = "../../../support/sso_mutation_policy.rs"]
mod sso_mutation_policy;

mod sso_user_resolution;
#[path = "../../../support/sso_user_resolution_policy.rs"]
mod sso_user_resolution_policy;

#[path = "../../../support/sso_provider_limit_policy.rs"]
mod sso_provider_limit_policy;
mod sso_provider_limits;

mod sso_idp_initiated;

mod sso_saml_algorithms;

mod sso_saml_signing_policy;
#[path = "../../../support/sso_signing_policy.rs"]
mod sso_signing_policy;

#[path = "../../../support/sso_encryption_policy.rs"]
mod sso_encryption_policy;

mod sso_storage_mapping;
#[path = "../../../support/sso_storage_schema.rs"]
mod sso_storage_schema;

mod sso_additional_fields;
#[path = "../../../support/sso_additional_fields.rs"]
mod sso_additional_fields_config;

mod scim_discovery;

mod sso_date_fields;
#[path = "../../../support/sso_date_fields.rs"]
mod sso_date_fields_config;

mod scim_managed_create;

mod scim_managed_list;

mod scim_managed_get;

mod scim_configured_projection;
mod scim_identity_reconciliation;
mod scim_managed_decommission;
mod scim_managed_events;
mod scim_managed_revoke;
mod scim_managed_rotate;
mod scim_populated_decommission;
mod scim_projection_admission;
mod scim_role_projection;
mod scim_terminal_binding;

mod scim_group_read;

mod scim_managed_bearer;

mod scim_bearer_verifier;

mod scim_user_read;

mod scim_group_list;

mod scim_user_list;

mod scim_group_create;

mod scim_group_delete;

mod scim_group_replace;

mod scim_group_patch;

mod scim_user_delete;

mod scim_user_create;

mod scim_user_replace;

mod scim_user_patch;

mod organization_feature_surface;

mod server_bearer;

mod server_custom_session;

mod server_multi_session;

mod scim_user_input;

mod server_last_login;

mod server_one_time_token_header;

mod scim_http_admission;

mod scim_entra_compatibility;

mod oauth_private_key_jwt;

mod oauth_assertion_consumption;

mod oauth_client_discovery;
mod oauth_server_client_authentication;
mod oauth_server_token_issuance;

mod oauth_remote_client_jwks;

mod oauth_token_expiration;

mod oauth_scope_expiration;

mod oauth_resource_issuance_admission;

mod oauth_resource_token_policy;

mod oauth_server_refresh_issuance;

mod oauth_claims_request;
mod oauth_extension_grants;
mod oauth_extension_metadata;
mod oauth_pairwise_subject;
mod oauth_extension_claims;
mod oauth_extension_authentication;
#[cfg(feature="axum")]
mod session_post_media;
mod request_form_mime;
mod oauth_dpop_proof;
