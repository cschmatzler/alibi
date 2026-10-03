//! Local Google JWKS transport and actual persisted One Tap configuration profiles.
use crate::{CompatVerificationSender, EmailOutboxRecord, TestSchema};
use async_trait::async_trait;
use axum::{routing::get, Json, Router};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{OAuthIdTokenVerifier, OAuthProvider};
use better_auth::plugins::one_tap::{GoogleJwksSource, OneTapClientId, OneTapConfig, OneTapPlugin};
use better_auth::plugins::{
    AdminPlugin, EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin, OrganizationPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::sea_orm::{DatabaseConnection, EntityTrait};
use better_auth_seaorm::store::entities::{account, session, user};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
const JWKS: &str = include_str!("../../../../fixtures/one-tap/jwks.json");
struct LocalKeys(String);
pub(crate) fn local_keys(base_url: &str) -> Arc<dyn GoogleJwksSource> {
    Arc::new(LocalKeys(format!("{base_url}/__test/one-tap/jwks")))
}
#[async_trait]
impl GoogleJwksSource for LocalKeys {
    async fn fetch_keys(&self) -> Result<Vec<Value>, String> {
        let value: Value = reqwest::Client::new()
            .get(&self.0)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        value
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "Missing fixture keys".into())
    }
}
struct RejectProviderVerifier;
#[async_trait]
impl OAuthIdTokenVerifier for RejectProviderVerifier {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Ok(false)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "one-tap-default",
        "one-tap-fallback",
        "one-tap-plugin-only",
        "one-tap-missing",
        "one-tap-empty-array",
        "one-tap-empty-audience-member",
        "one-tap-domain",
        "one-tap-domain-any",
        "one-tap-disabled",
        "one-tap-provider-disabled",
        "one-tap-required",
        "one-tap-required-no-mail",
        "one-tap-no-override",
        "one-tap-account-cookie",
        "one-tap-account-cookie-account-fractional",
        "one-tap-account-cookie-account-zero",
        "one-tap-account-cookie-account-negative",
        "one-tap-account-cookie-account-nan",
        "one-tap-account-cookie-fractional",
        "one-tap-account-cookie-zero",
        "one-tap-account-cookie-negative",
        "one-tap-account-cookie-nan",
        "one-tap-account-cookie-infinity",
        "one-tap-account-cookie-override",
        "one-tap-update-link",
        "one-tap-encrypted",
        "one-tap-retain-account",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut profile_config = config.clone().base_path(&path);
        profile_config.account.store_account_cookie =
            name.starts_with("one-tap-account-cookie") || name == "one-tap-retain-account";
        profile_config
            .account
            .account_linking
            .update_user_info_on_link = name == "one-tap-update-link";
        if name == "one-tap-update-link" {
            profile_config.account.account_linking.trusted_providers = vec!["google".into()];
        }
        profile_config.account.encrypt_oauth_tokens = name == "one-tap-encrypted";
        profile_config.account.update_account_on_sign_in = name != "one-tap-retain-account";
        profile_config.account.cookie_max_age = match name {
            "one-tap-account-cookie-account-fractional" => Some(1.75),
            "one-tap-account-cookie-account-zero" => Some(0.0),
            "one-tap-account-cookie-account-negative" => Some(-4.25),
            "one-tap-account-cookie-account-nan" => Some(f64::NAN),
            _ => None,
        };
        let age = match name {
            "one-tap-account-cookie-fractional" => Some(1.75),
            "one-tap-account-cookie-zero" => Some(0.0),
            "one-tap-account-cookie-negative" => Some(-4.25),
            "one-tap-account-cookie-nan" => Some(f64::NAN),
            "one-tap-account-cookie-infinity" => Some(f64::INFINITY),
            "one-tap-account-cookie-override" => Some(1.75),
            _ => None,
        };
        if let Some(max_age) = age {
            profile_config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
                enabled: false,
                max_age,
                ..Default::default()
            });
        }
        if name == "one-tap-account-cookie-override" {
            profile_config.advanced.cookies.insert(
                "account_data".into(),
                better_auth_core::config::CookieOverride {
                    name: None,
                    attributes: better_auth_core::config::CookieAttributes {
                        max_age: Some(7),
                        http_only: Some(false),
                        same_site: Some(better_auth_core::config::SameSite::Strict),
                        ..Default::default()
                    },
                },
            );
        }

        let mut provider =
            OAuthProvider::google("one-tap-provider-client", "local-unused-google-secret");
        provider.verify_id_token = Some(Arc::new(RejectProviderVerifier));
        if name == "one-tap-fallback" {
            provider = provider.with_client_ids(vec![
                "one-tap-provider-client".into(),
                "one-tap-provider-secondary".into(),
            ]);
        }
        if name == "one-tap-domain" {
            provider = provider.with_hosted_domain("workspace.fixture.test");
        }
        if name == "one-tap-domain-any" {
            provider = provider.with_hosted_domain("*");
        }
        provider.disable_sign_up = name == "one-tap-provider-disabled";
        provider.override_user_info_on_sign_in = name == "one-tap-no-override";
        provider.require_email_verification = name.starts_with("one-tap-required");
        let mut one_tap = OneTapConfig {
            client_id: Some(OneTapClientId::Single("one-tap-plugin-client".into())),
            disable_signup: name == "one-tap-disabled",
            jwks_source: Some(Arc::new(LocalKeys(format!(
                "{}/__test/one-tap/jwks",
                config.base_url
            )))),
        };
        if name == "one-tap-fallback" || name == "one-tap-missing" {
            one_tap.client_id = None;
        }
        if name == "one-tap-empty-audience-member" {
            one_tap.client_id = Some(OneTapClientId::Multiple(vec![String::new()]));
        }
        if name == "one-tap-empty-array" {
            one_tap.client_id = Some(OneTapClientId::Multiple(Vec::new()));
        }
        let mut oauth = OAuthPlugin::new();
        if name != "one-tap-plugin-only" && name != "one-tap-missing" {
            oauth = oauth.add_provider("google", provider);
        }
        let mut verification = EmailVerificationPlugin::new()
            .custom_send_verification_email(Arc::new(CompatVerificationSender {
                outbox: outbox.clone(),
            }))
            .send_on_sign_in(name == "one-tap-required");
        if name == "one-tap-required-no-mail" {
            verification = verification.send_on_sign_up(false);
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(profile_config.clone())
                .store(crate::backend::store::<TestSchema>(
                    profile_config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(AdminPlugin::new())
                .plugin(OrganizationPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(verification)
                .plugin(oauth)
                .plugin(OneTapPlugin::with_config(one_tap))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let fetches = Arc::new(AtomicUsize::new(0));
    let jwks_fetches = fetches.clone();
    router = router.route(
        "/__test/one-tap/jwks",
        get(move || {
            let fetches = jwks_fetches.clone();
            async move {
                _ = fetches.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::from_str::<Value>(JWKS).expect("fixture public JWKS"))
            }
        }),
    );
    Ok(router.route("/__test/one-tap/state", get(move || { let database = database.clone(); let fetches = fetches.clone(); async move {
        let users = user::Entity::find().all(&database).await.expect("fixture user rows");
        let accounts = account::Entity::find().all(&database).await.expect("fixture account rows");
        let sessions = session::Entity::find().all(&database).await.expect("fixture session rows");
        Json(json!({"jwksFetches":fetches.load(Ordering::SeqCst),"users":users.into_iter().map(|user|json!({"id":user.id,"email":user.email,"name":user.name,"emailVerified":user.email_verified,"image":user.image})).collect::<Vec<_>>(),"accounts":accounts.into_iter().map(|account|json!({"id":account.id,"userId":account.user_id,"providerId":account.provider_id,"accountId":account.account_id,"scope":account.scope,"idToken":account.id_token})).collect::<Vec<_>>(),"sessions":sessions.into_iter().map(|session|json!({"id":session.id,"userId":session.user_id,"token":session.token})).collect::<Vec<_>>()}))
    } })))
}
