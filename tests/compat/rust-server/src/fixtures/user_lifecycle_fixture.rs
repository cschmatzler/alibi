//! Real application callbacks and persisted observations for mailbox lifecycles.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::email_verification::SendVerificationEmail;
use better_auth::plugins::user_management::{
    AfterDeleteUser, BeforeDeleteUser, SendChangeEmailConfirmation, SendDeleteAccountVerification,
    UserInfo,
};
use better_auth::plugins::{
    EmailPasswordConfig, EmailPasswordPlugin, EmailVerificationPlugin, SessionManagementPlugin,
    UserManagementPlugin,
};
use better_auth::wire::UserView;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::utils::password::{PasswordHasher, ScryptHasher};
use better_auth_core::{
    CacheVersionContext, CookieCacheConfig, CookieCacheVersion, CookieCacheVersionResolver,
};
use better_auth_seaorm::{
    DatabaseConnection, SeaOrmStore,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, sea_query::Expr},
    store::entities::{account, session, user, verification},
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    events: Vec<Value>,
    failure: String,
    hold_next: bool,
    held: bool,
}
#[derive(Default)]
struct Application {
    state: Mutex<State>,
    release: tokio::sync::Notify,
}
impl Application {
    fn event(&self, stage: &str, user: Value, extra: Value) -> AuthResult<()> {
        let request = current_request_hook_context().map(|context| {
            json!({
                "method":format!("{:?}",context.method).to_uppercase(),
                "url":context.url,
                "marker":context.headers.get("x-lifecycle-marker"),
            })
        });
        let mut event = json!({"stage":stage,"user":user,"request":request});
        if let Some(extra) = extra.as_object() {
            for (name, value) in extra {
                event[name] = value.clone();
            }
        }
        let mut state = self.state.lock().expect("lifecycle callback receipts");
        state.events.push(event);
        if state.failure == stage {
            return Err(AuthError::Api {
                status: 400,
                code: Some("LIFECYCLE_REJECTED".into()),
                message: format!("Application {stage} rejected"),
            });
        }
        Ok(())
    }
}
fn callback_user(user: &UserInfo) -> Value {
    serde_json::to_value(user).expect("application user snapshot serialization")
}
#[async_trait]
impl SendDeleteAccountVerification for Application {
    async fn send(&self, user: &UserInfo, url: &str, token: &str) -> AuthResult<()> {
        self.event(
            "deletion-mail",
            callback_user(user),
            json!({"url":url,"token":token}),
        )
    }
}
#[async_trait]
impl SendVerificationEmail for Application {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.event(
            "verification-mail",
            serde_json::to_value(user)?,
            json!({"url":url,"token":token}),
        )
    }
}
#[async_trait]
impl SendChangeEmailConfirmation for Application {
    async fn send(
        &self,
        user: &UserInfo,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        self.event(
            "confirmation-mail",
            callback_user(user),
            json!({"newEmail":new_email,"url":url,"token":token}),
        )
    }
}
#[async_trait]
impl BeforeDeleteUser for Application {
    async fn before_delete(&self, user: &UserInfo) -> AuthResult<()> {
        self.event("before-delete", callback_user(user), json!({}))?;
        let hold = {
            let mut state = self.state.lock().expect("deletion hook gate");
            let hold = state.hold_next;
            state.hold_next = false;
            if hold {
                state.held = true;
            }
            hold
        };
        if hold {
            self.release.notified().await;
            self.state.lock().expect("deletion hook release").held = false;
        }
        Ok(())
    }
}
#[async_trait]
impl AfterDeleteUser for Application {
    async fn after_delete(&self, user: &UserInfo) -> AuthResult<()> {
        self.event("after-delete", callback_user(user), json!({}))
    }
}
#[async_trait]
impl CookieCacheVersionResolver for Application {
    async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String> {
        self.state
            .lock()
            .expect("lifecycle cache receipts")
            .events
            .push(json!({"stage":"cache","session":context.session(),"user":context.user()}));
        Ok("1".into())
    }
}
#[async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        ScryptHasher.hash(password).await
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        {
            let mut state = self.state.lock().expect("lifecycle hasher receipts");
            state
                .events
                .push(json!({"stage":"password-verify","password":password,"hash":hash}));
            if state.failure == "password-verify" {
                return Err(AuthError::Api {
                    status: 400,
                    code: Some("LIFECYCLE_REJECTED".into()),
                    message: "Application password-verify rejected".into(),
                });
            }
        }
        ScryptHasher.verify(hash, password).await
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    profile: String,
    action: String,
    failure: Option<String>,
    user_id: Option<String>,
    name: Option<String>,
    token: Option<String>,
    created_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
pub(crate) async fn router(base: &AuthConfig, db: DatabaseConnection) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in [
        "default",
        "required",
        "delivery",
        "auto",
        "change",
        "promotion",
        "promotion-no-mail",
        "verification-expired",
        "no-mail",
        "delete",
        "delete-mail",
        "delete-zero",
        "delete-expired",
        "delete-policy",
        "delete-no-freshness",
    ] {
        let app = Arc::new(Application::default());
        let path = format!("/__test/profiles/user-lifecycle-{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.session.fresh_age = Some(Duration::seconds(if name == "delete-no-freshness" {
            0
        } else {
            60
        }));
        if ["auto", "change", "promotion"].contains(&name) {
            config = config.session_cookie_cache(CookieCacheConfig {
                enabled: true,
                max_age: 300.0,
                version: Some(CookieCacheVersion::Resolver(app.clone())),
                ..Default::default()
            });
        }
        config.email_provider = None;
        let before_app = app.clone();
        let after_app = app.clone();
        let mut verification_plugin = EmailVerificationPlugin::new()
            .verification_token_expiry(Duration::seconds(if name == "verification-expired" {
                -1
            } else {
                90
            }))
            .send_on_sign_in(name == "delivery")
            .auto_sign_in_after_verification(name == "auto")
            .before_email_verification(Arc::new(move |user| {
                let app = before_app.clone();
                let user = user.clone();
                Box::pin(async move {
                    app.event(
                        "before-verification",
                        serde_json::to_value(user)?,
                        json!({}),
                    )
                })
            }))
            .after_email_verification(Arc::new(move |user| {
                let app = after_app.clone();
                let user = user.clone();
                Box::pin(async move {
                    app.event("after-verification", serde_json::to_value(user)?, json!({}))
                })
            }));
        if !["default", "required"].contains(&name) {
            verification_plugin = verification_plugin.send_on_sign_up(name == "delivery");
        }
        if !["no-mail", "promotion-no-mail"].contains(&name) {
            verification_plugin = verification_plugin.custom_send_verification_email(app.clone());
        }
        let mail = name.starts_with("delete-")
            && !["delete-policy", "delete-no-freshness"].contains(&name);
        let mut user_plugin = UserManagementPlugin::new()
            .change_email_enabled(true)
            .update_without_verification(name.starts_with("promotion"))
            .delete_user_enabled(true)
            .require_delete_verification(false)
            .delete_token_expires_in(Duration::seconds(match name {
                "delete-zero" => 0,
                "delete-expired" => -1,
                _ => 90,
            }))
            .before_delete(app.clone())
            .after_delete(app.clone());
        if mail {
            user_plugin = user_plugin.send_delete_account_verification(app.clone());
        }
        if name == "change" {
            user_plugin = user_plugin.send_change_email_confirmation(app.clone());
        }
        let policy = EmailPasswordConfig {
            enable_username: false,
            require_email_verification: ["required", "delivery"].contains(&name),
            password_max_length: if name == "delete-policy" { 12 } else { 128 },
            password_hasher: (name == "delete-policy")
                .then(|| app.clone() as Arc<dyn PasswordHasher>),
            ..Default::default()
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, db.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::with_config(policy))
                .plugin(verification_plugin)
                .plugin(SessionManagementPlugin::new())
                .plugin(user_plugin)
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(name.to_owned(), (auth, app));
    }
    Ok(router.route("/__test/user-lifecycle/control",post(move |Json(body):Json<Control>| {
        let profiles = profiles.clone(); let db = db.clone(); async move {
            let result:AuthResult<Value> = async {
                let (auth,app) = profiles.get(&body.profile).ok_or_else(||AuthError::bad_request("Unknown lifecycle profile"))?;
                match body.action.as_str() {
                    "reset" => *app.state.lock().expect("lifecycle reset") = State::default(),
                    "hold" => { let mut state = app.state.lock().expect("deletion hook hold"); state.hold_next = true; state.held = false; },
                    "release" => {}, // Capture the held snapshot before releasing the request below.
                    "ready" => {
                        let ready = async {
                            while !app.state.lock().expect("deletion hook arrival").held { tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
                        };
                        tokio::time::timeout(std::time::Duration::from_secs(3),ready).await.map_err(|_|AuthError::internal("Application deletion hook did not arrive"))?;
                    },
                    "failure" => app.state.lock().expect("lifecycle failure").failure = body.failure.unwrap_or_default(),
                    "rename" => { drop(auth.store().update_user(body.user_id.as_deref().ok_or_else(||AuthError::bad_request("Missing rename"))?,better_auth_core::UpdateUser { name:Some(body.name.ok_or_else(||AuthError::bad_request("Missing rename"))?), ..Default::default() }).await?); },
                    "session-clock" => { _ = session::Entity::update_many().col_expr(session::Column::CreatedAt,Expr::value(body.created_at.ok_or_else(||AuthError::bad_request("Missing session clock"))?)).col_expr(session::Column::ExpiresAt,Expr::value(body.expires_at.unwrap_or(DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z").unwrap().with_timezone(&Utc)))).filter(session::Column::Token.eq(body.token.ok_or_else(||AuthError::bad_request("Missing session clock"))?)).exec(&db).await.map_err(db_error)?; },
                    "state" => {},
                    _ => return Err(AuthError::bad_request("Unknown lifecycle action")),
                }
                let users = user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&db).await.map_err(db_error)?;
                let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&db).await.map_err(db_error)?;
                let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&db).await.map_err(db_error)?;
                let proofs = verification::Entity::find().order_by_asc(verification::Column::CreatedAt).all(&db).await.map_err(db_error)?;
                let accounts = accounts.iter().map(|account| { let mut value = serde_json::to_value(better_auth_core::wire::AccountView::from(account)).unwrap(); value["password"] = json!(account.password); value }).collect::<Vec<_>>();
                let proofs = proofs.iter().map(|proof| {let mut value = serde_json::to_value(better_auth_core::wire::VerificationView::from(proof)).unwrap(); let identifier = value.as_object_mut().unwrap().remove("identifier").unwrap(); let owner = value.as_object_mut().unwrap().remove("value").unwrap(); if let Some(token) = identifier.as_str().and_then(|identifier|identifier.strip_prefix("delete-account-")) {value["identifierPrefix"] = json!("delete-account-");value["token"] = json!(token);value["userId"] = owner;} else {value["identifier"] = identifier;value["value"] = owner;} value}).collect::<Vec<_>>();
                let snapshot = json!({"users":users.iter().map(|user|auth.context().user_view(user)).collect::<Vec<_>>(),"accounts":accounts,"sessions":sessions.iter().map(|session|auth.context().session_view(session)).collect::<Vec<_>>(),"verifications":proofs,"events":app.state.lock().expect("lifecycle state").events});
                // Own every row and receipt before the blocked deletion can resume.
                if body.action == "release" { app.release.notify_one(); }
                Ok(snapshot)
            }.await;
            result.map(Json).map_err(|error|(axum::http::StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"message":error.to_string()}))))
        }
    })))
}
