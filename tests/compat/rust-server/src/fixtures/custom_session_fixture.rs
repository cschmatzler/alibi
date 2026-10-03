//! Real application response transform composed with multiple sessions and JWT.
use crate::session_field_model::ApplicationSchema as TestSchema;
use async_trait::async_trait;
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::jwt::JwtPlugin;
use better_auth::plugins::{
    CustomSessionPlugin, EmailPasswordPlugin, MultiSessionPlugin, SessionTransform,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{AuthContext, AuthRequest};
use better_auth_seaorm::sea_orm::DatabaseConnection;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct TokenHook(Arc<AtomicUsize>);
#[async_trait]
impl better_auth_seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut better_auth::prelude::CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        session.token = Some(format!(
            "custom{:027}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        ));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

struct ApplicationTransform;
#[async_trait]
impl SessionTransform<TestSchema> for ApplicationTransform {
    async fn transform(
        &self,
        session: Value,
        request: &AuthRequest,
        context: &AuthContext<TestSchema>,
    ) -> AuthResult<Value> {
        match request.header("x-custom-session").map(String::as_str) {
            Some("error") => {
                return Err(AuthError::Api {
                    status: 403,
                    code: Some("CUSTOM_SESSION_DENIED".into()),
                    message: "Application session denied".into(),
                });
            }
            Some("ordinary") => return Err(AuthError::internal("Application session failed")),
            Some("null") => return Ok(Value::Null),
            Some("filtered") => {
                return Ok(
                    json!({"userId":session.pointer("/user/id"),"label":session.pointer("/user/name")}),
                );
            }
            _ => {}
        }
        let id = session
            .pointer("/user/id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Missing authenticated owner"))?;
        let user = context
            .database
            .get_user_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Authenticated user is missing"))?;
        let mut session = session;
        let object = session
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Invalid session projection"))?;
        use better_auth::prelude::AuthUser;
        drop(object.insert(
            "application".into(),
            json!({"userId":user.id(),"label":user.name(),"path":request.path()}),
        ));
        Ok(session)
    }
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "custom-session",
        "custom-session-jwt",
        "custom-session-deferred",
        "custom-session-core-error",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        config.session.defer_session_refresh = name.ends_with("-deferred");
        drop(
            config.session.additional_fields.insert(
                "label".into(),
                better_auth::field_policy::FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("custom-public-label")),
            ),
        );
        drop(
            config.session.additional_fields.insert(
                "hidden".into(),
                better_auth::field_policy::FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("custom-server-secret"))
                    .hidden(),
            ),
        );
        if name.ends_with("-core-error") {
            drop(
                config.session.additional_fields.insert(
                    "label".into(),
                    better_auth::field_policy::FieldConfig::new(json!({"type":"string"}))
                        .transform_output(|_| async {
                            Err(AuthError::internal("Configured session projection failed"))
                        }),
                ),
            );
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
                    .hook(TokenHook(counter.clone())),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(CustomSessionPlugin::new(ApplicationTransform).mutate_device_sessions(true))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(MultiSessionPlugin::new());
        let builder = if !name.ends_with("-jwt") && !name.ends_with("-deferred") {
            builder
        } else {
            builder.plugin(JwtPlugin::new())
        };
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
