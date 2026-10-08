//! Application configuration with concrete session columns and real callbacks.
use crate::session_field_model::{ApplicationSchema, application_session};
use alibi::__private_core::utils::json::JsValue;
use alibi::field_policy::{FieldConfig, FieldValues};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    AccountManagementPlugin, AdminPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
    OAuthPlugin, OpenApiPlugin, OrganizationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, UserManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement};
use alibi_seaorm::store::entities::user;
use alibi_seaorm::{DatabaseConnection, DatabaseHooks, HookControl};
use axum::{Json, Router, extract::Query, routing::get};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

struct Callbacks;
#[async_trait::async_trait]
impl DatabaseHooks<ApplicationSchema, crate::backend::Backend> for Callbacks {
    async fn before_update_session(
        &self,
        token: &str,
        fields: &mut FieldValues,
        ctx: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        if fields.get("label").and_then(JsValue::as_str) == Some("delete-before") {
            _ = crate::backend::hook_execute(
                ctx.db,
                "DELETE FROM sessions WHERE token=?",
                vec![token.to_owned()],
            )
            .await?;
        }
        if fields.get("label").and_then(JsValue::as_str) == Some("cancel-before") {
            return Ok(HookControl::Cancel);
        }
        if fields.get("label").and_then(JsValue::as_str) == Some("native-hook") {
            _ = fields.insert("label".into(), JsValue::String("model-override".into()));
        }
        if fields.get("label").and_then(JsValue::as_str) == Some("restore-undefined") {
            _ = fields.insert("transformed".into(), JsValue::String("hook-current".into()));
        }
        if fields.get("transformed").and_then(JsValue::as_str) == Some("stage:hook-input") {
            _ = fields.insert("transformed".into(), JsValue::String("hook-current".into()));
        }
        Ok(HookControl::Continue)
    }
}
#[derive(Deserialize)]
struct StateQuery {
    email: String,
}
pub(crate) async fn router(config: &AuthConfig, db: DatabaseConnection) -> AuthResult<Router> {
    for sql in [
        "ALTER TABLE sessions ADD COLUMN label TEXT",
        "ALTER TABLE sessions ADD COLUMN hidden TEXT",
        "ALTER TABLE sessions ADD COLUMN server_only TEXT",
        "ALTER TABLE sessions ADD COLUMN transformed TEXT",
        "ALTER TABLE sessions ADD COLUMN validated TEXT",
        "ALTER TABLE sessions ADD COLUMN callback TEXT",
        "ALTER TABLE sessions ADD COLUMN number REAL",
        "ALTER TABLE sessions ADD COLUMN payload JSON NOT NULL DEFAULT '{}'",
    ] {
        _ = db
            .execute_raw(Statement::from_string(db.get_database_backend(), sql))
            .await
            .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
    }
    let mut router = Router::new();
    for name in [
        "session-fields",
        "session-fields-plugins",
        "session-fields-secondary",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name == "session-fields-secondary" {
            config.session.secondary_storage =
                Some(Arc::new(alibi_core::store::MemoryCacheAdapter::new()));
        }
        let fields = &mut config.session.additional_fields;
        _ = fields.insert(
            "label".into(),
            FieldConfig::new(json!({"type":"string"})).default_value(json!("initial")),
        );
        _ = fields.insert(
            "hidden".into(),
            FieldConfig::new(json!({"type":"string"}))
                .hidden()
                .default_value(json!("server-secret")),
        );
        _ = fields.insert(
            "serverOnly".into(),
            FieldConfig::new(json!({"type":"string"}))
                .read_only()
                .default_value(json!("locked")),
        );
        _ = fields.insert(
            "callback".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_callback(|| JsValue::String("callback-created".into())),
        );
        _ = fields.insert(
            "payload".into(),
            FieldConfig::new(json!({"type":"json"})).default_value(json!({"initial":true})),
        );
        _ = fields.insert("number".into(), FieldConfig::new(json!({"type":"number"})));
        _ = fields.insert(
            "transformed".into(),
            FieldConfig::new(json!({"type":"string"})).transform(|value| {
                match value.and_then(JsValue::as_str) {
                    None => Ok(Some(JsValue::String("generated-without-default".into()))),
                    Some("stage:throw-at-binding") => {
                        Err(alibi::AuthError::internal("configured transform failed"))
                    }
                    Some("omit" | "stage:omit-at-binding") => Ok(None),
                    Some(value) => Ok(Some(JsValue::String(format!("stage:{value}")))),
                }
            }),
        );
        _ = fields.insert(
            "validated".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!(""))
                .validate(|value| match value {
                    JsValue::String(value) if !value.trim().is_empty() => {
                        Ok(JsValue::String(value.trim().to_owned()))
                    }
                    JsValue::Number(value) if value.is_infinite() => Ok(JsValue::String(
                        if value.is_sign_negative() {
                            "-Infinity"
                        } else {
                            "Infinity"
                        }
                        .into(),
                    )),
                    JsValue::Number(value) if *value == 0.0 && value.is_sign_negative() => {
                        Ok(JsValue::String("-0".into()))
                    }
                    _ => Err("configured validation rejected the value".into()),
                })
                .transform(|value| {
                    Ok(Some(JsValue::String(format!(
                        "stored:{}",
                        value.and_then(JsValue::as_str).unwrap_or_default()
                    ))))
                }),
        );
        if name.ends_with("plugins") {
            for field in ["activeOrganizationId", "activeTeamId", "impersonatedBy"] {
                _ = fields.insert(field.into(), FieldConfig::new(json!({"type":"string"})));
            }
            let mut conflict = FieldConfig::new(json!({"type":"string"}))
                .hidden()
                .default_value(json!("configured-default-org"))
                .transform(|value| {
                    Ok(Some(JsValue::String(format!(
                        "adapter:{}",
                        value.and_then(JsValue::as_str).unwrap_or("undefined")
                    ))))
                });
            conflict.required = true;
            _ = fields.insert("activeOrganizationId".into(), conflict);
        }
        if !name.ends_with("plugins") {
            _ = fields.insert(
                "activeOrganizationId".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("declared-without-plugin")),
            );
        }
        let mut builder = AuthBuilder::<ApplicationSchema>::new(config.clone())
            .store(crate::backend::store::<ApplicationSchema>(config, db.clone()).hook(Callbacks))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(OAuthPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true),
            )
            .plugin(OpenApiPlugin::new());
        if name.ends_with("plugins") {
            builder = builder
                .plugin(AdminPlugin::new())
                .plugin(OrganizationPlugin::with_config(
                    alibi::plugins::OrganizationConfig {
                        teams: alibi::plugins::organization::TeamsConfig {
                            enabled: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                ));
        }
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route("/__test/session-field-state",get(move|Query(query):Query<StateQuery>|{
        let db=db.clone();async move {
            let user=user::Entity::find().filter(user::Column::Email.eq(query.email)).one(&db).await.unwrap();
            let rows=if let Some(user)=user {crate::backend::rows::<application_session::Model>(&db,"SELECT * FROM sessions WHERE user_id = ?",vec![user.id]).await.unwrap()}else{Vec::new()};
            Json(Value::Array(rows.into_iter().map(|row|json!({"id":row.id,"token":row.token,"userId":row.user_id,"updatedAt":row.updated_at,"label":row.label,"hidden":row.hidden,"serverOnly":row.server_only,"transformed":row.transformed,"validated":row.validated,"callback":row.callback,"number":row.number,"payload":row.payload,"activeOrganizationId":row.active_organization_id,"activeTeamId":row.active_team_id,"impersonatedBy":row.impersonated_by})).collect()))
        }
    })))
}
