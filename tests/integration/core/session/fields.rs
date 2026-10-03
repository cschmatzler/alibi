#![expect(
    clippy::indexing_slicing,
    reason = "Assert successful public-handler SQLite setup and independently specified JSON/model events"
)]
//! Application storage and native hook contracts; the SDK owns built-in wire parity.
use super::application_model::ApplicationSchema;
use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, OpenApiPlugin, OrganizationPlugin, SessionManagementPlugin,
};
use better_auth::{
    AuthBuilder, AuthConfig,
    field_policy::{FieldConfig, FieldValues},
};
use better_auth_core::{AuthRequest, AuthResult, CreateSession, HttpMethod, utils::json::JsValue};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Statement};
use better_auth_seaorm::store::__private_test_support::migrator::run_migrations;
use better_auth_seaorm::{
    Database, DatabaseHooks, HookControl, SeaOrm, SeaOrmHookContext, SeaOrmStore,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct ApplicationHook;

#[async_trait]
impl DatabaseHooks<ApplicationSchema, SeaOrm> for ApplicationHook {
    async fn before_create_session(
        &self,
        data: &mut CreateSession,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        assert_eq!(
            data.additional_fields
                .get("hidden")
                .and_then(JsValue::as_str),
            Some("server-secret")
        );
        data.active_organization_id = Some("native-organization".into());
        Ok(HookControl::Continue)
    }
    async fn before_update_session(
        &self,
        token: &str,
        fields: &mut FieldValues,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if fields.get("label").and_then(JsValue::as_str) == Some("delete-before") {
            _ = ctx
                .db
                .execute_raw(Statement::from_sql_and_values(
                    ctx.db.get_database_backend(),
                    "DELETE FROM sessions WHERE token=?",
                    [token.into()],
                ))
                .await
                .map_err(|error| better_auth_core::AuthError::internal(error.to_string()))?;
        }
        Ok(HookControl::Continue)
    }
}

fn request(path: &str, body: Value, cookie: Option<&str>) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(serde_json::to_vec(&body).unwrap());
    drop(body);
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(
        req.headers
            .insert("origin".into(), "http://localhost:37821".into()),
    );
    if let Some(cookie) = cookie {
        drop(req.headers.insert("cookie".into(), cookie.into()));
    }
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn real_custom_session_columns_preserve_affinity_json_defaults_owner_and_model_hook_overrides()
     {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        run_migrations(&db).await.unwrap();
        for sql in [
            "ALTER TABLE sessions ADD COLUMN label TEXT",
            "ALTER TABLE sessions ADD COLUMN hidden TEXT",
            "ALTER TABLE sessions ADD COLUMN number REAL",
            "ALTER TABLE sessions ADD COLUMN server_only TEXT",
            "ALTER TABLE sessions ADD COLUMN transformed TEXT",
            "ALTER TABLE sessions ADD COLUMN validated TEXT",
            "ALTER TABLE sessions ADD COLUMN callback TEXT",
            "ALTER TABLE sessions ADD COLUMN payload JSON NOT NULL DEFAULT '{}'",
            "CREATE TABLE session_model_events (phase TEXT, label TEXT, is_insert BOOLEAN)",
        ] {
            _ = db
                .execute_raw(Statement::from_string(db.get_database_backend(), sql))
                .await
                .unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::clone(&calls);
        let mut config = AuthConfig::new("session-fields-native-secret-at-least-32")
            .base_url("http://localhost:37821");
        drop(config.session.additional_fields.insert(
            "label".into(),
            FieldConfig::new(json!({"type":"string"})).default_callback(move || {
                _ = captured.fetch_add(1, Ordering::SeqCst);
                JsValue::String("configured-default".into())
            }),
        ));
        drop(
            config.session.additional_fields.insert(
                "hidden".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("server-secret"))
                    .hidden()
                    .read_only(),
            ),
        );
        drop(
            config
                .session
                .additional_fields
                .insert("number".into(), FieldConfig::new(json!({"type":"number"}))),
        );
        drop(config.session.additional_fields.insert(
            "payload".into(),
            FieldConfig::new(json!({"type":"json"})).default_value(json!({"initial":true})),
        ));
        drop(
            config.session.additional_fields.insert(
                "activeOrganizationId".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("must-not-overwrite-native-hook"))
                    .transform(|value| {
                        Ok(Some(JsValue::String(format!(
                            "stored:{}",
                            value.and_then(JsValue::as_str).unwrap_or("undefined")
                        ))))
                    }),
            ),
        );
        let auth = AuthBuilder::<ApplicationSchema>::new(config.clone())
            .store(SeaOrmStore::<ApplicationSchema>::new(config, db.clone()).hook(ApplicationHook))
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::new())
            .plugin(OpenApiPlugin::new())
            .build()
            .await
            .unwrap();
        let signup = auth
            .handle_request(request(
                "/api/auth/sign-up/email",
                json!({"name":"App","email":"app-session@example.com","password":"password123"}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(signup.status, 200);
        let body: Value = serde_json::from_slice(&signup.body).unwrap();
        let token = body["token"].as_str().unwrap();
        let cookie = format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(token, &auth.config().secret)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let documentation = AuthRequest::new(HttpMethod::Get, "/api/auth/open-api/generate-schema");
        let document = auth.handle_request(documentation).await.unwrap();
        assert_eq!(document.status, 200);
        let document: Value = serde_json::from_slice(&document.body).unwrap();
        assert_eq!(
            document["components"]["schemas"]["Session"]["properties"]["label"],
            json!({"type":"string"})
        );
        // Public document generation must never invoke a stateful default callback.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let initial = auth.store().get_session(token).await.unwrap().unwrap();
        assert_eq!(initial.label.as_deref(), Some("configured-default"));
        assert_eq!(initial.hidden.as_deref(), Some("server-secret"));
        assert_eq!(
            initial.active_organization_id.as_deref(),
            Some("stored:native-organization")
        );
        assert_eq!(&*initial.payload, &json!({"initial":true}));
        let owner = initial.user_id.clone();
        _ = db
            .execute_raw(Statement::from_sql_and_values(
                db.get_database_backend(),
                "UPDATE sessions SET validated=? WHERE token=?",
                ["unregistered-storage-secret".into(), token.into()],
            ))
            .await
            .unwrap();
        let manual_context = better_auth_core::AuthContext::<ApplicationSchema>::new(
            Arc::new(auth.config().clone()),
            Arc::clone(auth.store()),
        );
        let stored = auth.store().get_session(token).await.unwrap().unwrap();
        let projection = serde_json::to_value(manual_context.session_view(&stored)).unwrap();
        assert!(
            projection.get("validated").is_none(),
            "undeclared physical sentinel must stay private in manually constructed contexts"
        );
        assert!(projection.get("hidden").is_none());
        assert_eq!(projection["label"], "configured-default");
        assert_eq!(
            projection["activeOrganizationId"],
            "stored:native-organization"
        );
        for (raw, expected) in [
            ("1e20", "1.0e+20"),
            ("1e-20", "1.0e-20"),
            ("1e999", "Inf"),
            ("-0", "0.0"),
        ] {
            let mut req = request("/api/auth/update-session", json!({}), Some(&cookie));
            req.body = Some(
                format!("{{\"label\":{raw},\"token\":\"wrong-token\",\"userId\":\"other-user\"}}")
                    .into_bytes(),
            );
            let response = auth.handle_request(req).await.unwrap();
            assert_eq!(response.status, 200);
            let updated: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(updated["session"]["label"], expected);
            assert_eq!(updated["session"]["token"], token);
            assert_eq!(updated["session"]["userId"], owner);
            assert!(updated["session"].get("hidden").is_none());
            assert!(
                updated["session"].get("validated").is_none(),
                "unregistered SQL columns are not output fields"
            );
            let stored_2 = auth.store().get_session(token).await.unwrap().unwrap();
            assert_eq!(stored_2.label.as_deref(), Some(expected));
            assert_eq!(stored_2.hidden, initial.hidden);
            assert_eq!(
                better_auth_core::AuthSession::additional_fields(&stored_2).get("validated"),
                Some(&json!("unregistered-storage-secret"))
            );
        }
        let payload =
            json!({"$serde_json::private::Number":"literal","nested":{"empty":{}},"list":[1,2]});
        let response = auth
            .handle_request(request(
                "/api/auth/update-session",
                json!({"label":"native-hook","payload":payload}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["session"]["label"], "model-override");
        assert_eq!(value["session"]["payload"], payload);
        assert_eq!(
            &*auth
                .store()
                .get_session(token)
                .await
                .unwrap()
                .unwrap()
                .payload,
            &payload
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "update must not evaluate creation defaults"
        );
        let rows = db
            .query_all_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT phase,label,is_insert FROM session_model_events ORDER BY rowid",
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 12);
        assert_eq!(
            rows[10].try_get::<String>("", "label").unwrap(),
            "native-hook"
        );
        assert_eq!(
            rows[11].try_get::<String>("", "label").unwrap(),
            "model-override"
        );
        let failed = auth
            .handle_request(request(
                "/api/auth/update-session",
                json!({"label":"delete-before"}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(failed.status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&failed.body).unwrap()["code"],
            "FAILED_TO_GET_SESSION"
        );
        assert!(failed.headers.get_all("set-cookie").any(|candidate| {
            candidate.contains("session_token=") && candidate.contains("Max-Age=0")
        }));
        assert!(auth.store().get_session(token).await.unwrap().is_none());
    }
}
