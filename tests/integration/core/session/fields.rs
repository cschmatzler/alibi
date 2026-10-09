#![expect(
    clippy::indexing_slicing,
    reason = "Assert successful public-handler SQLite setup and independently specified JSON/model events"
)]
//! Application storage and native hook contracts; the SDK owns built-in wire parity.
use super::application_model::ApplicationSchema;
use alibi::plugins::{
    EmailPasswordPlugin, OpenApiPlugin, OrganizationPlugin, SessionManagementPlugin,
};
use alibi::seaorm::sea_orm::{ConnectionTrait, Statement};
use alibi::seaorm::store::__private_test_support::migrator::run_migrations;
use alibi::seaorm::{
    Database, DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore,
};
use alibi::{
    AuthBuilder, AuthConfig,
    field_policy::{FieldConfig, FieldValues},
};
use alibi::{AuthRequest, AuthResult, CreateSession, HttpMethod, utils::json::JsValue};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct ApplicationHook;

#[async_trait]
impl DatabaseHooks<ApplicationSchema, SeaOrmBackend> for ApplicationHook {
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
                .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
        }
        Ok(HookControl::Continue)
    }
}

struct InitialSessionFieldsHook;

#[async_trait]
impl DatabaseHooks<ApplicationSchema, SeaOrmBackend> for InitialSessionFieldsHook {
    async fn before_create_session(
        &self,
        data: &mut CreateSession,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        assert_eq!(
            data.active_organization_id.as_deref(),
            Some("guest-organization")
        );
        assert_eq!(data.active_team_id.as_deref(), Some("guest-team"));
        assert_eq!(
            data.additional_fields
                .get("label")
                .and_then(JsValue::as_str),
            Some("guest-link")
        );
        // Hook transformations must also reach the initial insert and returned row.
        drop(
            data.additional_fields
                .insert("label".into(), JsValue::String("hook-label".into())),
        );
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &<ApplicationSchema as alibi::AuthSchema>::Session,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert_eq!(
            session.active_organization_id.as_deref(),
            Some("guest-organization")
        );
        assert_eq!(session.active_team_id.as_deref(), Some("guest-team"));
        assert_eq!(session.label.as_deref(), Some("hook-label"));
        Ok(())
    }
}

async fn session_fields_database() -> alibi::seaorm::DatabaseConnection {
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
    db
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
    async fn public_issuance_inserts_explicit_session_fields_before_creation_hooks() {
        use alibi::CreateUser;
        use alibi::prelude::{AuthSession, AuthUser};
        use alibi::session::{
            SessionOverrides, issue_user_session_with_fields, issue_user_session_with_fields_record,
        };

        let db = session_fields_database().await;
        for sql in [
            "CREATE TABLE initial_session_fields (organization TEXT, team TEXT, label TEXT)",
            "CREATE TRIGGER capture_initial_session AFTER INSERT ON sessions BEGIN INSERT INTO initial_session_fields VALUES (NEW.active_organization_id, NEW.active_team_id, NEW.label); END",
            "CREATE TRIGGER reject_session_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'issuance must use one insert'); END",
        ] {
            _ = db
                .execute_raw(Statement::from_string(db.get_database_backend(), sql))
                .await
                .unwrap();
        }
        let mut config = AuthConfig::new("initial-session-fields-secret-at-least-32");
        drop(
            config
                .session
                .additional_fields
                .insert("label".into(), FieldConfig::new(json!({"type":"string"}))),
        );
        let auth = AuthBuilder::<ApplicationSchema>::new(config.clone())
            .store(
                SeaOrmStore::<ApplicationSchema>::new(config, db.clone())
                    .hook(InitialSessionFieldsHook),
            )
            .build()
            .await
            .unwrap();
        let user = auth
            .store()
            .create_user(CreateUser::new().with_email("guest@session.fixture"))
            .await
            .unwrap();
        let fields = SessionOverrides {
            active_organization_id: Some("guest-organization".into()),
            active_team_id: Some("guest-team".into()),
            additional_fields: [("label".into(), JsValue::String("guest-link".into()))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        // Exercise both public return shapes against the same insert contract.
        let stored = issue_user_session_with_fields(
            auth.context(),
            user.id().as_ref(),
            Some("192.0.2.1".into()),
            Some("guest-agent".into()),
            fields.clone(),
        )
        .await
        .unwrap();
        let retained = issue_user_session_with_fields_record(
            auth.context(),
            user.id().as_ref(),
            None,
            None,
            fields,
        )
        .await
        .unwrap();
        assert_eq!(stored.session.ip_address(), Some("192.0.2.1"));
        assert_eq!(stored.session.user_agent(), Some("guest-agent"));
        for session in [&stored.session, retained.session.stored()] {
            assert_eq!(session.active_organization_id(), Some("guest-organization"));
            assert_eq!(session.active_team_id(), Some("guest-team"));
            assert_eq!(session.label.as_deref(), Some("hook-label"));
            let persisted = auth
                .store()
                .get_session(session.token())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(persisted, *session);
        }
        // Extension fields cannot replace issuer-owned identity or lifetime.
        for name in [
            "id",
            "token",
            "userId",
            "user_id",
            "expiresAt",
            "expires_at",
            "createdAt",
            "created_at",
            "updatedAt",
            "updated_at",
        ] {
            let forbidden = SessionOverrides {
                additional_fields: [(name.into(), JsValue::String("forbidden".into()))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            let error = issue_user_session_with_fields(
                auth.context(),
                user.id().as_ref(),
                None,
                None,
                forbidden,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                alibi::session::SessionIssueError::Auth(alibi::AuthError::BadRequest(_))
            ));
        }
        let inserted = db
            .query_all_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT organization, team, label FROM initial_session_fields",
            ))
            .await
            .unwrap();
        assert_eq!(inserted.len(), 2);
        for row in inserted {
            assert_eq!(
                row.try_get::<String>("", "organization").unwrap(),
                "guest-organization"
            );
            assert_eq!(row.try_get::<String>("", "team").unwrap(), "guest-team");
            assert_eq!(row.try_get::<String>("", "label").unwrap(), "hook-label");
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn real_custom_session_columns_preserve_affinity_json_defaults_owner_and_model_hook_overrides()
     {
        let db = session_fields_database().await;
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
            alibi::utils::cookie_utils::sign_cookie_value(token, &auth.config().secret)
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
        let manual_context = alibi::AuthContext::<ApplicationSchema>::new(
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
                alibi::AuthSession::additional_fields(&stored_2).get("validated"),
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
