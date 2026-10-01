#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![cfg(feature = "seaorm2")]
#![expect(
    clippy::indexing_slicing,
    reason = "Assert successful public-handler SQLite setup and independently specified JSON/model events"
)]
//! Application storage and native hook contracts; the SDK owns built-in wire parity.
#[path = "../compat-tests/rust-server/src/session_field_model.rs"]
mod application_model;

#[cfg(test)]
#[path = "session_fields_tests/tests.rs"]
mod tests;

use application_model::ApplicationSchema;
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
use better_auth_seaorm::{Database, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct ApplicationHook;

#[async_trait]
impl SeaOrmHooks<ApplicationSchema> for ApplicationHook {
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
