#![cfg(test)]
//! Compatibility tests that compare our implementation against the
//! generated upstream `OpenAPI` contract from the pinned Better Auth package.
//!
//! These tests ensure route coverage and response shape alignment with
//! the canonical Better-Auth TypeScript implementation.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "compatibility tests intentionally use panic-on-failure assertions and direct JSON indexing for contract checks"
)]

#[path = "support/compat/mod.rs"]
mod compat;

#[cfg(test)]
#[path = "compatibility_tests/tests.rs"]
mod tests;

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth,
    plugins::EmailPasswordPlugin,
    prelude::{AuthRequest, HttpMethod},
};
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use compat::helpers::html_text_content;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the generated upstream `OpenAPI` and return a map of path → set of HTTP methods.
fn load_reference_spec() -> BTreeMap<String, HashSet<String>> {
    let spec =
        compat::schema::load_openapi_spec_with_profile(compat::schema::OpenApiProfile::AllIn);
    let paths = spec.paths.as_ref().expect("generated spec must have paths");

    let mut result = BTreeMap::new();
    for (path, methods) in paths {
        let mut method_set = HashSet::new();
        if methods.get.is_some() {
            let _previous_get = method_set.insert("get".to_owned());
        }
        if methods.post.is_some() {
            let _previous_post = method_set.insert("post".to_owned());
        }
        if methods.put.is_some() {
            let _previous_put = method_set.insert("put".to_owned());
        }
        if methods.delete.is_some() {
            let _previous_delete = method_set.insert("delete".to_owned());
        }
        if methods.patch.is_some() {
            let _previous_patch = method_set.insert("patch".to_owned());
        }
        if methods.options.is_some() {
            let _previous_options = method_set.insert("options".to_owned());
        }
        if methods.head.is_some() {
            let _previous_head = method_set.insert("head".to_owned());
        }
        drop(result.insert(path.clone(), method_set));
    }
    result
}

fn reference_profile_reference_surface(
    reference: &BTreeMap<String, HashSet<String>>,
) -> BTreeMap<String, HashSet<String>> {
    let mut surface: BTreeMap<String, HashSet<String>> = [
        "/ok",
        "/error",
        "/sign-up/email",
        "/sign-in/email",
        "/get-session",
        "/sign-out",
        "/list-sessions",
        "/revoke-session",
        "/revoke-sessions",
        "/revoke-other-sessions",
        "/refresh-token",
        "/get-access-token",
        "/request-password-reset",
        "/reset-password",
        "/reset-password/{token}",
        "/change-password",
        "/verify-password",
        "/update-user",
        "/delete-user",
        "/delete-user/callback",
        "/change-email",
        "/send-verification-email",
        "/verify-email",
        "/sign-in/social",
        "/link-social",
        "/list-accounts",
        "/unlink-account",
        "/account-info",
        "/device/code",
        "/device/token",
        "/device",
        "/device/approve",
        "/device/deny",
        "/api-key/create",
        "/api-key/get",
        "/api-key/list",
        "/api-key/update",
        "/api-key/delete",
    ]
    .into_iter()
    .map(|path| {
        (
            path.to_owned(),
            reference
                .get(path)
                .unwrap_or_else(|| panic!("reference spec missing reference-profile path {path}"))
                .clone(),
        )
    })
    .collect();

    // The pinned TS runtime exposes `/callback/{provider}` publicly, but the
    // generated OpenAPI profile omits it. Treat it as a reference-profile
    // runtime route and assert it explicitly until the structural profile
    // catches up.
    drop(surface.insert(
        "/callback/{provider}".to_owned(),
        HashSet::from(["get".to_owned(), "post".to_owned()]),
    ));
    // The pinned TS runtime exposes `/sign-in/username` and
    // `/is-username-available` publicly when the username plugin is enabled,
    // but the generated OpenAPI profile omits them.
    drop(surface.insert(
        "/sign-in/username".to_owned(),
        HashSet::from(["post".to_owned()]),
    ));
    drop(surface.insert(
        "/is-username-available".to_owned(),
        HashSet::from(["post".to_owned()]),
    ));

    surface
}

/// Create a test auth instance with all currently implemented plugins.
async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    database
}

async fn create_full_auth() -> BetterAuth<TestSchema> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);

    AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(better_auth::plugins::SessionManagementPlugin::new())
        .plugin(better_auth::plugins::PasswordManagementPlugin::new())
        .plugin(better_auth::plugins::EmailVerificationPlugin::new())
        .plugin(
            better_auth::plugins::UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(better_auth::plugins::AccountManagementPlugin::new())
        .plugin(better_auth::plugins::OAuthPlugin::new())
        .plugin(better_auth::plugins::DeviceAuthorizationPlugin::new())
        .plugin(better_auth::plugins::TwoFactorPlugin::new())
        .plugin(better_auth::plugins::ApiKeyPlugin::builder().build())
        .build()
        .await
        .expect("Failed to create test auth instance")
}

/// Collect all routes our implementation exposes (core + plugin).
fn collect_implemented_routes(auth: &BetterAuth<TestSchema>) -> BTreeMap<String, HashSet<String>> {
    let mut routes: BTreeMap<String, HashSet<String>> = BTreeMap::new();

    // Core routes (from handle_core_request)
    let core = vec![("/ok", "get"), ("/error", "get"), ("/update-user", "post")];
    for (path, method) in core {
        let _ignored_to_owned = routes
            .entry(path.to_owned())
            .or_default()
            .insert(method.to_owned());
    }

    // Plugin routes
    for plugin in auth.plugins() {
        for route in plugin.routes() {
            let method_str = match route.method {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Delete => "delete",
                HttpMethod::Patch => "patch",
                HttpMethod::Options => "options",
                HttpMethod::Head => "head",
            };
            let _ignored_to_owned_2 = routes
                .entry(route.path.clone())
                .or_default()
                .insert(method_str.to_owned());
        }
    }

    routes
}

// ---------------------------------------------------------------------------
// Contract Tests — validate response shapes
// ---------------------------------------------------------------------------

/// Helper to send a request and parse the JSON response body.
async fn send_json_request(
    auth: &BetterAuth<TestSchema>,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = AuthRequest::new(method, path);
    if let Some(b) = body {
        req.body = Some(b.to_string().into_bytes());
        drop(
            req.headers
                .insert("content-type".to_owned(), "application/json".to_owned()),
        );
    }
    let resp = auth
        .handle_request(req)
        .await
        .expect("Request should not panic");
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}
