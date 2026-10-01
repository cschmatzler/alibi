#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "surface tests intentionally use panic-on-failure assertions and direct JSON indexing for API shape checks"
)]

#[cfg(test)]
#[path = "rust_surface_auth_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::prelude::{AuthRequest, AuthResponse, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct RouteTestPlugin;

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for RouteTestPlugin {
    fn name(&self) -> &'static str {
        "route-test"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/route-test", "route_test"),
            AuthRoute::post("/route-test", "route_test_post"),
        ]
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .expect("sqlite test migrations should run");
    database
}

async fn build_auth_with_route_plugin() -> BetterAuth<TestSchema> {
    let config = test_config();
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);
    AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(RouteTestPlugin)
        .build()
        .await
        .expect("build should succeed")
}
