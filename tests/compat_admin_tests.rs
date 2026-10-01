#![cfg(test)]
//! Compatibility tests for a subset of Admin plugin endpoints (Admin).
//!
//! Endpoints tested:
//! - GET  /admin/get-user
//! - GET  /admin/list-users
//! - POST /admin/create-user
//! - POST /admin/update-user
//! - POST /admin/remove-user
//! - POST /admin/set-user-password
//! - POST /admin/set-role
//! - POST /admin/has-permission
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "admin compatibility tests intentionally use panic-on-failure assertions and direct JSON indexing for endpoint contract checks"
)]

mod compat;

#[cfg(test)]
#[path = "compat_admin_tests/tests.rs"]
mod tests;

use better_auth::prelude::AuthUser;
use compat::helpers::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Helper: create an admin user and return the admin token
// ---------------------------------------------------------------------------

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn setup_admin(auth: &better_auth::BetterAuth<TestSchema>) -> String {
    use better_auth::prelude::UpdateUser;

    // Sign up a regular user first
    let (token, _) = signup_user(auth, "admin@test.com", "password123", "Admin User").await;

    // Promote the user to admin using the database directly
    let user = auth
        .store()
        .get_user_by_email("admin@test.com")
        .await
        .unwrap()
        .unwrap();

    let update = UpdateUser {
        role: Some("admin".to_owned()),
        ..Default::default()
    };
    drop(auth.store().update_user(&user.id(), update).await.unwrap());

    token
}
