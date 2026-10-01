#![cfg(test)]
//! Compatibility tests for admin admin stateful flows.
//!
//! Focused on the shared banned-user session gate and admin stateful semantics
//! that cross route boundaries.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "compat contract tests use direct assertions and JSON indexing for endpoint checks"
)]

mod compat;

#[cfg(test)]
#[path = "compat_admin_stateful_tests/tests.rs"]
mod tests;

use better_auth::prelude::{AuthUser, UpdateUser};
use chrono::{Duration, Utc};
use compat::helpers::*;
use serde_json::json;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn setup_admin(auth: &better_auth::BetterAuth<TestSchema>) -> String {
    let (token, _) = signup_user(auth, "admin-stateful@test.com", "password123", "Admin").await;

    let user = auth
        .store()
        .get_user_by_email("admin-stateful@test.com")
        .await
        .unwrap()
        .unwrap();

    drop(
        auth.store()
            .update_user(
                &user.id(),
                UpdateUser {
                    role: Some("admin".to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
    );

    token
}
