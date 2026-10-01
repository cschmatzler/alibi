#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Phone database hooks must apply through every trusted store facade and remain local to one auth instance.

#[cfg(test)]
#[path = "phone_number_integration_tests/tests.rs"]
mod tests;

use std::sync::Arc;

use better_auth::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin};

use better_auth::{AuthBuilder, AuthConfig};

use better_auth_core::{AuthAccount, AuthSession, AuthUser, CreateUser, UpdateUser};

use better_auth_seaorm::{Database, SeaOrmStore};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
