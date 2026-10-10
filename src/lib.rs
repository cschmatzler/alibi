//! # Alibi
//!
//! Authentication for Rust, compatible with Better Auth's TypeScript client.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use alibi::{AuthConfig, AuthSchema, Alibi};
//! use alibi::plugins::EmailPasswordPlugin;
//! use alibi::seaorm::{Database, SeaOrmStore};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key-that-is-at-least-32-chars");
//!     let database = Database::connect("sqlite::memory:").await?;
//!     let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);
//!
//!     let auth = Alibi::<AppAuthSchema>::new(config)
//!         .store(store)
//!         .plugin(EmailPasswordPlugin::new())
//!         .build()
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

extern crate self as alibi;

mod runtime;

pub mod config;
pub mod email;
pub mod error;
pub mod hooks;
pub mod integrations;
pub mod middleware;
pub mod plugin;
pub mod plugins;
pub mod prelude;
pub mod schema;
#[cfg(feature = "seaorm")]
pub mod seaorm;
pub mod session;
#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
pub mod sqlx;
pub mod store;
pub mod telemetry;
pub mod wire;

#[doc(hidden)]
pub use alibi_core as __private_core;
pub use alibi_core::*;
pub use runtime::{Alibi, AuthBuilder};
