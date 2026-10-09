//! Framework integrations.

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(any(feature = "axum", feature = "poem"))]
mod dispatch;
#[cfg(feature = "poem")]
pub mod poem;
#[cfg(any(feature = "axum", feature = "poem"))]
mod shared;

#[cfg(any(feature = "axum", feature = "poem"))]
pub use shared::{CurrentSession, OptionalSession};
