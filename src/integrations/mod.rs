//! Framework integrations.

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "poem")]
pub mod poem;

#[cfg(any(feature = "axum", feature = "poem"))]
mod dispatch;
