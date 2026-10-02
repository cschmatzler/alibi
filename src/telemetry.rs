//! Explicit application-owned telemetry. No endpoint, environment discovery or
//! process fingerprinting is enabled by the library. Install a sink on the auth
//! builder to opt in; the application owns its transport and retention policy.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// An initialization or application-defined event delivered to the installed sink.
/// Application payloads are supplied by trusted host code, never HTTP requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Value,
}

impl TelemetryEvent {
    #[must_use]
    pub fn new(event_type: impl Into<String>, payload: Value) -> Self {
        Self {
            event_type: event_type.into(),
            payload,
        }
    }
}

/// Application-owned asynchronous event delivery.
#[async_trait]
pub trait TelemetrySink: Send + Sync {
    /// Deliver an event. Failures are nonfatal and logged without the payload or
    /// sink error, which may contain credentials or transport details.
    ///
    /// # Errors
    /// Returns the sink's delivery failure.
    async fn track(&self, event: TelemetryEvent) -> crate::AuthResult<()>;
}

/// Opt-in telemetry configuration. Default construction disables collection.
#[derive(Clone, Default)]
pub struct TelemetryConfig {
    enabled: bool,
    sink: Option<Arc<dyn TelemetrySink>>,
}

impl std::fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryConfig")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl TelemetryConfig {
    /// Install an application sink and enable delivery, including initialization.
    #[must_use]
    pub fn new(sink: impl TelemetrySink + 'static) -> Self {
        Self {
            enabled: true,
            sink: Some(Arc::new(sink)),
        }
    }

    /// Enable or disable collection for this auth instance.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled && self.sink.is_some()
    }

    pub(crate) async fn publish(&self, event: TelemetryEvent) {
        if self.enabled
            && let Some(sink) = &self.sink
            && sink.track(event).await.is_err()
        {
            tracing::warn!("Authentication telemetry delivery failed");
        }
    }
}
