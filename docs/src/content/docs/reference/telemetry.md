---
title: "Telemetry"
description: "Opt-in, application-owned authentication telemetry."
---

Telemetry is disabled by default. To enable it, provide a sink and register it on the builder:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::sqlx::SqlxStore;
use better_auth::telemetry::{TelemetryConfig, TelemetryEvent, TelemetrySink};
use better_auth::{AuthConfig, AuthResult, BetterAuth};

struct EventLog;

#[async_trait]
impl TelemetrySink for EventLog {
    async fn track(&self, event: TelemetryEvent) -> AuthResult<()> {
        eprintln!("Auth event: {}", event.event_type);
        Ok(())
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .telemetry(TelemetryConfig::new(EventLog))
        .build()
        .await
}
```

Initialization sends one event containing the library version, platform, and installed plugins. Your sink owns delivery; errors produce a warning and do not fail authentication. Use `publish_telemetry` to send application events through the same sink.
