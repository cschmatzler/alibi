---
title: "Telemetry"
description: "Opt-in, application-owned authentication telemetry: events, sinks and privacy."
---

Alibi collects **nothing** by default and never contacts a telemetry service. Telemetry is a hook for *your* code: you install a sink, the library hands it events, and you decide where they go.

## Enable it

Provide a `TelemetrySink` and register it on the builder:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::sqlx::SqlxStore;
use alibi::telemetry::{TelemetryConfig, TelemetryEvent, TelemetrySink};
use alibi::{AuthConfig, AuthResult, Alibi};

struct EventLog;

#[async_trait]
impl TelemetrySink for EventLog {
    async fn track(&self, event: TelemetryEvent) -> AuthResult<()> {
        eprintln!("auth event {}: {}", event.event_type, event.payload);
        Ok(())
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .telemetry(TelemetryConfig::new(EventLog))
        .build()
        .await
}
```

`TelemetryConfig::new(sink)` enables delivery; `.enabled(false)` turns it off again. Without a configured sink nothing is emitted.

## Events

Initialization publishes one event:

```json
{"type":"init","payload":{"libraryVersion":"0.4.1","runtime":"rust","platform":"linux","architecture":"x86_64","plugins":["email-password","session-management","oauth"]}}
```

It contains the library version, platform and the installed plugin names — no hostnames, URLs, secrets or user data. Publish your own application events through the same sink:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::telemetry::TelemetryEvent;
use serde_json::json;

async fn record(auth: &Alibi<AppAuthSchema>) {
    auth.publish_telemetry(TelemetryEvent::new("checkout_started", json!({ "plan": "pro" }))).await;
}
```

## Delivery semantics

- The **sink owns transport and retention**: batch it, forward it to your analytics system, or drop it.
- A sink error produces a log warning (without the payload or the error text, which may hold credentials) and **never fails authentication**.
- Application payloads come from your trusted code, never from HTTP requests.
