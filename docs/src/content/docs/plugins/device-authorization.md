---
title: "Device authorization"
description: "OAuth 2.0 device flow (RFC 8628): sign in a CLI, TV or IoT device through a browser on another device."
---

`DeviceAuthorizationPlugin` implements the **device authorization grant**. A device without a browser (a CLI, a TV app, a Raspberry Pi) asks for a short code, tells the user to open a URL on their phone or laptop, and polls until the user approves it. The result is a session token for the device.

## Schema

```bash
better-auth-rs generate --plugins device-authorization -o src/auth_schema.rs
```

Adds the `device_code` table (device code, user code, status, polling interval, client id, scope, owner). With [`AuthBuilder::without_database`](/databases/no-database/) device codes live in memory and are lost on restart.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(DeviceAuthorizationPlugin::new().verification_uri("https://app.example.com/device"))
        .build()
        .await
}
```

`verification_uri` is **your** approval page — a frontend route where a signed-in user enters or confirms the code. The plugin serves the API behind it.

## The flow

```text
Device                          Server                         User (browser)
  │  POST /device/code            │                                  │
  ├──────────────────────────────►│  {device_code, user_code,        │
  │◄──────────────────────────────┤   verification_uri, interval}    │
  │  show: "go to …/device, code ABCD2345"                          │
  │                               │      GET /device?user_code=…     │
  │  POST /device/token (poll)    │◄─────────────────────────────────┤  (signed in: claims the code)
  │  authorization_pending        │      POST /device/approve        │
  │                               │◄─────────────────────────────────┤
  │  POST /device/token           │                                  │
  ├──────────────────────────────►│  {access_token: <session token>} │
  │◄──────────────────────────────┤                                  │
```

1. **Request codes** — `POST /device/code` with `{"client_id":"my-cli","scope":"read"}`:

   ```json
   {"device_code":"GmRhmhcxhwAzkoEqiMEg…","user_code":"ABCD2345","verification_uri":"https://app.example.com/device","verification_uri_complete":"https://app.example.com/device?user_code=ABCD2345","expires_in":1800,"interval":5}
   ```

   Both `application/json` and form-encoded bodies are accepted.
2. **Show the user** `verification_uri` and `user_code` (or open `verification_uri_complete`).
3. **User approves.** In the approval page the signed-in user's browser calls `GET /device?user_code=…` — this *claims* the code for their session and returns `{user_code, status, client_id, scope}` (details are shown only to the claimant) — then `POST /device/approve` or `/device/deny` with `{"userCode":"…"}`. Approval and denial are refused for codes nobody has claimed.
4. **Poll** `POST /device/token` with `{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"…","client_id":"my-cli"}` no faster than `interval` seconds.

Poll responses follow RFC 8628:

| Response | Meaning |
| --- | --- |
| `400 authorization_pending` | Keep polling |
| `400 slow_down` | Polled too fast; wait longer |
| `400 access_denied` | The user denied the request (code is deleted) |
| `400 expired_token` | The code expired |
| `400 invalid_grant` | Unknown code, wrong `client_id`, or already redeemed |
| `200 {"access_token","token_type":"Bearer","expires_in","scope"}` | Approved — the code is consumed exactly once |

`access_token` is an ordinary **session token**. Use it as `Authorization: Bearer <token>` with the [bearer plugin](/plugins/bearer/), or store it as the device's session cookie value. Responses carry `Cache-Control: no-store`.

Concurrent approve/deny calls that both read a pending code can both succeed; the last completed write decides the state, matching the behavior measured on Better Auth 1.7.6 and unchanged in 1.7.7. A later decision that sees an already processed code is rejected.

## Configuration

`DeviceAuthorizationPlugin` builder methods:

| Method | Default | Effect |
| --- | --- | --- |
| `verification_uri(…)` | none | URL of your approval page (sets `verification_uri` in responses) |
| `expires_in(chrono::Duration)` | 30 minutes | Lifetime of a device/user code pair |
| `interval(chrono::Duration)` | 5 seconds | Minimum polling interval (`slow_down` beyond it) |
| `device_code_length(n)`, `user_code_length(n)` | 40, 8 | Generated lengths |
| `generate_device_code_with(fn)`, `generate_user_code_with(fn)` | random | Custom synchronous generators (`async` variants: `…_async_with`) |
| `validate_client(async fn(String) -> AuthResult<bool>)` | accept all | Validate `client_id` before issuing or redeeming |
| `on_device_auth_request(async fn(client_id, Option<scope>))` | none | Hook when a request is created |

```rust
use better_auth::plugins::DeviceAuthorizationPlugin;
use chrono::Duration;

fn device_flow() -> DeviceAuthorizationPlugin {
    DeviceAuthorizationPlugin::new()
        .verification_uri("https://app.example.com/device")
        .expires_in(Duration::minutes(10))
        .interval(Duration::seconds(5))
        .user_code_length(8)
        .validate_client(|client_id| async move { Ok(matches!(client_id.as_str(), "my-cli" | "my-tv")) })
        .on_device_auth_request(|client_id, scope| async move {
            println!("device request from {client_id} for {scope:?}");
            Ok(())
        })
}
```

`GET /device` carries its own rate limit — 5 requests per client IP within one code lifetime (`expires_in`) — to resist user-code guessing. User codes use an unambiguous alphabet (no `0`, `O`, `1`, `I`) so they are easy to read aloud and type.

## Write the device client

```ts
const { device_code, user_code, verification_uri, interval } = await post("/device/code", { client_id: "my-cli" });
console.log(`Open ${verification_uri} and enter ${user_code}`);
let wait = interval;
for (;;) {
  await sleep(wait * 1000);
  const res = await post("/device/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code, client_id: "my-cli" });
  if (res.access_token) return res.access_token;
  if (res.error === "slow_down") wait += 5;
  else if (res.error !== "authorization_pending") throw new Error(res.error);
}
```

## Frontend

See the official [Device authorization guide](https://www.better-auth.com/docs/plugins/device-authorization).
