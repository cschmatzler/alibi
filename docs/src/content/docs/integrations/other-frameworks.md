---
title: "Other frameworks"
description: "Embed the native request handler or dispatch trusted server operations."
---

Other Rust frameworks can call `BetterAuth::handle_request`. Convert the incoming method, path, headers, and body to an `AuthRequest`; then return the response status, bytes, and headers.

## Forward the response

This example uses HTTP types re-exported by Axum. `append` preserves repeated headers, including every `Set-Cookie`:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::http::{HeaderName, HeaderValue, Response};
use better_auth::BetterAuth;
use better_auth::prelude::AuthRequest;

async fn dispatch(
    auth: &BetterAuth<AppAuthSchema>,
    request: AuthRequest,
) -> Result<Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let result = auth.handle_request(request).await?;
    let mut response = Response::builder()
        .status(result.status)
        .body(result.body)?;
    for (name, value) in result.headers {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(&value)?,
        );
    }
    Ok(response)
}
```

Your host owns the dispatch future. If requests must finish after a disconnect, supervise them in an application-owned task. Cancelling dispatch can leave earlier database writes committed. The [Axum integration](/integrations/axum/) provides this supervision automatically.

## Trusted server operations

`BetterAuth::dispatch_endpoint` accepts logical inputs and headers for trusted server calls. These operations stay on the server and do not create HTTP routes. See the [integration contract](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/audits/core/integration/native-integrations.md) for dispatch behavior.

## Frontend

See the official [Better Auth client documentation](https://www.better-auth.com/docs/concepts/client).
