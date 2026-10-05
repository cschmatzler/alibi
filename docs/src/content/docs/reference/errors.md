---
title: "Errors"
description: "The HTTP error envelope, common error codes, and the Rust AuthError type."
---

## HTTP errors

Errors share one JSON envelope:

```json
{"code":"INVALID_EMAIL_OR_PASSWORD","message":"Invalid email or password"}
```

`code` is a stable upper-case identifier you can switch on; `message` is human-readable and may change. Only errors that have an upstream constant carry a `code`; a few responses (rate limits, some validation failures) carry only a `message`. Unexpected failures return an empty `500` — the cause is logged on the server and never sent to the client.

Common codes (the full set per plugin is on its page and in the [OpenAPI document](/plugins/open-api/)):

| Status | Code | Raised by |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Malformed body: `{"code":"VALIDATION_ERROR","message":"[body.email] Invalid email address"}` |
| 400 | `PASSWORD_TOO_SHORT`, `PASSWORD_TOO_LONG` | Password policy |
| 400 | `EMAIL_PASSWORD_SIGN_UP_DISABLED` | Sign-up without `enable_signup(true)` |
| 400 | `INVALID_TOKEN` | Reset, verification, magic-link tokens |
| 400 | `FIELD_NOT_ALLOWED` | Writing a [read-only field](/concepts/field-policies/) |
| 401 | `INVALID_EMAIL_OR_PASSWORD` | Wrong credentials |
| 401 | `UNAUTHORIZED`, `Authentication required` | No valid session |
| 403 | `MISSING_OR_NULL_ORIGIN`, `INVALID_ORIGIN`, `INVALID_CALLBACK_URL` | [Origin and redirect checks](/concepts/security/) |
| 403 | `EMAIL_NOT_VERIFIED` | Unverified email at sign-in |
| 403 | `BANNED_USER` | [Admin](/plugins/admin/) ban |
| 403 | `SESSION_NOT_FRESH` | [Freshness](/concepts/session-management/#session-freshness) |
| 404 | `PROVIDER_NOT_FOUND` | Unknown [OAuth provider](/authentication/social-sign-on/) |
| 422 | `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | Duplicate sign-up |
| 413 | — | Body over `BodyLimitConfig::max_bytes` |
| 429 | — | [Rate limited](/concepts/rate-limit/) (see `X-Retry-After`) |

## `AuthError`

In Rust, operations return `AuthResult<T> = Result<T, AuthError>`. Each variant maps to an HTTP status through `AuthError::status_code()` and renders with `to_auth_response()`.

| Variant | Status | Use |
| --- | --- | --- |
| `Api { status, code, message }` | as given | An **intentional public error** from application policy; the message is returned verbatim |
| `Upstream { status, code, message }` | as given | A documented upstream error with a fixed code and message |
| `BadRequest`, `InvalidRequest`, `Validation` | 400 | Invalid input |
| `InvalidCredentials`, `Unauthenticated`, `AuthenticationFailed`, `SessionNotFound` | 401 | Authentication failures |
| `Forbidden`, `Unauthorized`, `BannedUser` | 403 | Authorization failures |
| `NotFound`, `UserNotFound` | 404 | Missing resources |
| `Conflict`, `UnprocessableEntity` | 409 / 422 | Conflicts |
| `PayloadTooLarge`, `MethodNotAllowed`, `RateLimited` | 413 / 405 / 429 | Request-level rejections |
| `NotImplemented` | 501 | A feature the configured store or plugin does not support |
| `Config`, `Database`, `Internal`, `Encryption`, `PasswordHash`, `Jwt`, `Serialization`, `Plugin` | 500 | Internal failures; private details are logged, not returned |
| `CallbackFailure(Box<AuthError>)` | 500 (empty) | An ordinary failure inside an application callback |

Helper constructors: `AuthError::bad_request(msg)`, `forbidden`, `not_found`, `conflict`, `validation`, `internal`, `config`, `not_implemented`.

### Errors from your callbacks

Delivery and policy callbacks return `AuthResult`. What the client sees depends on the variant:

```rust
use better_auth::{AuthError, AuthResult};

fn check(allowed: bool) -> AuthResult<()> {
    if !allowed {
        // An intentional, public error: rendered with this status and message.
        return Err(AuthError::Api {
            status: 403,
            code: Some("TENANT_SUSPENDED".into()),
            message: "This workspace is suspended".into(),
        });
    }
    // Anything else (database, network, bug) becomes an empty 500 and is logged.
    Ok(())
}
```

Return `AuthError::Api`/`forbidden`/`bad_request` for errors the user may see; let infrastructure failures propagate as ordinary errors. Never put secrets in a public message.

## Database errors

`AuthError::Database(DatabaseError)` wraps storage failures. They are logged and returned as `500`. Constraint violations that map to a user-facing condition (a duplicate email, for example) are translated before they reach this variant.
