---
title: "Users and accounts"
description: "Identity, linked credentials, profile updates, email changes, account deletion and linking policy."
---

A **user** is an identity. An **account** is one way that identity authenticates — a password (`provider_id = "credential"`) or an OAuth provider (`"google"`, `"github"`, …). One user can have several accounts, several sessions, and — with the right plugins — many more things attached.

```text
user ──┬── account (credential)       password hash
       ├── account (google)           access/refresh/id tokens
       ├── session  ×N                one per signed-in device
       └── plugin data                passkeys, API keys, memberships, …
```

The core user endpoints are installed on every instance:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/update-user` | Update `name`, `image` and your [additional fields](/concepts/field-policies/) |
| `POST` | `/change-email` | Change the email address (opt in) |
| `POST` | `/delete-user` | Delete the account (opt in) |
| `GET` | `/delete-user/callback` | Complete a verified deletion |
| `GET` | `/list-accounts` | List linked accounts |
| `POST` | `/unlink-account` | Remove a linked account |
| `POST` | `/link-social` | Link another OAuth provider ([Social sign-on](/authentication/social-sign-on/)) |

## Update the profile

```bash
curl -b cookies.txt http://localhost:3000/api/auth/update-user \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"Ada Lovelace","image":"https://example.com/ada.png"}'
```

```json
{"status":true}
```

Read the result back with `GET /get-session`. Which extra fields a client may write is controlled by [field policies](/concepts/field-policies/). Plugin-owned fields can be protected from direct writes — for example the phone number cannot be changed through `/update-user` once the [phone number](/plugins/phone-number/) plugin is installed.

## Change the email address

Email changes are disabled by default. Enable them by replacing the default user module:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::UserManagementPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(UserManagementPlugin::new().change_email_enabled(true))
        .build()
        .await
}
```

What happens on `POST /change-email` depends on the user and the callbacks you configure:

| User | Configuration | Result |
| --- | --- | --- |
| Email verified | `send_change_email_confirmation` set | A confirmation link goes to the **current** address; the change is applied when it is followed |
| Email verified | no confirmation callback | A verification link goes to the **new** address; the change is applied when it is followed |
| Email unverified | `update_without_verification(true)` | The address is changed immediately; a verification link is sent to the new address if delivery is configured |
| Email unverified | default | A verification link goes to the new address |

If the requested address belongs to another user, the response is the same `{"status":true}` and nothing is sent, so the endpoint cannot be used to probe for registered addresses. Delivery needs the verification sender from [Email verification](/authentication/email-verification/) or an [email provider](/concepts/notifications/); otherwise the request fails with `400 Verification email isn't enabled`. To customize the confirmation message, supply a callback:

```rust
use async_trait::async_trait;
use alibi::plugins::{SendChangeEmailConfirmation, UserManagementPlugin};
use alibi::wire::UserView;
use alibi::AuthResult;
use std::sync::Arc;

struct ChangeEmailMailer;

#[async_trait]
impl SendChangeEmailConfirmation for ChangeEmailMailer {
    async fn send(&self, user: &UserView, new_email: &str, url: &str, _token: &str) -> AuthResult<()> {
        // `user.email` is the current address, `new_email` the requested one.
        println!("approve moving {:?} to {new_email}: {url}", user.email);
        Ok(())
    }
}

fn users() -> UserManagementPlugin {
    UserManagementPlugin::new()
        .change_email_enabled(true)
        .send_change_email_confirmation(Arc::new(ChangeEmailMailer))
}
```

The request body is `{"newEmail":"…","callbackURL":"…"}`; changing to the current address fails with `400 Email is the same`.

## Delete an account

Deletion is also opt-in:

```rust
use async_trait::async_trait;
use alibi::plugins::UserManagementPlugin;
use alibi::plugins::user_management::{AfterDeleteUser, BeforeDeleteUser, SendDeleteAccountVerification};
use alibi::wire::UserView;
use alibi::{AuthError, AuthResult};
use chrono::Duration;
use std::sync::Arc;

struct Guard;

#[async_trait]
impl BeforeDeleteUser for Guard {
    async fn before_delete(&self, user: &UserView) -> AuthResult<()> {
        if user.email.as_deref() == Some("root@example.com") {
            return Err(AuthError::forbidden("The root account cannot be deleted"));
        }
        Ok(())
    }
}

struct Cleanup;

#[async_trait]
impl AfterDeleteUser for Cleanup {
    async fn after_delete(&self, user: &UserView) -> AuthResult<()> {
        println!("remove application data of {}", user.id);
        Ok(())
    }
}

struct ConfirmDeletion;

#[async_trait]
impl SendDeleteAccountVerification for ConfirmDeletion {
    async fn send(&self, user: &UserView, url: &str, _token: &str) -> AuthResult<()> {
        println!("send {url} to {:?}", user.email);
        Ok(())
    }
}

fn users() -> UserManagementPlugin {
    UserManagementPlugin::new()
        .delete_user_enabled(true)
        .delete_token_expires_in(Duration::hours(1))
        .send_delete_account_verification(Arc::new(ConfirmDeletion))
        .before_delete(Arc::new(Guard))
        .after_delete(Arc::new(Cleanup))
}
```

`POST /delete-user` accepts a `password`, a `token` and a `callbackURL`. Without a verification sender (and without `require_delete_verification(true)`), the call deletes the account immediately, but only when the session is [fresh](/concepts/session-management/#session-freshness) or the password is supplied. With a sender, the first call stores a one-time proof and sends a link to `GET /delete-user/callback?token=…`; following it — or posting the `token` back — completes the deletion. A `before_delete` error aborts the operation. The user, sessions, accounts and any [API keys](/plugins/api-key/) are removed and the response clears the auth cookies. Until you opt in, `/delete-user` answers `404`.

## Linked accounts

```bash
curl -b cookies.txt http://localhost:3000/api/auth/list-accounts
```

```json
[{"id":"832482ba-…","accountId":"574c3df7-…","providerId":"credential","userId":"574c3df7-…","createdAt":"…","updatedAt":"…","scopes":[]},
 {"id":"a12f3c…","accountId":"4821937","providerId":"github","userId":"574c3df7-…","createdAt":"…","updatedAt":"…","scopes":["read:user","user:email"]}]
```

Public account output never includes tokens or password hashes. `POST /unlink-account` with `{"accountId":"<id>"}` removes one. Removing the last account fails with `400 FAILED_TO_UNLINK_LAST_ACCOUNT` unless `allow_unlinking_all` is set.

### Linking policy

`AuthConfig::account` controls when an OAuth sign-in may attach to an existing user. Matching profile data alone never establishes ownership: the provider must assert a verified email, or be explicitly trusted.

```rust
use alibi::AuthConfig;
use alibi::config::AccountLinkingConfig;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.account.account_linking = AccountLinkingConfig {
        enabled: true,
        // Link these providers even if they report an unverified email.
        trusted_providers: vec!["google".into()],
        ..Default::default()
    };
    config.account.encrypt_oauth_tokens = true;
    config
}
```

| `AccountLinkingConfig` field | Default | Effect |
| --- | --- | --- |
| `enabled` | `true` | Allow linking at all |
| `trusted_providers` | `[]` | Providers trusted for linking even with an unverified email. An empty list does **not** bypass the verified-email requirement |
| `trusted_providers_resolver` | none | Async policy replacing the static list, evaluated at startup and per request |
| `allow_different_emails` | `false` | Let a user link an account whose email differs. **Security-sensitive** |
| `allow_unlinking_all` | `false` | Allow removing the final account |
| `disable_implicit_linking` | `false` | Link only through the explicit `/link-social` call, never during sign-in |
| `require_local_email_verified` | `true` | The existing local account's email must be verified before a social account links implicitly |
| `update_user_info_on_link` | `false` | Copy profile data from the provider when linking |

Other `AccountConfig` switches:

| Field | Default | Effect |
| --- | --- | --- |
| `update_account_on_sign_in` | `true` | Refresh stored OAuth tokens at each sign-in |
| `encrypt_oauth_tokens` | `false` | Encrypt access and refresh tokens at rest with the [secret](/reference/secrets/) |
| `store_account_cookie` | `false` | Keep provider account data in an `account_data` cookie for token flows without a database |
| `store_state_strategy` | `Automatic` | Where OAuth `state` lives: `Cookie`, `Database`, or `Automatic` (database with a store, cookie without) |
| `skip_state_cookie_check` | `false` | Skip the state-cookie comparison. **Security-sensitive; leave off** |

To decide linking per request, implement `TrustedProvidersResolver`:

```rust
use async_trait::async_trait;
use alibi::config::TrustedProvidersResolver;
use alibi::prelude::AuthRequest;
use alibi::{AuthConfig, AuthResult};

struct TenantProviders;

#[async_trait]
impl TrustedProvidersResolver for TenantProviders {
    // `request` is `None` during initialization and the real request afterwards.
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        let tenant = request.and_then(|r| r.headers.get("x-tenant").cloned());
        Ok(match tenant.as_deref() {
            Some("acme") => vec!["google".into(), "okta".into()],
            _ => vec![],
        })
    }
}

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret).trusted_providers_resolver(TenantProviders)
}
```

## Validate new identities

`AuthConfig::user_validation` runs before a user is created, before a provider account is written, and before a provider account is linked. It sees the candidate user and where it came from (`password`, OAuth provider, SSO, anonymous, …) and can mutate or reject it. A rejection becomes a `403` with your error code. Implement `alibi::user_validation::UserInfoValidator`:

```rust
use async_trait::async_trait;
use alibi::{AuthConfig, AuthResult};
use alibi::hooks::RequestHookContext;
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use std::sync::Arc;

struct CompanyAddressesOnly;

#[async_trait]
impl UserInfoValidator for CompanyAddressesOnly {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _request: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let allowed = data
            .user
            .email
            .as_deref()
            .is_some_and(|email| email.ends_with("@example.com"));
        Ok((!allowed).then(|| UserValidationRejection {
            error: "EMAIL_DOMAIN_NOT_ALLOWED".into(),
            error_description: Some("Only example.com addresses may register".into()),
        }))
    }
}

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.user_validation = Some(Arc::new(CompanyAddressesOnly));
    config
}
```

Returning `Ok(None)` admits the identity. For side effects on the database write itself, use [database hooks](/concepts/hooks/).

## Frontend

See the official [users and accounts guide](https://www.better-auth.com/docs/concepts/users-accounts).
