---
title: "Admin"
description: "User management for operators: list, create, update and delete users, set roles, ban, impersonate and revoke sessions."
---

`AdminPlugin` adds a privileged API on top of your users: browse and edit accounts, assign roles, ban abusers, revoke sessions and impersonate a user to reproduce a support problem. Every operation is authorized against a **role-based permission policy**.

## Schema

```bash
alibi generate --plugins admin -o src/auth_schema.rs
```

Adds `users.role`, `users.banned`, `users.ban_reason`, `users.ban_expires`, `users.metadata` and `sessions.impersonated_by`.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::{AdminPlugin, EmailPasswordPlugin};
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(AdminPlugin::new())
        .build()
        .await
}
```

New users get the role `user` (configurable). The built-in role `admin` may do everything below; `user` may do nothing. Non-admins calling these endpoints receive `403` with a precise code, for example:

```json
{"code":"YOU_ARE_NOT_ALLOWED_TO_LIST_USERS","message":"You are not allowed to list users"}
```

### Create the first administrator

Nobody is an admin yet, and only admins can set roles. Bootstrap one of three ways:

- list their user ids in `admin_user_ids` — these users bypass permission checks entirely;
- update the row once: `UPDATE users SET role = 'admin' WHERE email = 'you@example.com'`;
- seed the user from a migration or a server-side [`create_endpoint`](/guides/server-side-calls/).

## Endpoints

All require a signed-in admin session. Paths are under `/api/auth`.

| Method | Path | Body / query | Permission |
| --- | --- | --- | --- |
| `GET` | `/admin/list-users` | `limit`, `offset`, `sortBy`, `sortDirection`, `searchField` (`email`/`name`), `searchOperator`, `searchValue`, `filterField`, `filterOperator`, `filterValue` | `user:list` |
| `GET` | `/admin/get-user` | `id` | `user:get` |
| `POST` | `/admin/create-user` | `email`, `password`, `name`, `role`, `data` | `user:create` (+ `user:set-role` when a role is given) |
| `POST` | `/admin/update-user` | `userId`, `data` | `user:update` |
| `POST` | `/admin/set-role` | `userId`, `role` (string or array) | `user:set-role` |
| `POST` | `/admin/set-user-password` | `userId`, `newPassword` | `user:set-password` |
| `POST` | `/admin/ban-user` | `userId`, `banReason`, `banExpiresIn` (seconds) | `user:ban` |
| `POST` | `/admin/unban-user` | `userId` | `user:ban` |
| `POST` | `/admin/impersonate-user` | `userId` | `user:impersonate` |
| `POST` | `/admin/stop-impersonating` | — | the impersonating session |
| `POST` | `/admin/list-user-sessions` | `userId` | `session:list` |
| `POST` | `/admin/revoke-user-session` | `sessionToken` | `session:revoke` |
| `POST` | `/admin/revoke-user-sessions` | `userId` | `session:revoke` |
| `POST` | `/admin/remove-user` | `userId` | `user:delete` |
| `POST` | `/admin/has-permission` | `permissions` (or `permission`) | none beyond a session |

```bash
# Search and page through users
curl -b admin.txt 'http://localhost:3000/api/auth/admin/list-users?limit=20&sortBy=createdAt&sortDirection=desc&searchField=email&searchOperator=contains&searchValue=example.com'
```

```json
{"users":[{"id":"d5063022-…","name":"Bob","email":"bob@example.com","emailVerified":false,"image":null,"createdAt":"…","updatedAt":"…","role":"user","banned":false,"banReason":null,"banExpires":null,"twoFactorEnabled":false,"username":null,"displayUsername":null}],"total":1,"limit":20,"offset":0}
```

`filterOperator` accepts `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`; `sortDirection` defaults to ascending. Admin output includes your [additional fields](/concepts/field-policies/) and the admin columns, but never credentials.

### Roles

```bash
curl -b admin.txt http://localhost:3000/api/auth/admin/set-role \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"userId":"d5063022-…","role":["admin","support"]}'
# {"user":{… "role":"admin,support" …}}
```

A user may hold several roles, stored comma-separated; a permission is granted if **any** role grants it.

### Ban

```bash
curl -b admin.txt http://localhost:3000/api/auth/admin/ban-user \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"userId":"d5063022-…","banReason":"spam","banExpiresIn":3600}'
# {"user":{… "banned":true,"banReason":"spam","banExpires":"2026-10-04T11:17:37.183Z" …}}
```

Banning revokes all of the user's sessions. While the ban lasts, **every** way of creating a session — password, OAuth, magic link, passkey — fails with `403 BANNED_USER`, and existing cookies read as no session. An expired ban is lifted automatically. Without `banExpiresIn` (and without `default_ban_expires_in`) the ban is permanent.

### Impersonation

`POST /admin/impersonate-user` creates a session for the target user, marked `impersonatedBy: <admin id>`, valid for one hour (`impersonation_session_duration`). The admin's own session is kept in the `admin_session` cookie so `POST /admin/stop-impersonating` can restore it:

```json
{"session":{"id":"…","userId":"<target>","impersonatedBy":"<admin>","expiresAt":"<now+1h>","token":"…"},"user":{…target…}}
```

Admins cannot impersonate other admins unless `allow_impersonating_admins` is set (`403 YOU_CANNOT_IMPERSONATE_ADMINS`). Impersonated sessions are hidden from the target's `GET /list-sessions`.

## Configuration

`AdminPlugin` builder methods / `AdminConfig` fields:

| Option | Default | Effect |
| --- | --- | --- |
| `default_role` | `"user"` | Role assigned to new users |
| `admin_roles` | `["admin"]` | Roles treated as admin for "may not impersonate an admin" checks; each must exist in `roles` |
| `admin_user_ids` | none | Users that bypass all permission checks |
| `roles` | built-in `admin` and `user` | `HashMap<String, RolePermissions>` replacing the built-in policy (`Some(empty)` grants nothing) |
| `default_ban_reason` | none | Reason used when none is supplied |
| `default_ban_expires_in` | none | Ban duration in seconds when none is supplied (`0`/`NaN` = permanent) |
| `impersonation_session_duration` | 3600 s | Lifetime of impersonation sessions |
| `banned_user_message` | built-in text | Message returned to banned users |
| `banned_user_message_callback` | none | Async callback computing that message from the stored user |
| `allow_impersonating_admins` | `false` | Allow admins to impersonate admins |

### Custom roles and permissions

The permission model is `resource → actions`. The built-in resources are `user` (`create`, `list`, `set-role`, `ban`, `impersonate`, `delete`, `set-password`, `get`, `update`) and `session` (`list`, `revoke`, `delete`):

```rust
use alibi::plugins::{AdminPlugin, RolePermissions};
use std::collections::HashMap;

fn admin() -> AdminPlugin {
    let roles = HashMap::from([
        (
            "admin".to_owned(),
            RolePermissions::new()
                .allow("user", ["create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "get", "update"])
                .allow("session", ["list", "revoke", "delete"]),
        ),
        (
            // Support staff can look but not change anything.
            "support".to_owned(),
            RolePermissions::new().allow("user", ["list", "get"]).allow("session", ["list"]),
        ),
        ("user".to_owned(), RolePermissions::new()),
    ]);
    AdminPlugin::new()
        .roles(roles)
        .admin_roles(vec!["admin".to_owned()])
        .default_role("user")
        .impersonation_session_duration(1800.0)
        .default_ban_expires_in(7.0 * 24.0 * 3600.0)
}
```

Check a permission from the client with `POST /admin/has-permission` and `{"permissions":{"user":["ban"]}}` → `{"success":true,"error":null}`. For access-control checks in **your own** code, use the [access-control helpers](/plugins/organization/#application-side-access-control), which implement the same `resource → actions` semantics.

### Custom ban message

```rust
use async_trait::async_trait;
use alibi::plugins::{AdminBannedUserMessage, AdminPlugin};
use alibi::prelude::AuthUser;
use alibi::AuthResult;
use crate::auth_schema::user::Model as User;

struct BanNotice;

#[async_trait]
impl AdminBannedUserMessage<User> for BanNotice {
    // Receives the stored user, including columns hidden from public responses.
    async fn message(&self, user: &User) -> AuthResult<String> {
        Ok(format!("Account {} is suspended. Contact support@example.com.", user.id()))
    }
}

fn admin() -> AdminPlugin {
    AdminPlugin::new().banned_user_message_callback::<User, _>(BanNotice)
}
```

## Security notes

- Hiding an admin page is not authorization — enforce the plugin's permission policy (or yours) on the server.
- `admin_user_ids` bypasses every check; keep it to break-glass accounts and prefer roles.
- Log impersonation: sessions carry `impersonatedBy`, so audit middleware can record who acted as whom.
- `remove-user` deletes the user's sessions and accounts and cannot be undone. It also removes the user's [API keys](/plugins/api-key/) when the `api_keys` table exists.

## Frontend

See the official [Admin guide](https://www.better-auth.com/docs/plugins/admin).
