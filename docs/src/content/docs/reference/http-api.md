---
title: "HTTP API"
description: "Every route an instance can serve, grouped by feature, with the plugin that provides it."
---

All paths are relative to `AuthConfig::base_path` (`/api/auth` by default). The table is generated from the instance's own OpenAPI model with every plugin enabled; a real instance serves only the routes of the plugins you register (list them with `auth.registered_routes()` or the [OpenAPI plugin](/plugins/open-api/)). Request and response bodies are documented on each feature's page, and in full — with schemas — by the OpenAPI document.

Conventions: unless noted, endpoints need a session (cookie, [bearer token](/plugins/bearer/) or an [API key](/plugins/api-key/#create-and-use-a-key) with `enable_session_for_api_keys`). State-changing requests carrying cookies need a trusted `Origin` ([Security](/concepts/security/)). Server-only operations — API-key verification, JWT signing, organization `addMember`, … — are **not** HTTP routes; see [Server-side calls](/guides/server-side-calls/).

## Core

The core plugins are installed on every instance. `POST /sign-up/email` and `POST /sign-in/email` require `EmailPasswordPlugin`; `/sign-in/social` and the OAuth endpoints require registered providers.

### Sessions

[Session management](/concepts/session-management/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/get-session` | Current session and user, or `null` |
| `POST` | `/get-session` | Same, performing a deferred refresh (needs `defer_session_refresh`) |
| `GET` | `/list-sessions` | List all active sessions of the user (fresh session required) |
| `POST` | `/revoke-other-sessions` | Revoke all other sessions for the user except the current one |
| `POST` | `/revoke-session` | Revoke a single session |
| `POST` | `/revoke-sessions` | Revoke all sessions for the user |
| `POST` | `/sign-out` | Sign out the current user |
| `POST` | `/update-session` | Update the current session |

### Sign-up and sign-in

[Email and password sign-in; the passwordless and federated routes are listed under each plugin](/authentication/email-password/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/sign-in/email` | Sign in with email and password |
| `POST` | `/sign-in/social` | Sign in with a social provider |
| `POST` | `/sign-up/email` | Sign up a user using email and password |

### Users

[User management](/concepts/users-accounts/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/change-email` | Change the email address (opt in) |
| `POST` | `/delete-user` | Delete the user |
| `GET` | `/delete-user/callback` | Callback to complete user deletion with verification token |
| `POST` | `/update-user` | Update the current user |

### Passwords

[Password reset and change](/authentication/email-password/#reset-a-forgotten-password)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/change-password` | Change the password of the user |
| `POST` | `/request-password-reset` | Send a password reset email to the user |
| `POST` | `/reset-password` | Reset the password for a user |
| `GET` | `/reset-password/{token}` | Redirects the user to the callback URL with the token |
| `POST` | `/verify-password` | Verify the current user's password |

### Email verification

[Email verification](/authentication/email-verification/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/send-verification-email` | Send a verification email to the user |
| `GET` | `/verify-email` | Verify the email of the user |

### Accounts and OAuth

[Linked accounts and provider tokens](/authentication/social-sign-on/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/account-info` | Get the account info provided by the provider |
| `GET` | `/callback/{id}` | OAuth provider callback (code exchange) |
| `POST` | `/callback/{id}` | OAuth provider callback for `response_mode=form_post` |
| `POST` | `/get-access-token` | Get a valid access token, doing a refresh if needed |
| `POST` | `/link-social` | Link a social account to the user |
| `GET` | `/list-accounts` | List linked accounts |
| `POST` | `/refresh-token` | Refresh the access token using a refresh token |
| `POST` | `/unlink-account` | Unlink an account |

### Service

[Health and error pages](/concepts/security/#error-pages)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/__test/openapi.json` | Native extension: the OpenAPI document (served by every instance) |
| `GET` | `/error` | Error page (or redirect) for OAuth failures |
| `GET` | `/ok` | Check if the API is working |

## Plugins

### [Admin](/plugins/admin/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/admin/ban-user` | Ban a user |
| `POST` | `/admin/create-user` | Create a new user |
| `GET` | `/admin/get-user` | Get an existing user |
| `POST` | `/admin/has-permission` | Check if the user has permission |
| `POST` | `/admin/impersonate-user` | Impersonate a user |
| `POST` | `/admin/list-user-sessions` | List user sessions |
| `GET` | `/admin/list-users` | List users |
| `POST` | `/admin/remove-user` | Delete a user and all their sessions and accounts. Cannot be undone. |
| `POST` | `/admin/revoke-user-session` | Revoke a user session |
| `POST` | `/admin/revoke-user-sessions` | Revoke all user sessions |
| `POST` | `/admin/set-role` | Set the role of a user |
| `POST` | `/admin/set-user-password` | Set a user's password |
| `POST` | `/admin/stop-impersonating` | Stop impersonating and restore the admin session |
| `POST` | `/admin/unban-user` | Unban a user |
| `POST` | `/admin/update-user` | Update a user's details |

### [Anonymous](/plugins/anonymous/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/delete-anonymous-user` | Delete an anonymous user |
| `POST` | `/sign-in/anonymous` | Sign in anonymously |

### [API key](/plugins/api-key/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api-key/create` | Create a new API key for a user |
| `POST` | `/api-key/delete` | Delete an existing API key |
| `GET` | `/api-key/get` | Retrieve an existing API key by ID |
| `GET` | `/api-key/list` | List all API keys for the authenticated user or for a specific organization |
| `POST` | `/api-key/update` | Update an existing API key by ID |

### [Device authorization](/plugins/device-authorization/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/device` | Verify user code and get device authorization status |
| `POST` | `/device/approve` | Approve device authorization |
| `POST` | `/device/code` | Request a device and user code |
| `POST` | `/device/deny` | Deny device authorization |
| `POST` | `/device/token` | Exchange device code for access token |

### [Email OTP](/plugins/email-otp/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/email-otp/change-email` | Verify new email with OTP and change the email if verification is successful |
| `POST` | `/email-otp/check-verification-otp` | Verify an email with an OTP |
| `POST` | `/email-otp/request-email-change` | Request email change with verification OTP sent to the new email |
| `POST` | `/email-otp/request-password-reset` | Request password reset with email and OTP |
| `POST` | `/email-otp/reset-password` | Reset password with email and OTP |
| `POST` | `/email-otp/send-verification-otp` | Send a verification OTP to an email |
| `POST` | `/email-otp/verify-email` | Verify email with OTP |
| `POST` | `/forget-password/email-otp` | Deprecated: Use /email-otp/request-password-reset instead. |
| `POST` | `/sign-in/email-otp` | Sign in with email and OTP |

### [JWT](/plugins/jwt/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/jwks` | Get the JSON Web Key Set |
| `GET` | `/token` | Get a JWT token |

### [Magic link](/plugins/magic-link/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/magic-link/verify` | Verify magic link |
| `POST` | `/sign-in/magic-link` | Sign in with magic link |

### [Multi-session](/plugins/multi-session/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/multi-session/list-device-sessions` | List the sessions remembered by this browser |
| `POST` | `/multi-session/revoke` | Revoke a device session |
| `POST` | `/multi-session/set-active` | Set the active session |

### [OAuth popup](/plugins/oauth-popup/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/oauth-popup/start` | Start an OAuth flow inside a popup window |

### [OAuth proxy](/plugins/oauth-proxy/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/callback/{provider}/oauth-proxy` | Complete a proxied OAuth sign-in on the originating host |
| `GET` | `/oauth-proxy-callback` | Legacy proxy callback |

### [Google One Tap](/plugins/one-tap/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/one-tap/callback` | Use this endpoint to authenticate with Google One Tap |

### [One-time token](/plugins/one-time-token/)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/one-time-token/generate` | Issue a single-use token for the current session |
| `POST` | `/one-time-token/verify` | Exchange a token for its session |

### [Organization](/plugins/organization/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/organization/accept-invitation` | Accept an invitation to an organization |
| `POST` | `/organization/add-team-member` | The newly created member |
| `POST` | `/organization/cancel-invitation` | Cancel a pending invitation |
| `POST` | `/organization/check-slug` | Check whether an organization slug is available |
| `POST` | `/organization/create` | Create an organization |
| `POST` | `/organization/create-role` | Create a dynamic role |
| `POST` | `/organization/create-team` | Create a new team within an organization |
| `POST` | `/organization/delete` | Delete an organization |
| `POST` | `/organization/delete-role` | Delete a dynamic role |
| `GET` | `/organization/get-active-member` | Get the member details of the active organization |
| `GET` | `/organization/get-active-member-role` | The caller's role in the active organization |
| `GET` | `/organization/get-full-organization` | Get the full organization |
| `GET` | `/organization/get-invitation` | Get an invitation by ID |
| `GET` | `/organization/get-organization` | Get the organization metadata |
| `GET` | `/organization/get-role` | Read a dynamic role |
| `POST` | `/organization/has-permission` | Check if the user has permission |
| `POST` | `/organization/invite-member` | Create an invitation to an organization |
| `POST` | `/organization/leave` | Leave an organization |
| `GET` | `/organization/list` | List all organizations |
| `GET` | `/organization/list-invitations` | List an organization's invitations |
| `GET` | `/organization/list-members` | List an organization's members |
| `GET` | `/organization/list-roles` | List an organization's dynamic roles |
| `GET` | `/organization/list-team-members` | List the members of the given team. |
| `GET` | `/organization/list-teams` | List all teams in an organization |
| `GET` | `/organization/list-user-invitations` | List all invitations a user has received |
| `GET` | `/organization/list-user-teams` | List teams for a user. Without parameters, returns teams for the current user across every organization they belong to. Pass `organizationId` to scope the result to a specific organization. Pass `userId` to list teams for another member; this requires `member:update` permission in the target organization (the explicit `organizationId` if provided, otherwise the session's active organization). |
| `POST` | `/organization/reject-invitation` | Reject an invitation to an organization |
| `POST` | `/organization/remove-member` | Remove a member from an organization |
| `POST` | `/organization/remove-team` | Remove a team from an organization |
| `POST` | `/organization/remove-team-member` | Remove a member from a team |
| `POST` | `/organization/set-active` | Set the active organization |
| `POST` | `/organization/set-active-team` | Set the active team for the current active organization |
| `POST` | `/organization/update` | Update an organization |
| `POST` | `/organization/update-member-role` | Update the role of a member in an organization |
| `POST` | `/organization/update-role` | Update a dynamic role |
| `POST` | `/organization/update-team` | Update an existing team in an organization |

### [Passkey](/plugins/passkey/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/passkey/delete-passkey` | Delete a specific passkey |
| `GET` | `/passkey/generate-authenticate-options` | Generate authentication options for a passkey |
| `GET` | `/passkey/generate-register-options` | Generate registration options for a new passkey |
| `GET` | `/passkey/list-user-passkeys` | List all passkeys for the authenticated user |
| `POST` | `/passkey/update-passkey` | Update a specific passkey's name |
| `POST` | `/passkey/verify-authentication` | Verify authentication of a passkey |
| `POST` | `/passkey/verify-registration` | Verify registration of a new passkey |

### [Phone number](/plugins/phone-number/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/phone-number/request-password-reset` | Request OTP for password reset via phone number |
| `POST` | `/phone-number/reset-password` | Reset password using phone number OTP |
| `POST` | `/phone-number/send-otp` | Use this endpoint to send OTP to phone number |
| `POST` | `/phone-number/verify` | Use this endpoint to verify phone number |
| `POST` | `/sign-in/phone-number` | Use this endpoint to sign in with phone number |

### [Sign in with Ethereum](/plugins/siwe/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/siwe/get-nonce` | Alias of `/siwe/nonce` |
| `POST` | `/siwe/nonce` | Issue a Sign-In with Ethereum nonce |
| `POST` | `/siwe/verify` | Verify a signed SIWE message and sign in |

### [Two-factor](/plugins/two-factor/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/two-factor/disable` | Use this endpoint to disable two factor authentication. |
| `POST` | `/two-factor/enable` | Enable two factor authentication. Pass method 'totp' (default) to set up an authenticator app (returns TOTP URI and backup codes), or 'otp' to enable email/SMS-based codes immediately. |
| `POST` | `/two-factor/generate-backup-codes` | Generate new backup codes for two-factor authentication |
| `POST` | `/two-factor/get-totp-uri` | Use this endpoint to get the TOTP URI |
| `POST` | `/two-factor/send-otp` | Send two factor OTP to the user |
| `POST` | `/two-factor/verify-backup-code` | Verify a backup code for two-factor authentication |
| `POST` | `/two-factor/verify-otp` | Verify two factor OTP |
| `POST` | `/two-factor/verify-totp` | Verify two factor TOTP |

### [Username](/plugins/username/)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/is-username-available` | Check whether a username is free |
| `POST` | `/sign-in/username` | Sign in with username |

### Plugins without routes

[Bearer](/plugins/bearer/), [CAPTCHA](/plugins/captcha/), [Have I Been Pwned](/plugins/have-i-been-pwned/), [Last login method](/plugins/last-login-method/) and [Custom session](/plugins/custom-session/) add behavior to existing routes (headers, checks, response shaping) rather than their own paths. [OpenAPI](/plugins/open-api/) serves `GET /open-api/generate-schema` and the HTML reference (`GET /reference` by default). [JWT](/plugins/jwt/)'s key set path is configurable (`/jwks` by default).

## Frontend

The official client exposes these routes as typed methods; see the Better Auth [client documentation](https://www.better-auth.com/docs/concepts/client).
