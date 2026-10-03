---
title: "Plugins"
description: "Native authentication plugins available in Better Auth RS."
sidebar:
  label: Overview
  order: 0
---

Choose a plugin below for its schema requirements, complete builder example, and endpoints.

| Plugin | Purpose |
| --- | --- |
| [API key](/plugins/api-key/) | Issue, manage, and verify scoped API credentials. |
| [Admin](/plugins/admin/) | Administrative user management, bans, impersonation, and role-based permissions. |
| [Anonymous](/plugins/anonymous/) | Create a temporary user identity before full account registration. |
| [Bearer](/plugins/bearer/) | Authenticate requests with session tokens in the Authorization header. |
| [CAPTCHA](/plugins/captcha/) | Verify challenges before authentication writes. |
| [Custom session](/plugins/custom-session/) | Customize session response data. |
| [Device authorization](/plugins/device-authorization/) | Authorize a CLI or constrained device through a browser on another device. |
| [Email OTP](/plugins/email-otp/) | Authenticate or verify email with a one-time code. |
| [Have I Been Pwned](/plugins/have-i-been-pwned/) | Check password choices against the compromised-password range API. |
| [JWT](/plugins/jwt/) | Issue signed JSON Web Tokens and expose a JWKS key set. |
| [Last login method](/plugins/last-login-method/) | Remember which authentication method a visitor last used. |
| [Magic link](/plugins/magic-link/) | Sign in through a single-use link delivered to an email address. |
| [Multi-session](/plugins/multi-session/) | Keep multiple signed-in identities on one browser or device. |
| [OAuth proxy](/plugins/oauth-proxy/) | Proxy OAuth callbacks for environments with a separate production auth origin. |
| [One Tap](/plugins/one-tap/) | Verify Google One Tap credentials on the Rust server. |
| [One-time token](/plugins/one-time-token/) | Exchange an existing session through a short-lived, single-use credential. |
| [OpenAPI](/plugins/open-api/) | Inspect your configured authentication API and generate an API reference. |
| [Organization](/plugins/organization/) | Organizations, invitations, membership, roles, and optional teams. |
| [Passkey](/plugins/passkey/) | WebAuthn registration and authentication using passkeys. |
| [Phone number](/plugins/phone-number/) | Verify phone numbers and authenticate with phone credentials. |
| [Sign in with Ethereum](/plugins/siwe/) | Verify wallet identities using application policies. |
| [Two-factor authentication](/plugins/two-factor/) | TOTP, email OTP challenges, and backup codes for a second authentication factor. |
| [Username](/plugins/username/) | Username sign-in through the email/password plugin. |

The builder supplies core modules for sessions, accounts, users, and verification. [Email/password login](/authentication/email-password/) stays disabled until configured. Explicit registration replaces the corresponding default; see [plugin concepts](/concepts/plugins/).

## Frontend

For frontend and client usage, see the official Better Auth guide: [Plugins](https://www.better-auth.com/docs/plugins).
