---
title: "Plugins"
description: "Every Better Auth RS plugin by category, with its schema needs and endpoints."
sidebar:
  label: Overview
  order: 0
---

Plugins add sign-in methods, token types, security controls and administration features. Each page below documents the plugin's **schema requirements**, a **complete builder example**, its **HTTP endpoints** with request and response examples, and every **configuration option**.

How registration works — and which core plugins are always installed — is covered in [Plugin concepts](/concepts/plugins/). To write your own, see [Writing a plugin](/guides/writing-a-plugin/).

## Sign-in methods

| Plugin | Purpose | Schema |
| --- | --- | --- |
| [Email and password](/authentication/email-password/) | Credentials, password reset, custom hashing | none |
| [Username](/plugins/username/) | Sign in with a username, with validation and normalization policy | `username` |
| [Anonymous](/plugins/anonymous/) | Temporary guest identities that upgrade to real accounts | `anonymous` |
| [Magic link](/plugins/magic-link/) | Single-use sign-in links by email | none |
| [Email OTP](/plugins/email-otp/) | One-time codes for sign-in, verification, password reset and email change | none |
| [Phone number](/plugins/phone-number/) | Phone verification, OTP and password sign-in | `phone-number` |
| [Passkey](/plugins/passkey/) | WebAuthn passkeys (platform and security keys) | `passkey` |
| [Sign in with Ethereum](/plugins/siwe/) | Wallet sign-in (ERC-4361) | `siwe` |
| [Google One Tap](/plugins/one-tap/) | Verify Google One Tap credentials | none |

## OAuth and federation

| Plugin | Purpose |
| --- | --- |
| [Social sign-on](/authentication/social-sign-on/) | 36 built-in OAuth/OIDC providers |
| [Generic OAuth](/authentication/generic-oauth/) | Any OIDC or OAuth 2.0 server |
| [OAuth popup](/plugins/oauth-popup/) | Popup-window sign-in for SPAs and embedded apps |
| [OAuth proxy](/plugins/oauth-proxy/) | One registered callback for preview and staging hosts |

## Multi-factor and devices

| Plugin | Purpose | Schema |
| --- | --- | --- |
| [Two-factor](/plugins/two-factor/) | TOTP, OTP and backup codes as a second factor | `two-factor` |
| [Device authorization](/plugins/device-authorization/) | Sign in a CLI or TV through a browser (RFC 8628) | `device-authorization` |

## Sessions and tokens

| Plugin | Purpose | Schema |
| --- | --- | --- |
| [Bearer](/plugins/bearer/) | `Authorization: Bearer` session tokens | none |
| [JWT](/plugins/jwt/) | Signed JWTs and a JWKS endpoint for other services | `jwt` |
| [One-time token](/plugins/one-time-token/) | Short-lived single-use session handoff | none |
| [Multi-session](/plugins/multi-session/) | Several signed-in accounts per browser | none |
| [Custom session](/plugins/custom-session/) | Reshape the `/get-session` response | none |
| [Last login method](/plugins/last-login-method/) | Remember which method a visitor used last | `last-login-method` (optional) |

## Machine access

| Plugin | Purpose | Schema |
| --- | --- | --- |
| [API key](/plugins/api-key/) | Scoped, rate-limited, expiring credentials for users and organizations | `api-key` |

## Hardening

| Plugin | Purpose |
| --- | --- |
| [CAPTCHA](/plugins/captcha/) | Turnstile, reCAPTCHA, hCaptcha, CaptchaFox or Vercel BotID before auth writes |
| [Have I Been Pwned](/plugins/have-i-been-pwned/) | Reject breached passwords |

## Administration and tenancy

| Plugin | Purpose | Schema |
| --- | --- | --- |
| [Admin](/plugins/admin/) | User management, roles, bans and impersonation | `admin` |
| [Organization](/plugins/organization/) | Organizations, members, invitations, roles, teams | `organization` (+ `organization-teams`, `organization-dynamic-roles`) |

## Developer tools

| Plugin | Purpose |
| --- | --- |
| [OpenAPI](/plugins/open-api/) | OpenAPI document and interactive API reference for your instance |

## Conventions used on these pages

- **Paths** are relative to `/api/auth` (your `base_path`).
- **Schema** values are `better-auth-rs generate --plugins …` names; see [Database](/concepts/database/#plugin-schema).
- **Examples** use `AppAuthSchema` and `SqlxStore<AppAuthSchema>` from the [installation](/installation/) guide. SeaORM works identically.
- **Config structs** can be built with `..Default::default()`; plugins that use builder methods list them.
- Numeric options that mirror JavaScript numbers (OTP lengths, lifetimes in seconds) are `f64`, so write `300.0`, not `300`.

## Frontend

For client plugins, see the official [Better Auth plugin guides](https://www.better-auth.com/docs/plugins).
