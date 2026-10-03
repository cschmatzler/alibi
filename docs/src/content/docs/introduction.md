---
title: "Introduction"
description: "Better Auth, built for Rust applications."
---

Better Auth RS brings Better Auth's authentication model to Rust: an auth instance, your database, and plugins for the features you need. Use SQLx or SeaORM for storage and Axum for routing and session extraction.

:::caution[Source-only project]
Use this project directly from Git. APIs, wire formats, and schemas may change.
:::

## Get started

1. [Build an auth instance and start a server](/installation/).
2. [Sign up, sign in, and read a session](/basic-usage/).
3. [Add plugins](/plugins/) for passwordless login, two-factor authentication, organizations, and more.

These docs follow [Better Auth's topics](https://www.better-auth.com/docs/introduction) and cover the Rust backend. The tested HTTP compatibility target is **better-auth@1.7.6**; see [compatibility](/reference/compatibility/) for the supported contract.

## Frontend

See the official [client setup and frontend guides](https://www.better-auth.com/docs/concepts/client).
