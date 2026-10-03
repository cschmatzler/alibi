---
title: "Compatibility"
description: "The Better Auth version target and native embedding boundaries."
---

The tested HTTP target is **better-auth@1.7.6**. The pinned runtime and official client define expected endpoints, payloads, errors, cookies, and authentication behavior.

Rust schemas, database models, plugin builders, delivery callbacks, and Axum extractors are native APIs. Use the [plugin catalog](/plugins/) and [generated OpenAPI](/plugins/open-api/) to inspect the implemented surface. Newer upstream docs may describe features outside this target.

See the [compatibility guide](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/README.md) for the test contract and [native integration audit](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/audits/core/integration/native-integrations.md) for embedding behavior.

## Frontend

See the official [Better Auth client and frontend documentation](https://www.better-auth.com/docs/concepts/client).
