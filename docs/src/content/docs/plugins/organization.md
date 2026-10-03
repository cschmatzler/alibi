---
title: "Organization"
description: "Organizations, invitations, membership, roles, and optional teams."
---

`OrganizationPlugin` manages organizations, invitations, membership, roles, and optional teams.

## Setup

```bash
better-auth-rs generate --plugins organization -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::OrganizationPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OrganizationPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Create an organization through `POST /organization/create`, invite members through `/organization/invite-member`, and accept invitations through `/organization/accept-invitation`. Reads include `/organization/list` and `/organization/list-members`.

Organization membership and permissions are checked per operation. Configure roles and policies with `OrganizationConfig`; teams and dynamic role endpoints are conditional on those options. Implement invitation delivery in your application before offering email invitations.

## Frontend

See the official [Organization guide](https://www.better-auth.com/docs/plugins/organization).

## Application-side access control

`better_auth::plugins::access` provides `role`, `create_access_control`, and
`AccessControl::new_role` for literal resource/action grants. Plain action lists
and `Role::authorize` use AND. A resource rule can choose OR for its actions;
`authorize_with_connector` independently chooses AND or OR across resources.
Empty requests and empty action lists deny, and resources and actions are case
sensitive. AND returns the first rejection in Source object-entry order.

```rust
use better_auth::plugins::access::{ActionRequest, Connector, create_access_control};

let ac = create_access_control(
    [("report".into(), vec!["read".into(), "publish".into()])].into(),
);
let reviewer = ac.new_role([("report".into(), vec!["read".into()])].into());
let request = [("report".into(), ActionRequest::Rule {
    actions: vec!["read".into(), "publish".into()],
    connector: Connector::Or,
})].into();
assert!(reviewer.authorize(&request).success());
```

These are typed application utilities. They do not change the organization
HTTP permission schema, which accepts action arrays and requires one assigned
role to satisfy the entire request. Rust declarations do not enforce Source's
TypeScript compile-time resource/action subset constraints; grants are supplied
as string lists, matching Source's runtime constructor behavior. Arbitrary
JavaScript values and custom-adapter permission representations remain outside
this typed API.
