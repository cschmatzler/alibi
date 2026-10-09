---
title: "Organization"
description: "Multi-tenant organizations with members, roles, invitations, teams, dynamic roles, limits and lifecycle hooks."
---

`OrganizationPlugin` is the building block for B2B apps: users create **organizations**, invite others, assign **roles**, optionally group members into **teams**, and your code authorizes actions against those memberships. The same API serves SaaS workspaces, school classes, GitHub-style orgs and anything else with "who may do what inside this group".

## Schema

```bash
alibi generate --plugins organization -o src/auth_schema.rs
# teams:
alibi generate --plugins organization,organization-teams -o src/auth_schema.rs
# dynamic roles:
alibi generate --plugins organization,organization-dynamic-roles -o src/auth_schema.rs
```

| Flag | Adds |
| --- | --- |
| `organization` | tables `organization`, `member`, `invitation`; `sessions.active_organization_id` |
| `organization-teams` | tables `team`, `team_member`; `sessions.active_team_id`; `invitation.team_id` is part of `organization` |
| `organization-dynamic-roles` | table `organization_role` |

## Application-owned SQLx tables

Bind existing organization, member, and invitation tables with `OrganizationModels`. Each application row derives `sqlx::FromRow` and `alibi::sqlx::SqlxModel`. Use the plugin's Rust field names and `#[sqlx(rename = "…")]` for physical columns; the organization table can have any name.

```rust nocheck
use alibi::sqlx::{OrganizationModels, SqlxStore};
use alibi::plugins::organization::OrganizationConfig;
use alibi::field_policy::{FieldConfig, SessionFields};
use crate::auth_schema::{AppAuthSchema, Event, Membership, Invite};
use crate::ids::{event_id, member_id, invitation_id};

let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool)
    .with_organization_models(OrganizationModels::new::<Event, Membership, Invite>(
        event_id, member_id, invitation_id,
    ));
let mut organization_fields = SessionFields::default();
organization_fields.0.insert(
    "language".into(),
    FieldConfig::new(serde_json::json!({"type":"string"})),
);
let plugin_config = OrganizationConfig {
    organization_fields,
    ..Default::default()
};
```

The three ID factories return `String` IDs. Explicit organization or invitation IDs from trusted creation input are retained. Ordinary creation and invitation acceptance use the corresponding factories.

| Model | Rust fields |
| --- | --- |
| Organization | `id`, `name`, `slug`, `logo`, `metadata`, `created_at`; optional `updated_at`; application fields such as `language` |
| Member | `id`, `organization_id`, `user_id`, `role`, `created_at` |
| Invitation | `id`, `organization_id`, `email`, `role`, `status`, `inviter_id`, `expires_at`, `created_at`; optional `team_id` |

For example, map `organization_id` to `event_id` on both member and invitation. Annotate String IDs and foreign keys backed by PostgreSQL `CHAR(n)` with `#[auth(column_type = "bpchar")]`. Use `chrono::NaiveDateTime` for UTC `timestamp without time zone` columns. Metadata can be nullable JSON or JSON text (`Option<String>`). Imported invitations may have `Option<String>` roles; their null role remains null in output and does not grant a membership role.

An organization model without `updated_at` uses its creation timestamp for that canonical getter and omits the column from writes. An invitation model without `team_id` works with teams disabled. Configure the session model's `active_organization_id` with its own physical rename, such as `active_event_id`.

`organization_fields` applies configured input policies, creation defaults, and adapter transforms to additional fields. They persist through create/update and appear in organization output. Updates retain unrequested application columns. Existing creation policies, role permissions, billing/cleanup hooks, and invitation email callbacks continue to use the native plugin. Application migrations own these tables; the bundled migrator continues to install the bundled schema.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::OrganizationPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};

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

## Core concepts

- **Organization** — `name`, unique `slug`, optional `logo` and JSON `metadata`.
- **Member** — a user's membership with one or more comma-separated **roles**.
- **Invitation** — a pending offer to join with a role (and optionally a team), expiring after 48 hours by default.
- **Active organization** — each session may carry `activeOrganizationId`, so endpoints can omit `organizationId`. Creating an organization or accepting an invitation sets it.
- **Roles and permissions** — default roles `owner`, `admin`, `member`; each action on a resource is granted or not.

The default permission matrix (verified against a running instance):

| Resource → action | `owner` | `admin` | `member` |
| --- | :---: | :---: | :---: |
| `organization`: `update` | ✓ | ✓ | |
| `organization`: `delete` | ✓ | | |
| `member`: `create`, `update`, `delete` | ✓ | ✓ | |
| `invitation`: `create`, `cancel` | ✓ | ✓ | |
| `team`: `create`, `update`, `delete` | ✓ | ✓ | |
| `ac`: `create`, `update`, `delete` | ✓ | ✓ | |
| `ac`: `read` | ✓ | ✓ | ✓ |

The creator of an organization is its `owner` (change that with `creator_role`).

## Endpoints

Paths are relative to `/api/auth`; every endpoint needs a session.

**Organizations**

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/organization/create` | `name`, `slug`, `logo`, `metadata`, `keepCurrentActiveOrganization` |
| `POST` | `/organization/update` | `organizationId`, `data` |
| `POST` | `/organization/delete` | `organizationId` |
| `GET` | `/organization/list` | The user's organizations |
| `GET` | `/organization/get-full-organization` | Organization with members, invitations (and teams); `organizationId` or `organizationSlug` |
| `POST` | `/organization/check-slug` | `{"slug"}` → `ORGANIZATION_SLUG_ALREADY_TAKEN` (400) when taken |
| `POST` | `/organization/set-active` | Select the active organization (`organizationId` or `organizationSlug`; `null` clears) |
| `POST` | `/organization/leave` | Leave an organization (not as the only owner) |

**Members**

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/organization/list-members` | `{"members":[…],"total":n}`; filters, `limit`, `offset`, `sortBy` |
| `GET` | `/organization/get-active-member`, `/organization/get-active-member-role` | The caller's membership / role |
| `POST` | `/organization/update-member-role` | `memberId`, `role` |
| `POST` | `/organization/remove-member` | `memberIdOrEmail` |
| `POST` | `/organization/has-permission` | `{"permissions":{"member":["create"]}}` → `{"success":true,"error":null}` |

**Invitations**

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/organization/invite-member` | `email`, `role`, optional `teamId`, `resend` |
| `POST` | `/organization/accept-invitation` / `reject-invitation` | `invitationId` (for the invited user) |
| `POST` | `/organization/cancel-invitation` | `invitationId` (for managers) |
| `GET` | `/organization/get-invitation`, `list-invitations`, `list-user-invitations` | Read invitations |

**Teams** (when enabled) — `create-team`, `update-team`, `remove-team`, `list-teams`, `list-user-teams`, `list-team-members`, `set-active-team`, `add-team-member`, `remove-team-member`.

**Dynamic roles** (when enabled) — `create-role`, `update-role`, `delete-role`, `get-role`, `list-roles`.

Server-only: **adding a member directly** (`addMember`) is not an HTTP route; see [Server-side operations](#server-side-operations).

### A walkthrough

```bash
# Create an organization (the caller becomes owner)
curl -b cookies.txt http://localhost:3000/api/auth/organization/create \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"Acme","slug":"acme"}'
# {"id":"132715c8-…","name":"Acme","slug":"acme","logo":null,"createdAt":"…","members":[{"id":"37cbfebc-…","userId":"dac58f63-…","organizationId":"132715c8-…","role":"owner","createdAt":"…"}]}

# Invite a colleague
curl -b cookies.txt http://localhost:3000/api/auth/organization/invite-member \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"email":"bob@example.com","role":"member"}'
# {"id":"83b116a7-…","organizationId":"132715c8-…","email":"bob@example.com","role":"member","status":"pending","inviterId":"dac58f63-…","expiresAt":"2026-10-06T10:17:10.832Z","createdAt":"…"}

# Bob accepts (signed in as bob@example.com)
curl -b bob.txt http://localhost:3000/api/auth/organization/accept-invitation \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"invitationId":"83b116a7-…"}'
# {"invitation":{… "status":"accepted"},"member":{… "role":"member"}}
```

Invitations are matched to the signed-in user's **email**: only the invited address can accept or reject. Viewing or listing invitations by email requires a **verified** email (`403 EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION`); by default acceptance by id does not, unless the database uses numeric ids (guessable) or you set `require_email_verification_on_invitation`.

## Deliver invitations

Creating an invitation stores it; sending the email is yours. Provide `send_invitation_email` on the config:

```rust
use async_trait::async_trait;
use alibi::CallbackContext;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationInvitationDelivery, OrganizationInvitationEmailSender,
};
use alibi::plugins::OrganizationPlugin;
use alibi::AuthResult;
use std::sync::Arc;

#[derive(Debug)]
struct InviteMailer;

#[async_trait]
impl OrganizationInvitationEmailSender for InviteMailer {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        _callback: &CallbackContext,
    ) -> AuthResult<()> {
        let to = delivery.email();
        let link = format!("https://app.example.com/accept-invitation/{}", delivery.invitation.id);
        println!(
            "{to}: {} invited you to {} — {link}",
            delivery.user.name.clone().unwrap_or_default(),
            delivery.organization.name,
        );
        Ok(())
    }
}

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        send_invitation_email: Some(Arc::new(InviteMailer)),
        invitation_expires_in: Some(7.0 * 24.0 * 3600.0),
        ..Default::default()
    })
}
```

`OrganizationInvitationDelivery` has `invitation`, `organization`, `inviter` (the member) and `user` (the inviting user). Delivery errors are logged and do not fail the invitation (the `after_create_invitation` hook still runs); run delivery in the [background](/concepts/notifications/#deliver-in-the-background) if you configured a handler.

## Configuration

Builder methods work for scalar options; the rest are fields of `OrganizationConfig` (use `OrganizationPlugin::with_config`).

| Option | Default | Effect |
| --- | --- | --- |
| `allow_user_to_create_organization` | `true` | Whether users may create organizations (also see `creation_policy`) |
| `organization_limit` | none | Max organizations per user (`f64`; JavaScript number semantics) |
| `creator_role` | `"owner"` | Role of the creator |
| `membership_limit` | `Fixed(100.0)` | `MembershipLimit::Fixed(n)` or `Resolver(…)` — max members per organization |
| `invitation_limit` | `Fixed(100.0)` | `InvitationLimit` — max pending invitations |
| `invitation_expires_in` | `172800.0` (48 h) | Lifetime in seconds |
| `cancel_pending_invitations_on_reinvite` | `false` | Cancel the earlier pending invitation when re-inviting |
| `disable_organization_deletion` | `false` | Remove deletion (`404 ORGANIZATION_DELETION_DISABLED`) |
| `require_email_verification_on_invitation` | none | Force verified email to view/accept/reject by id |
| `roles` | built-in | `HashMap<String, RolePermissions>` of static roles; `Some(empty)` grants nothing |
| `access_control` | none | Statements (`resource → actions`) required by dynamic roles |
| `teams` | disabled | `TeamsConfig` |
| `dynamic_access_control` | disabled | `DynamicAccessControlConfig` |
| `creation_policy` | none | `OrganizationCreationPolicy` — `allow_creation(user)` / `limit_reached(user)` per request |
| `send_invitation_email` | none | `OrganizationInvitationEmailSender` |

### Custom roles

Static roles map to `RolePermissions` (fields `organization`, `member`, `invitation`, `team`, `ac`, `api_key` and a flattened map for your own resources):

```rust
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, RolePermissions};
use std::collections::HashMap;

fn organization() -> OrganizationPlugin {
    let roles = HashMap::from([
        (
            "owner".to_owned(),
            RolePermissions {
                organization: vec!["update".into(), "delete".into()],
                member: vec!["create".into(), "update".into(), "delete".into()],
                invitation: vec!["create".into(), "cancel".into()],
                ..Default::default()
            },
        ),
        (
            "billing".to_owned(),
            RolePermissions { organization: vec!["update".into()], ..Default::default() },
        ),
        ("member".to_owned(), RolePermissions::default()),
    ]);
    OrganizationPlugin::with_config(OrganizationConfig {
        roles: Some(roles),
        creator_role: "owner".into(),
        ..Default::default()
    })
}
```

A user may hold several roles (comma-separated); a request needs **one assigned role** that satisfies all requested actions. Defining `roles` replaces the defaults, so list `owner`, `admin` and `member` again if you still want them.

### Limits and creation policy

```rust
use async_trait::async_trait;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    MembershipLimit, OrganizationConfig, OrganizationCreationPolicy,
};
use alibi::wire::UserView;
use alibi::AuthResult;
use std::sync::Arc;

#[derive(Debug)]
struct OnlyVerified;

#[async_trait]
impl OrganizationCreationPolicy for OnlyVerified {
    // `Some(false)` denies creation; `None` defers to `allow_user_to_create_organization`.
    async fn allow_creation(&self, user: &UserView) -> AuthResult<Option<bool>> {
        Ok(Some(user.email_verified))
    }
}

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        organization_limit: Some(3.0),
        membership_limit: Some(MembershipLimit::Fixed(25.0)),
        creation_policy: Some(Arc::new(OnlyVerified)),
        ..Default::default()
    })
}
```

## Teams

Teams group members inside an organization (for example "Backend", "Support"). Enable them on the config and generate `organization-teams`:

```rust
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig};

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            create_default_team: true,          // every new organization gets a default team
            maximum_teams: Some(10.0),
            maximum_members_per_team: Some(50.0),
            allow_removing_all_teams: false,
            ..Default::default()
        },
        ..Default::default()
    })
}
```

| `TeamsConfig` field | Default | Effect |
| --- | --- | --- |
| `enabled` | `false` | Register team endpoints |
| `create_default_team` | `true` | Create a team named after the organization at creation |
| `allow_removing_all_teams` | `false` | Allow deleting an organization's last team |
| `maximum_teams`, `maximum_members_per_team` | none | Quotas (`f64`; `0`/`NaN` disable, negative denies) |
| `limit_resolver` | none | `OrganizationLimitResolver`: compute quotas per request |
| `hooks` | none | `OrganizationTeamHooks`: `before_create`/`after_create`, update, delete, add/remove member |
| `default_team_factory` | none | `DefaultTeamFactory`: customize the default team |

```bash
curl -b cookies.txt http://localhost:3000/api/auth/organization/create-team \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"Backend","organizationId":"132715c8-…"}'
# {"id":"9ca2139e-…","name":"Backend","organizationId":"132715c8-…","createdAt":"…","updatedAt":"…"}
```

Invitations can carry a `teamId`; accepting adds the user to that team too. `set-active-team` stores `activeTeamId` on the session.

## Dynamic roles

Static roles live in code. **Dynamic roles** let organization admins define custom roles at runtime and store them in `organization_role`. Enable them *and* declare the permission statements roles may reference — without `access_control` the endpoints answer `501 MISSING_AC_INSTANCE`:

```rust
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, default_organization_statements,
};

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        access_control: Some(default_organization_statements()),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: true,
            maximum_roles_per_organization: Some(20.0),
            limit_resolver: None,
        },
        ..Default::default()
    })
}
```

`default_organization_statements()` is `organization: [update, delete]`, `member: [create, update, delete]`, `invitation: [create, cancel]`, `team: [create, update, delete]`, `ac: [create, read, update, delete]`; extend the map with your own resources and actions.

```bash
curl -b owner.txt http://localhost:3000/api/auth/organization/create-role \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"role":"billing","permission":{"organization":["update"]},"organizationId":"08a6484e-…"}'
# {"success":true,"roleData":{"id":"9f6e77cd-…","organizationId":"08a6484e-…","role":"billing","permission":{"organization":["update"]},"createdAt":"…","updatedAt":null},"statements":{"organization":["update"]}}
```

The role can immediately be used in `invite-member` / `update-member-role`. A caller can only grant permissions they hold themselves, so an admin cannot escalate beyond their own authority, and creating roles needs the `ac:create` permission.

## Lifecycle hooks

Each phase of the organization lifecycle has an awaited, typed hook trait you implement and place on the config. Hooks run in the order the TypeScript server runs them; **there is no wrapping transaction**, so an error keeps earlier writes — keep hooks idempotent.

| Config field | Trait | Phases |
| --- | --- | --- |
| `creation_hooks` | `OrganizationCreationHooks` | `before_create` (may patch name/slug/logo/metadata), `before_add_member`, `after_add_member`, `after_create` |
| `update_hooks` | `OrganizationUpdateHooks` | before / after update |
| `deletion_hooks` | `OrganizationDeletionHooks` | before / after delete |
| `member_addition_hooks` | `OrganizationMemberAdditionHooks` | server-only admission |
| `member_role_hooks` | `OrganizationMemberRoleHooks` | before / after role change |
| `member_removal_hooks` | `OrganizationMemberRemovalHooks` | before / after removal |
| `invitation_hooks` | `OrganizationInvitationHooks` | before/after create, reject, cancel |
| `invitation_acceptance_hooks` | `OrganizationInvitationAcceptanceHooks` | around the atomic claim-and-join |
| `teams.hooks` | `OrganizationTeamHooks` | team create/update/delete, add/remove member |

```rust
use async_trait::async_trait;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationCreatePatch, OrganizationCreatedContext,
    OrganizationCreationHooks, OrganizationDraftContext,
};
use alibi::AuthResult;
use std::sync::Arc;

#[derive(Debug)]
struct Provisioning;

#[async_trait]
impl OrganizationCreationHooks for Provisioning {
    // Force lowercase slugs before the row is written.
    async fn before_create(
        &self,
        context: &OrganizationDraftContext,
    ) -> AuthResult<Option<OrganizationCreatePatch>> {
        Ok(Some(OrganizationCreatePatch {
            slug: Some(context.organization.slug.to_lowercase()),
            ..Default::default()
        }))
    }

    async fn after_create(&self, context: &OrganizationCreatedContext) -> AuthResult<()> {
        println!("provision workspace for {} ({})", context.organization.name, context.organization.id);
        Ok(())
    }
}

fn organization() -> OrganizationPlugin {
    OrganizationPlugin::with_config(OrganizationConfig {
        creation_hooks: Some(Arc::new(Provisioning)),
        ..Default::default()
    })
}
```

Hook contexts carry immutable snapshots of the authority (user, session, headers) and the persisted rows. Hook errors that are intentional API errors (`AuthError::forbidden(..)`) are returned verbatim; other failures become an empty `500`.

## Server-side operations

Some operations are only available to trusted server code — they bypass the "caller must be a member" checks. Use [`dispatch_endpoint`](/guides/server-side-calls/):

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::BetterAuth;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::types::CreateOrganizationRequest;

async fn create_for(
    auth: &BetterAuth<AppAuthSchema>,
    user_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = CreateOrganizationRequest {
        additional_fields: Default::default(),
        name: "Acme".into(),
        slug: "acme".into(),
        logo: None,
        metadata: None,
        keep_current_active_organization: None,
    };
    let created = auth
        .dispatch_endpoint(
            // The explicit user id is a trusted server option (HTTP always uses the session user).
            OrganizationPlugin::create_endpoint(&body, Some(user_id))?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    Ok(format!("{created:?}"))
}
```

`OrganizationPlugin::add_member_endpoint` adds a user to an organization without an invitation (admission hooks still run), `remove_member_endpoint` and `delete_endpoint` mirror the HTTP operations, and the instance methods `add_member_with_headers`, `remove_member_with_headers`, `delete_organization_with_headers` and `create_organization_for_user` are the lower-level equivalents on a plugin you hold.

## Application-side access control

`alibi::plugins::access` provides the same resource/action model for **your own** authorization checks, independent of the HTTP API. Create the access-control instance with your statements and derive roles from it:

```rust
use alibi::plugins::access::{ActionRequest, Connector, create_access_control};

fn authorize_report_access() -> bool {
    let ac = create_access_control(
        [("report".into(), vec!["read".into(), "publish".into()])].into(),
    );
    let reviewer = ac.new_role([("report".into(), vec!["read".into()])].into());

    // OR within one resource: read OR publish is enough.
    let request = [(
        "report".into(),
        ActionRequest::Rule {
            actions: vec!["read".into(), "publish".into()],
            connector: Connector::Or,
        },
    )]
    .into();
    reviewer.authorize(&request).success()
}
```

Semantics:

- A plain action list — and `Role::authorize` across resources — uses **AND**.
- A resource rule can choose `Connector::Or` for its actions; `authorize_with_connector` chooses AND or OR **across resources**.
- Empty requests and empty action lists deny; resource and action names are case sensitive.
- AND reports the first rejection (`unauthorized to access resource "report"`), in insertion order.
- Roles do not merge: authorization evaluates one role's grants at a time.

These are typed utilities. They do not change the organization HTTP permission schema — HTTP requests accept action arrays and require a single assigned role to satisfy the whole request. Rust declarations do not enforce TypeScript's compile-time subset checks: grants are plain string lists.

## Security notes

- Authorization is checked **per operation** on the server; the active organization is a convenience, not a permission.
- Members can only be invited with roles the inviter may grant; dynamic roles follow the same no-escalation rule.
- Invitation acceptance atomically claims the invitation and creates the membership, so a race cannot admit a user twice.
- Organization-owned [API keys](/plugins/api-key/#several-configurations-and-organization-keys) require the `apiKey` permission in that organization (only the creator role has it by default).

## Frontend

See the official [Organization guide](https://www.better-auth.com/docs/plugins/organization).

## Typed native endpoints

Call organization operations in-process through `BetterAuth::dispatch_endpoint`.
The installed plugin, authentication, authorization, organization callbacks, and
builder endpoint hooks all participate. Input is validated after before-hook
patches. Supply genuine credentials with `EndpointOptions`; an optional original
HTTP request remains distinct from the logical body/query. Native calls do not
construct an HTTP request or flatten numeric query fields into strings.

```rust
use alibi::plugins::organization::{OrganizationPlugin, types::{
    SetActiveOrganizationRequest, NullableStringField,
}};
use alibi::endpoint::EndpointOptions;

let output = auth.dispatch_endpoint(
    OrganizationPlugin::set_active_endpoint(&SetActiveOrganizationRequest {
        organization_id: NullableStringField::Value(organization_id),
        organization_slug: None,
    })?,
    EndpointOptions {
        headers: Some(credentials),
        ..Default::default()
    },
).await?;
let organization = output.decode()?;
// Publish every output.headers().get_all("set-cookie") value separately.
```

Successful outputs expose `decode()`, `headers()`, and `status()`. Endpoint API
errors retain their `AuthError`, accumulated headers, and any explicit error
body in `EndpointError`. Ordinary storage and application callback failures
propagate through the native lifecycle. After hooks can replace response values;
`decode()` reports a type error if the replacement has a different shape.

Every organization operation has an `OrganizationPlugin` constructor. Types are
public in `organization::types`; constructors encode body or query as appropriate:

| Operations | Constructors (each ends in `_endpoint`) |
| --- | --- |
| Organizations | `create`, `update`, `delete`, `list_organizations`, `get_organization`, `get_full_organization`, `check_slug`, `set_active`, `leave` |
| Members | `add_member`, `remove_member`, `update_member_role`, `list_members`, `get_active_member`, `get_active_member_role`, `has_permission` |
| Invitations | `invite_member`, `get_invitation`, `list_invitations`, `list_user_invitations`, `accept_invitation`, `reject_invitation`, `cancel_invitation` |
| Teams | `create_team`, `update_team`, `remove_team`, `set_active_team`, `list_teams`, `list_user_teams`, `list_team_members`, `add_team_member`, `remove_team_member` |
| Dynamic roles | `create_role`, `update_role`, `delete_role`, `get_role`, `list_roles` |

Team and dynamic role operations require their respective plugin configuration
features. The existing server-only `add_member_endpoint` and explicit user option
of `create_endpoint` retain their privileged authority. `list_user_invitations_endpoint`
accepts an email selector for trusted native calls without an HTTP request;
request-backed calls must use the authenticated session email.

Use `NullableStringField::Missing` to omit an active organization/team selector,
`Null` to clear it, and `Value` to select it. Optional update fields are omitted
when absent; `UpdateOrganizationData::logo = Some(None)` explicitly clears a logo.
