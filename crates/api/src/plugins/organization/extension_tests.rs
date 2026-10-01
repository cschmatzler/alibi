use super::*;
use crate::plugins::test_helpers::{create_test_config, create_user_and_session};
use better_auth_core::types::{CreateMember, CreateTeam, Team, TeamMember};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthError, AuthInitContext, AuthSession, CreateUser};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use chrono::Duration;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug)]
struct RequestTeamLimits;

#[async_trait]
impl OrganizationLimitResolver for RequestTeamLimits {
    async fn maximum_teams(
        &self,
        context: &extensions::TeamLimitContext,
    ) -> AuthResult<Option<usize>> {
        let authenticated = context
            .user
            .as_ref()
            .zip(context.session.as_ref())
            .is_some_and(|(user, session)| {
                user.id == session.user_id && user.name.as_deref() == Some("limit-owner")
            });
        let expanded = context
            .request
            .as_ref()
            .and_then(|request| request.header("x-team-policy").map(String::as_str))
            == Some("expanded");
        Ok(Some(if authenticated && expanded { 3 } else { 1 }))
    }

    async fn maximum_team_members(
        &self,
        context: &extensions::TeamLimitContext,
    ) -> AuthResult<Option<usize>> {
        let authenticated = context
            .user
            .as_ref()
            .zip(context.session.as_ref())
            .is_some_and(|(user, session)| {
                user.id == session.user_id && user.name.as_deref() == Some("limit-owner")
            });
        Ok(Some(usize::from(
            authenticated && context.team_id.is_some(),
        )))
    }
}

#[derive(Debug)]
struct LifecycleHooks {
    events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl LifecycleHooks {
    fn record(&self, name: &str) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_error| AuthError::internal("Hook event lock poisoned"))?
            .push(name.to_owned());
        Ok(())
    }
}

#[async_trait]
impl OrganizationTeamHooks for LifecycleHooks {
    async fn before_create(
        &self,
        data: &mut CreateTeam,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("before-create")?;
        data.name = format!("hook:{}", data.name);
        Ok(())
    }
    async fn after_create(
        &self,
        _team: &Team,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("after-create")
    }
    async fn before_update(
        &self,
        _team: &Team,
        update: &mut better_auth_core::types::UpdateTeam,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("before-update")?;
        update.name = update.name.take().map(|name| format!("updated:{name}"));
        Ok(())
    }
    async fn after_update(
        &self,
        _team: &Team,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("after-update")
    }
    async fn before_add_member(
        &self,
        _team: &Team,
        user: &UserView,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("before-add")?;
        if user.email.as_deref() == Some("hook-denied@example.com") {
            return Err(AuthError::forbidden("Callback refused team membership"));
        }
        Ok(())
    }
    async fn after_add_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("after-add")
    }
    async fn before_remove_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("before-remove")
    }
    async fn after_remove_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("after-remove")
    }
    async fn before_delete(
        &self,
        _team: &Team,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("before-delete")
    }
    async fn after_delete(
        &self,
        _team: &Team,
        _context: &extensions::TeamHookContext,
    ) -> AuthResult<()> {
        self.record("after-delete")
    }
}

#[derive(Debug)]
struct CustomDefaultTeam;

#[async_trait]
impl DefaultTeamFactory for CustomDefaultTeam {
    async fn create(
        &self,
        organization: &better_auth_core::types::Organization,
        context: &DefaultTeamContext,
        store: &dyn better_auth_core::store::TeamStore,
    ) -> AuthResult<Option<Team>> {
        let request = context.request.as_ref().ok_or_else(|| {
            AuthError::bad_request("Default team callback did not receive the organization request")
        })?;
        if context
            .session
            .as_ref()
            .map(|session| session.user_id.as_str())
            != Some(context.user.id.as_str())
        {
            return Err(AuthError::bad_request(
                "Factory did not receive the authenticated principal",
            ));
        }
        if context.config.base_path != "/api/auth" {
            return Err(AuthError::bad_request(
                "Factory did not receive the configured base path",
            ));
        }
        if request.path() != "/organization/create" {
            return Err(AuthError::bad_request("Unexpected default team request"));
        }
        store
            .create_team(CreateTeam {
                name: format!("Factory:{}", organization.name),
                organization_id: organization.id.clone(),
                updated_at: None,
            })
            .await
            .map(Some)
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn asynchronous_team_limits_use_the_actual_request_and_session_principal() -> TestResult {
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            maximum_teams: Some(99),
            maximum_members_per_team: Some(99),
            limit_resolver: Some(std::sync::Arc::new(RequestTeamLimits)),
            ..Default::default()
        },
        ..Default::default()
    });
    let ctx = context(&plugin).await?;
    let (_, owner_session) = actor(&ctx, "limit-owner").await;
    let created = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Limited","slug":"native-async-limits"})),
        &[],
    )
    .await?;
    let organization: Value = body(&created)?;
    let organization_id = id(&organization)?;
    assert_eq!(ctx.database.list_teams(organization_id).await?.len(), 1);
    for (name, expanded, expected) in [
        ("Default denied", false, 400),
        ("Expanded first", true, 200),
        ("Expanded second", true, 200),
        ("Expanded full", true, 400),
    ] {
        let mut request = AuthRequest::new(HttpMethod::Post, "/organization/create-team");
        let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
            &owner_session.token,
            &ctx.config,
        );
        request.headers.insert(
            "cookie".to_owned(),
            cookie
                .split(';')
                .next()
                .ok_or("Session cookie pair missing")?
                .to_owned(),
        );
        if expanded {
            request
                .headers
                .insert("x-team-policy".to_owned(), "expanded".to_owned());
        }
        request.body = Some(serde_json::to_vec(
            &json!({"organizationId":organization_id,"name":name}),
        )?);
        let response = match plugin.on_request(&request, &ctx).await {
            Ok(Some(response)) => response,
            Ok(None) => return Err("Team route was not handled".into()),
            Err(error) => error.to_auth_response(),
        };
        assert_eq!(response.status, expected);
        if expected == 400 {
            assert_error(
                &response,
                400,
                "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
            )?;
        }
    }
    let teams = ctx.database.list_teams(organization_id).await?;
    assert_eq!(teams.len(), 3);
    let team = teams
        .iter()
        .find(|team| team.name == "Expanded first")
        .ok_or("Allowed team was not persisted")?;
    let (first, _) = actor(&ctx, "limit-first").await;
    let (second, _) = actor(&ctx, "limit-second").await;
    for user in [&first, &second] {
        ctx.database
            .create_member(CreateMember {
                organization_id: organization_id.to_owned(),
                user_id: user.id.clone(),
                role: "member".to_owned(),
            })
            .await?;
    }
    let added = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/add-team-member",
        Some(json!({"organizationId":organization_id,"teamId":team.id,"userId":first.id})),
        &[],
    )
    .await?;
    assert_eq!(added.status, 200);
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"organizationId":organization_id,"teamId":team.id,"userId":second.id})),
            &[],
        )
        .await?,
        403,
        "TEAM_MEMBER_LIMIT_REACHED",
    )?;
    let members = ctx.database.list_team_members(&team.id).await?;
    assert_eq!(members.len(), 1);
    assert_eq!(
        (members)
            .first()
            .expect("fixture contains the requested index")
            .user_id,
        first.id
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn team_member_requests_coerce_custom_user_ids_and_keep_permission_and_tenant_guards()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = context(&plugin).await?;
    let (owner, owner_session) = actor(&ctx, "coercion-owner").await;
    let organization = ctx
        .database
        .create_organization(better_auth_core::types::CreateOrganization::new(
            "Custom IDs",
            "native-coercion",
        ))
        .await?;
    ctx.database
        .create_member(CreateMember {
            organization_id: organization.id.clone(),
            user_id: owner.id.clone(),
            role: "owner".to_owned(),
        })
        .await?;
    let team = plugin
        .create_team(
            &ctx,
            CreateTeam {
                organization_id: organization.id.clone(),
                name: "Custom ID team".to_owned(),
                updated_at: None,
            },
        )
        .await?;
    let other_org = ctx
        .database
        .create_organization(better_auth_core::types::CreateOrganization::new(
            "Other tenant",
            "native-coercion-other",
        ))
        .await?;
    let other_team = plugin
        .create_team(
            &ctx,
            CreateTeam {
                organization_id: other_org.id,
                name: "Other team".to_owned(),
                updated_at: None,
            },
        )
        .await?;
    for (index, (input, expected_id)) in [
        (Some(json!(42)), "42"),
        (Some(json!(1.0)), "1"),
        (Some(json!(1e21)), "1e+21"),
        (Some(json!(9_007_199_254_740_993_u64)), "9007199254740992"),
        (Some(json!(true)), "true"),
        (Some(Value::Null), "null"),
        (
            Some(json!(["42", null, {"key":"value"}])),
            "42,,[object Object]",
        ),
        (Some(json!({"key":"value"})), "[object Object]"),
        (None, "undefined"),
    ]
    .into_iter()
    .enumerate()
    {
        let (target, target_session) = create_user_and_session(
            &ctx,
            CreateUser {
                id: Some(expected_id.to_owned()),
                email: Some(format!("coercion-{index}@example.com")),
                ..Default::default()
            },
            Duration::hours(1),
        )
        .await;
        ctx.database
            .create_member(CreateMember {
                organization_id: organization.id.clone(),
                user_id: target.id.clone(),
                role: "member".to_owned(),
            })
            .await?;
        let mut request = json!({"organizationId":organization.id,"teamId":team.id});
        if let Some(input) = input {
            drop(
                request
                    .as_object_mut()
                    .expect("request is an object")
                    .insert("userId".to_owned(), input),
            );
        }
        let added = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(request.clone()),
            &[],
        )
        .await?;
        assert_eq!(added.status, 200, "add-member must coerce {expected_id}");
        let added: TeamMember = body(&added)?;
        assert_eq!(added.user_id, expected_id);
        let persisted = ctx.database.list_team_members(&team.id).await?;
        assert_eq!(persisted.len(), 1);
        assert_eq!(
            (persisted)
                .first()
                .expect("fixture contains the requested index")
                .id,
            added.id
        );
        assert_eq!(
            (persisted)
                .first()
                .expect("fixture contains the requested index")
                .user_id,
            expected_id
        );
        if expected_id == "42" {
            assert_error(
                &call(
                    &plugin,
                    &ctx,
                    Some(&target_session.token),
                    HttpMethod::Post,
                    "/organization/add-team-member",
                    Some(request.clone()),
                    &[],
                )
                .await?,
                403,
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
            )?;
            assert_error(
                &call(
                    &plugin,
                    &ctx,
                    Some(&target_session.token),
                    HttpMethod::Post,
                    "/organization/remove-team-member",
                    Some(request.clone()),
                    &[],
                )
                .await?,
                403,
                "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
            )?;
            let mut wrong_tenant = request.clone();
            drop(
                wrong_tenant
                    .as_object_mut()
                    .expect("request is an object")
                    .insert("teamId".to_owned(), json!(other_team.id)),
            );
            assert_error(
                &call(
                    &plugin,
                    &ctx,
                    Some(&owner_session.token),
                    HttpMethod::Post,
                    "/organization/add-team-member",
                    Some(wrong_tenant),
                    &[],
                )
                .await?,
                400,
                "TEAM_NOT_FOUND",
            )?;
            assert_eq!(ctx.database.list_team_members(&team.id).await?.len(), 1);
            assert!(
                ctx.database
                    .list_team_members(&other_team.id)
                    .await?
                    .is_empty()
            );
        }
        let removed = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/remove-team-member",
            Some(request),
            &[],
        )
        .await?;
        assert_eq!(removed.status, 200);
        assert!(ctx.database.list_team_members(&team.id).await?.is_empty());
    }
    Ok(())
}

fn configuration() -> OrganizationConfig {
    OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn context(plugin: &OrganizationPlugin) -> AuthResult<AuthContext<BundledSchema>> {
    configured_context(plugin, create_test_config()).await
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn configured_context(
    plugin: &OrganizationPlugin,
    config: better_auth_core::AuthConfig,
) -> AuthResult<AuthContext<BundledSchema>> {
    configured_context_with_connection(plugin, config)
        .await
        .map(|(context, _)| context)
}

async fn configured_context_with_connection(
    plugin: &OrganizationPlugin,
    config: better_auth_core::AuthConfig,
) -> AuthResult<(
    AuthContext<BundledSchema>,
    better_auth_seaorm::DatabaseConnection,
)> {
    let database = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let config = std::sync::Arc::new(config);
    let store = std::sync::Arc::new(better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(
        std::sync::Arc::clone(&config),
        database.clone(),
    ));
    let mut ctx = AuthContext::new(config, store);
    let mut init = AuthInitContext::new(
        std::sync::Arc::clone(&ctx.config),
        std::sync::Arc::clone(&ctx.database),
    );
    plugin.on_init(&mut init).await?;
    let parts = init.into_parts();
    ctx.metadata = parts.metadata;
    Ok((ctx, database))
}

pub(super) async fn actor(ctx: &AuthContext<BundledSchema>, name: &str) -> (UserView, SessionView) {
    create_user_and_session(
        ctx,
        CreateUser {
            email: Some(format!("{name}@example.com")),
            name: Some(name.to_owned()),
            email_verified: Some(true),
            ..Default::default()
        },
        Duration::hours(1),
    )
    .await
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn call(
    plugin: &OrganizationPlugin,
    ctx: &AuthContext<BundledSchema>,
    token: Option<&str>,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    query: &[(&str, &str)],
) -> AuthResult<AuthResponse> {
    let mut req = AuthRequest::new(method, path);
    if let Some(token) = token {
        let cookie =
            better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config);
        let pair = cookie
            .split(';')
            .next()
            .ok_or_else(|| AuthError::internal("Session cookie missing pair"))?;
        drop(req.headers.insert("cookie".to_owned(), pair.to_owned()));
    }
    for (key, value) in query {
        drop(req.query.insert((*key).to_owned(), (*value).to_owned()));
    }
    if let Some(body) = body {
        req.body = Some(serde_json::to_vec(&body)?);
        drop(
            req.headers
                .insert("content-type".to_owned(), "application/json".to_owned()),
        );
    }
    match plugin.on_request(&req, ctx).await {
        Ok(Some(response)) => Ok(response),
        Ok(None) => Err(AuthError::internal("Organization route was not handled")),
        Err(error) => Ok(error.to_auth_response()),
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn body<T: DeserializeOwned>(response: &AuthResponse) -> Result<T, serde_json::Error> {
    serde_json::from_slice(&response.body)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn id(value: &Value) -> Result<&str, std::io::Error> {
    value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("Response is missing ID"))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn assert_error(response: &AuthResponse, status: u16, code: &str) -> TestResult {
    assert_eq!(response.status, status);
    assert_eq!(
        body::<Value>(response)?.get("code").and_then(Value::as_str),
        Some(code)
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn team_routes_enforce_principal_membership_scope_and_persist_session_changes() -> TestResult
{
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = context(&plugin).await?;
    let (owner, owner_session) = actor(&ctx, "team-owner").await;
    let (member, member_session) = actor(&ctx, "team-member").await;
    let (stranger, stranger_session) = actor(&ctx, "team-stranger").await;
    let created = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Teams", "slug":"native-teams"})),
        &[],
    )
    .await?;
    assert_eq!(created.status, 200);
    let organization: Value = body(&created)?;
    let org_id = id(&organization)?;
    assert!(organization.get("teams").is_none());
    let defaults = ctx.database.list_teams(org_id).await?;
    let default_team = defaults
        .first()
        .ok_or_else(|| std::io::Error::other("Default team not created"))?;
    assert_eq!(defaults.len(), 1);
    assert_eq!(default_team.name, "Teams");
    assert!(default_team.updated_at.is_none());
    assert!(
        ctx.database
            .get_team_member(&default_team.id, &owner.id)
            .await?
            .is_some()
    );
    let persisted = ctx
        .database
        .get_session(&owner_session.token)
        .await?
        .ok_or_else(|| std::io::Error::other("Owner session missing"))?;
    assert_eq!(persisted.active_team_id(), Some(default_team.id.as_str()));
    drop(
        ctx.database
            .create_member(CreateMember::new(org_id, &member.id, "member"))
            .await?,
    );
    drop(
        ctx.database
            .update_session_active_organization(&member_session.token, Some(org_id))
            .await?,
    );

    assert_error(
        &call(
            &plugin,
            &ctx,
            None,
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Unauthenticated", "organizationId":org_id})),
            &[],
        )
        .await?,
        401,
        "UNAUTHORIZED",
    )?;
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Forbidden"})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    )?;
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&stranger_session.token),
            HttpMethod::Get,
            "/organization/list-teams",
            None,
            &[("organizationId", org_id)],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
    )?;

    let created_team = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/create-team",
        Some(json!({"name":"Engineering"})),
        &[],
    )
    .await?;
    assert_eq!(created_team.status, 200);
    let team: Team = body(&created_team)?;
    assert_eq!(team.organization_id, org_id);
    assert_eq!(team.updated_at, Some(team.created_at));
    let updated = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/update-team",
        Some(json!({"teamId":team.id,"data":{"name":"Platform"}})),
        &[],
    )
    .await?;
    assert_eq!(updated.status, 200);
    assert_eq!(body::<Team>(&updated)?.name, "Platform");
    assert_eq!(
        ctx.database
            .get_team(Some(org_id), &team.id)
            .await?
            .map(|row| row.name),
        Some("Platform".to_owned())
    );
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":stranger.id})),
            &[],
        )
        .await?,
        400,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    )?;
    let added = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/add-team-member",
        Some(json!({"teamId":team.id,"userId":member.id})),
        &[],
    )
    .await?;
    assert_eq!(added.status, 200);
    let membership: TeamMember = body(&added)?;
    assert_eq!(membership.user_id, member.id);
    assert_eq!(membership.team_id, team.id);
    let active = call(
        &plugin,
        &ctx,
        Some(&member_session.token),
        HttpMethod::Post,
        "/organization/set-active-team",
        Some(json!({"teamId":team.id})),
        &[],
    )
    .await?;
    assert_eq!(active.status, 200);
    assert!(active.headers.get("set-cookie").is_some());
    let persisted_2 = ctx
        .database
        .get_session(&member_session.token)
        .await?
        .ok_or_else(|| std::io::Error::other("Member session missing"))?;
    assert_eq!(persisted_2.active_team_id(), Some(team.id.as_str()));
    assert_eq!(persisted_2.token(), member_session.token);
    let listed = call(
        &plugin,
        &ctx,
        Some(&member_session.token),
        HttpMethod::Get,
        "/organization/list-team-members",
        None,
        &[],
    )
    .await?;
    assert_eq!(listed.status, 200);
    let rows: Vec<TeamMember> = body(&listed)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows.first().map(|row| row.id.as_str()),
        Some(membership.id.as_str())
    );
    let own_teams = call(
        &plugin,
        &ctx,
        Some(&member_session.token),
        HttpMethod::Get,
        "/organization/list-user-teams",
        None,
        &[],
    )
    .await?;
    assert_eq!(body::<Vec<Team>>(&own_teams)?.len(), 1);
    let other_teams = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Get,
        "/organization/list-user-teams",
        None,
        &[("userId", &member.id), ("organizationId", org_id)],
    )
    .await?;
    assert_eq!(
        body::<Vec<Team>>(&other_teams)?
            .first()
            .map(|row| row.id.as_str()),
        Some(team.id.as_str())
    );
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Get,
            "/organization/list-user-teams",
            None,
            &[("userId", &owner.id), ("organizationId", org_id)],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    )?;
    let clear = call(
        &plugin,
        &ctx,
        Some(&member_session.token),
        HttpMethod::Post,
        "/organization/set-active-team",
        Some(json!({"teamId":null})),
        &[],
    )
    .await?;
    assert_eq!(body::<Value>(&clear)?, Value::Null);
    assert!(
        ctx.database
            .get_session(&member_session.token)
            .await?
            .is_some_and(|row| row.active_team_id().is_none())
    );
    let removed = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/remove-team-member",
        Some(json!({"teamId":team.id,"userId":member.id})),
        &[],
    )
    .await?;
    assert_eq!(removed.status, 200);
    assert!(
        ctx.database
            .get_team_member(&team.id, &member.id)
            .await?
            .is_none()
    );
    let deleted = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/remove-team",
        Some(json!({"teamId":team.id})),
        &[],
    )
    .await?;
    assert_eq!(deleted.status, 200);
    assert!(
        ctx.database
            .get_team(Some(org_id), &team.id)
            .await?
            .is_none()
    );
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/remove-team",
            Some(json!({"teamId":default_team.id})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
    )?;
    drop(
        call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/set-active-team",
            Some(json!({"teamId":null})),
            &[],
        )
        .await?,
    );
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/remove-team",
            Some(json!({"teamId":default_team.id})),
            &[],
        )
        .await?,
        400,
        "UNABLE_TO_REMOVE_LAST_TEAM",
    )?;
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn lifecycle_hooks_change_persisted_team_data_and_veto_membership_before_writing()
-> TestResult {
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            hooks: Some(std::sync::Arc::new(LifecycleHooks {
                events: std::sync::Arc::clone(&events),
            })),
            ..Default::default()
        },
        ..Default::default()
    });
    let ctx = context(&plugin).await?;
    let (owner, session) = actor(&ctx, "hook-owner").await;
    let (denied, _) = actor(&ctx, "hook-denied").await;
    let created = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Callbacks","slug":"native-callbacks"})),
        &[],
    )
    .await?;
    let created: Value = body(&created)?;
    let org_id = id(&created)?;
    assert_eq!(
        ctx.database
            .list_teams(org_id)
            .await?
            .first()
            .map(|team| team.name.as_str()),
        Some("hook:Callbacks")
    );
    drop(
        ctx.database
            .create_member(CreateMember::new(org_id, &denied.id, "member"))
            .await?,
    );
    let created_2 = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create-team",
        Some(json!({"name":"Custom"})),
        &[],
    )
    .await?;
    let team: Team = body(&created_2)?;
    assert_eq!(team.name, "hook:Custom");
    let updated = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/update-team",
        Some(json!({"teamId":team.id,"data":{"name":"Changed"}})),
        &[],
    )
    .await?;
    assert_eq!(body::<Team>(&updated)?.name, "updated:Changed");
    assert_eq!(
        ctx.database
            .get_team(Some(org_id), &team.id)
            .await?
            .map(|team| team.name),
        Some("updated:Changed".to_owned())
    );
    let refused = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/add-team-member",
        Some(json!({"teamId":team.id,"userId":denied.id})),
        &[],
    )
    .await?;
    assert_eq!(refused.status, 403);
    assert!(
        ctx.database
            .get_team_member(&team.id, &denied.id)
            .await?
            .is_none()
    );
    let admitted = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/add-team-member",
        Some(json!({"teamId":team.id,"userId":owner.id})),
        &[],
    )
    .await?;
    assert_eq!(admitted.status, 200);
    let removed = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/remove-team-member",
        Some(json!({"teamId":team.id,"userId":owner.id})),
        &[],
    )
    .await?;
    assert_eq!(removed.status, 200);
    let deleted = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/remove-team",
        Some(json!({"teamId":team.id})),
        &[],
    )
    .await?;
    assert_eq!(deleted.status, 200);
    assert!(ctx.database.get_team(None, &team.id).await?.is_none());
    assert_eq!(
        *events
            .lock()
            .map_err(|_error| std::io::Error::other("Hook event lock poisoned"))?,
        vec![
            "before-create",
            "after-create",
            "before-create",
            "after-create",
            "before-update",
            "after-update",
            "before-add",
            "before-add",
            "after-add",
            "before-remove",
            "after-remove",
            "before-delete",
            "after-delete"
        ]
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn default_team_factory_receives_request_and_its_persisted_team_becomes_active() -> TestResult
{
    use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            default_team_factory: Some(std::sync::Arc::new(CustomDefaultTeam)),
            ..Default::default()
        },
        ..Default::default()
    });
    let mut config = create_test_config();
    config.session.update_age = None;
    let (ctx, database) = configured_context_with_connection(&plugin, config).await?;
    let (owner, session) = actor(&ctx, "factory-owner").await;
    // Refresh-on-every-access must still refresh only once for one authenticated
    // request. A real database trigger records expiry writes, while the factory
    // receives the session already read by the handler.
    for statement in [
        "CREATE TABLE session_refresh_audit (refreshes INTEGER NOT NULL)",
        "INSERT INTO session_refresh_audit (refreshes) VALUES (0)",
        "CREATE TRIGGER record_session_refresh AFTER UPDATE OF expires_at ON sessions BEGIN UPDATE session_refresh_audit SET refreshes = refreshes + 1; END",
    ] {
        database
            .execute_raw(Statement::from_string(DbBackend::Sqlite, statement))
            .await?;
    }
    let response = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"FactoryOrg","slug":"native-factory"})),
        &[],
    )
    .await?;
    assert_eq!(response.status, 200);
    let refreshes: i64 = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT refreshes FROM session_refresh_audit",
        ))
        .await?
        .ok_or("Refresh audit row missing")?
        .try_get("", "refreshes")?;
    assert_eq!(refreshes, 1, "One request must refresh the session once");
    let organization: Value = body(&response)?;
    let teams = ctx.database.list_teams(id(&organization)?).await?;
    assert_eq!(teams.len(), 1);
    let team = teams
        .first()
        .ok_or_else(|| std::io::Error::other("Factory returned no team"))?;
    assert_eq!(team.name, "Factory:FactoryOrg");
    assert!(
        ctx.database
            .get_team_member(&team.id, &owner.id)
            .await?
            .is_some()
    );
    assert_eq!(
        ctx.database
            .get_session(&session.token)
            .await?
            .and_then(|session| session.active_team_id),
        Some(team.id.clone())
    );
    let kept = call(&plugin, &ctx, Some(&session.token), HttpMethod::Post, "/organization/create", Some(json!({"name":"KeptFactory","slug":"native-factory-kept","keepCurrentActiveOrganization":true})), &[]).await?;
    assert_eq!(kept.status, 200);
    let kept: Value = body(&kept)?;
    let refreshes_2: i64 = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT refreshes FROM session_refresh_audit",
        ))
        .await?
        .ok_or("Refresh audit row missing")?
        .try_get("", "refreshes")?;
    assert_eq!(
        refreshes_2, 2,
        "Two requests must refresh the session twice"
    );
    let kept_teams = ctx.database.list_teams(id(&kept)?).await?;
    assert_eq!(kept_teams.len(), 1);
    assert_eq!(
        (kept_teams)
            .first()
            .expect("fixture contains the requested index")
            .name,
        "Factory:KeptFactory"
    );
    assert!(
        ctx.database
            .get_team_member(
                &(kept_teams)
                    .first()
                    .expect("fixture contains the requested index")
                    .id,
                &owner.id
            )
            .await?
            .is_some()
    );
    let preserved = ctx
        .database
        .get_session(&session.token)
        .await?
        .ok_or("Session must remain active")?;
    assert_eq!(preserved.active_organization_id(), Some(id(&organization)?));
    assert_eq!(preserved.active_team_id(), Some(team.id.as_str()));

    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn configured_team_limits_apply_to_server_and_http_creation() -> TestResult {
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            create_default_team: false,
            maximum_teams: Some(1),
            maximum_members_per_team: Some(1),
            ..Default::default()
        },
        ..Default::default()
    });
    let mut config = create_test_config();
    config.advanced.database.default_find_many_limit = 1;
    let ctx = configured_context(&plugin, config).await?;
    let (owner, session) = actor(&ctx, "limited-owner").await;
    let (_, target_session) = actor(&ctx, "limited-target").await;
    let created = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Limits","slug":"native-limits"})),
        &[],
    )
    .await?;
    let organization: Value = body(&created)?;
    let org_id = id(&organization)?;
    assert!(ctx.database.list_teams(org_id).await?.is_empty());
    let team = plugin
        .create_team(
            &ctx,
            CreateTeam {
                name: "Server team".to_owned(),
                organization_id: org_id.to_owned(),
                updated_at: Some(chrono::Utc::now()),
            },
        )
        .await?;
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Second"})),
            &[],
        )
        .await?,
        400,
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
    )?;
    drop(
        ctx.database
            .create_member(CreateMember::new(org_id, &target_session.user_id, "member"))
            .await?,
    );
    let added = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/add-team-member",
        Some(json!({"teamId":team.id,"userId":owner.id})),
        &[],
    )
    .await?;
    assert_eq!(added.status, 200);
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":target_session.user_id})),
            &[],
        )
        .await?,
        403,
        "TEAM_MEMBER_LIMIT_REACHED",
    )?;
    assert!(plugin.remove_team(&ctx, org_id, &team.id).await.is_err());
    let allowed = OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            allow_removing_all_teams: true,
            ..Default::default()
        },
        ..Default::default()
    });
    allowed.remove_team(&ctx, org_id, &team.id).await?;
    assert!(ctx.database.list_teams(org_id).await?.is_empty());
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn custom_role_configuration_replaces_defaults_and_whole_permission_checks_do_not_union_roles()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        roles: Some(HashMap::from([
            (
                "delegate".to_owned(),
                RolePermissions {
                    team: vec!["create".to_owned()],
                    ac: vec!["create".to_owned(), "read".to_owned()],
                    ..Default::default()
                },
            ),
            (
                "member-editor".to_owned(),
                RolePermissions {
                    member: vec!["update".to_owned()],
                    ..Default::default()
                },
            ),
        ])),
        ..configuration()
    });
    let ctx = context(&plugin).await?;
    let (_, session) = actor(&ctx, "custom-role-owner").await;
    let created = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Custom roles","slug":"native-custom-roles"})),
        &[],
    )
    .await?;
    let created: Value = body(&created)?;
    let _org_id = id(&created)?;
    let member_id = created
        .get("members")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(|member| member.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("Created organization has no creator membership"))?;
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Owner defaults must not leak"})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    )?;
    // update-member-role deliberately permits the creator even when custom
    // definitions omit owner permissions; the upstream endpoint opts into it.
    let assigned = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/update-member-role",
        Some(json!({"memberId":member_id,"role":["owner","delegate","member-editor"]})),
        &[],
    )
    .await?;
    assert_eq!(assigned.status, 200);
    let allowed = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create-team",
        Some(json!({"name":"Delegated"})),
        &[],
    )
    .await?;
    assert_eq!(allowed.status, 200);
    let together = call(
        &plugin,
        &ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/has-permission",
        Some(json!({"permissions":{"team":["create"],"member":["update"]}})),
        &[],
    )
    .await?;
    assert_eq!(
        (*(body::<Value>(&together)?)
            .get("success")
            .unwrap_or(&Value::Null)),
        false
    );
    let empty = OrganizationPlugin::with_config(OrganizationConfig {
        roles: Some(HashMap::new()),
        ..configuration()
    });
    assert_error(
        &call(
            &empty,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Explicitly no roles"})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    )?;

    let founder = OrganizationPlugin::with_config(OrganizationConfig {
        creator_role: "founder".to_owned(),
        roles: Some(HashMap::from([
            (
                "founder".to_owned(),
                RolePermissions {
                    invitation: vec!["create".to_owned()],
                    ..Default::default()
                },
            ),
            (
                "inviter".to_owned(),
                RolePermissions {
                    invitation: vec!["create".to_owned()],
                    ..Default::default()
                },
            ),
        ])),
        ..configuration()
    });
    let founder_ctx = context(&founder).await?;
    let (_, founder_session) = actor(&founder_ctx, "configured-founder").await;
    let created_2 = call(
        &founder,
        &founder_ctx,
        Some(&founder_session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Founder roles","slug":"native-founder-roles"})),
        &[],
    )
    .await?;
    let created_2_3: Value = body(&created_2)?;
    let founder_org = id(&created_2_3)?;
    // The pinned invitation route recognizes the three built-in role names
    // even when permissions and the creator role have been replaced.
    let invited = call(
        &founder,
        &founder_ctx,
        Some(&founder_session.token),
        HttpMethod::Post,
        "/organization/invite-member",
        Some(json!({"email":"builtin-owner@example.com","role":"owner"})),
        &[],
    )
    .await?;
    assert_eq!(invited.status, 200);
    let invitation: Value = body(&invited)?;
    let saved = founder_ctx
        .database
        .get_invitation_by_id(id(&invitation)?)
        .await?
        .ok_or_else(|| std::io::Error::other("Owner-role invitation was not persisted"))?;
    assert_eq!(saved.organization_id, founder_org);
    assert_eq!(saved.role, "owner");
    assert_eq!(
        saved.status,
        better_auth_core::types::InvitationStatus::Pending
    );

    let (sender, inviter_session) = actor(&founder_ctx, "configured-inviter").await;
    drop(
        founder_ctx
            .database
            .create_member(CreateMember::new(founder_org, &sender.id, "inviter"))
            .await?,
    );
    assert_error(
        &call(
            &founder,
            &founder_ctx,
            Some(&inviter_session.token),
            HttpMethod::Post,
            "/organization/invite-member",
            Some(json!({"organizationId":founder_org,"email":"protected-founder@example.com","role":"founder"})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
    )?;
    assert!(
        founder_ctx
            .database
            .get_pending_invitation(founder_org, "protected-founder@example.com")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn invitation_email_policy_guards_id_actions_and_preserves_rejection_state() -> TestResult {
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        require_email_verification_on_invitation: Some(true),
        ..configuration()
    });
    let mut ctx = context(&plugin).await?;
    let (owner, owner_session) = actor(&ctx, "verified-inviter").await;
    let (recipient, recipient_session) = actor(&ctx, "unverified-recipient").await;
    drop(
        ctx.database
            .update_user(
                &recipient.id,
                better_auth_core::UpdateUser {
                    email_verified: Some(false),
                    ..Default::default()
                },
            )
            .await?,
    );
    let created = call(
        &plugin,
        &ctx,
        Some(&owner_session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Verified invitation","slug":"verified-invitation"})),
        &[],
    )
    .await?;
    let created: Value = body(&created)?;
    let organization_id = id(&created)?;
    let invitation = ctx
        .database
        .create_invitation(better_auth_core::CreateInvitation {
            email: recipient
                .email
                .clone()
                .ok_or_else(|| std::io::Error::other("Recipient has no email"))?,
            role: "member".to_owned(),
            organization_id: organization_id.to_owned(),
            inviter_id: owner.id.clone(),
            expires_at: chrono::Utc::now() + Duration::hours(1),
            team_id: None,
        })
        .await?;
    let forbidden_get = call(
        &plugin,
        &ctx,
        Some(&recipient_session.token),
        HttpMethod::Get,
        "/organization/get-invitation",
        None,
        &[("id", &invitation.id)],
    )
    .await?;
    assert_error(
        &forbidden_get,
        403,
        "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    )?;
    for path in [
        "/organization/accept-invitation",
        "/organization/reject-invitation",
    ] {
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Post,
                path,
                Some(json!({"invitationId":invitation.id})),
                &[],
            )
            .await?,
            403,
            "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
        )?;
    }
    let untouched = ctx
        .database
        .get_invitation_by_id(&invitation.id)
        .await?
        .ok_or_else(|| std::io::Error::other("Rejected invitation disappeared"))?;
    assert_eq!(
        untouched.status,
        better_auth_core::InvitationStatus::Pending
    );
    assert!(
        ctx.database
            .get_member(organization_id, &recipient.id)
            .await?
            .is_none()
    );
    assert!(
        ctx.database
            .list_user_teams(&recipient.id)
            .await?
            .is_empty()
    );

    // Opaque IDs use the default policy without requiring email verification.
    let automatic = OrganizationPlugin::with_config(configuration());
    assert_eq!(
        call(
            &automatic,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &invitation.id)]
        )
        .await?
        .status,
        200
    );
    let mut numeric_config = ctx.config.as_ref().clone();
    numeric_config.advanced.database.use_number_id = true;
    ctx.config = std::sync::Arc::new(numeric_config);
    assert_error(
        &call(
            &automatic,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &invitation.id)],
        )
        .await?,
        403,
        "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    )?;
    let explicit_false = OrganizationPlugin::with_config(OrganizationConfig {
        require_email_verification_on_invitation: Some(false),
        ..configuration()
    });
    assert_eq!(
        call(
            &explicit_false,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &invitation.id)]
        )
        .await?
        .status,
        200
    );
    let rejected = call(
        &explicit_false,
        &ctx,
        Some(&recipient_session.token),
        HttpMethod::Post,
        "/organization/reject-invitation",
        Some(json!({"invitationId":invitation.id})),
        &[],
    )
    .await?;
    assert_eq!(rejected.status, 200);
    assert_eq!(
        ctx.database
            .get_invitation_by_id(&invitation.id)
            .await?
            .ok_or_else(|| std::io::Error::other("Processed invitation disappeared"))?
            .status,
        better_auth_core::InvitationStatus::Rejected
    );
    let processed = call(
        &explicit_false,
        &ctx,
        Some(&recipient_session.token),
        HttpMethod::Get,
        "/organization/get-invitation",
        None,
        &[("id", &invitation.id)],
    )
    .await?;
    assert_eq!(processed.status, 400);
    assert_eq!(
        body::<Value>(&processed)?,
        json!({"message":"Invitation not found!"})
    );

    let expired = ctx
        .database
        .create_invitation(better_auth_core::CreateInvitation {
            email: invitation.email.clone(),
            role: "member".to_owned(),
            organization_id: organization_id.to_owned(),
            inviter_id: owner.id.clone(),
            expires_at: chrono::Utc::now() - Duration::hours(1),
            team_id: None,
        })
        .await?;
    let expired_get = call(
        &plugin,
        &ctx,
        Some(&recipient_session.token),
        HttpMethod::Get,
        "/organization/get-invitation",
        None,
        &[("id", &expired.id)],
    )
    .await?;
    assert_eq!(expired_get.status, 400);
    assert_eq!(
        body::<Value>(&expired_get)?,
        json!({"message":"Invitation not found!"})
    );
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Post,
            "/organization/accept-invitation",
            Some(json!({"invitationId":expired.id})),
            &[],
        )
        .await?,
        400,
        "INVITATION_NOT_FOUND",
    )?;
    drop(
        ctx.database
            .update_user(
                &recipient.id,
                better_auth_core::UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?,
    );
    // Rejecting an expired, pending invitation remains supported upstream.
    assert_eq!(
        call(
            &plugin,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Post,
            "/organization/reject-invitation",
            Some(json!({"invitationId":expired.id})),
            &[]
        )
        .await?
        .status,
        200
    );
    let pending = ctx
        .database
        .create_invitation(better_auth_core::CreateInvitation {
            email: invitation.email,
            role: "member".to_owned(),
            organization_id: organization_id.to_owned(),
            inviter_id: owner.id.clone(),
            expires_at: chrono::Utc::now() + Duration::hours(1),
            team_id: None,
        })
        .await?;
    let owner_member = ctx
        .database
        .get_member(organization_id, &owner.id)
        .await?
        .ok_or_else(|| std::io::Error::other("Creator membership missing"))?;
    ctx.database.delete_member(&owner_member.id).await?;
    assert_error(
        &call(
            &plugin,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &pending.id)],
        )
        .await?,
        400,
        "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
    )?;
    Ok(())
}
