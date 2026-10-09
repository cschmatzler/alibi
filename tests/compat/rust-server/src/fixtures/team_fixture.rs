//! Private fixture configuration and server-side organization team operations.

use crate::TestSchema;
use alibi::AuthUser;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, OrganizationLimitResolver, RolePermissions,
    TeamsConfig, default_organization_statements,
};
use alibi::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin,
    EmailVerificationPlugin, OrganizationPlugin, SessionManagementPlugin, TwoFactorPlugin,
};
use alibi::seaorm::sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use alibi::seaorm::store::entities::{
    invitation, member, organization, organization_role, team, team_member,
};
use alibi::types::{
    CreateMember, CreateOrganizationRole, CreateTeam, CreateUser, OrganizationPermissions,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

type Auth = Arc<BetterAuth<TestSchema>>;

#[derive(Clone)]
pub(crate) struct TeamProfile {
    name: &'static str,
    auth: Auth,
    config: OrganizationConfig,
}

fn numeric_value(name: &str) -> Option<f64> {
    if name.ends_with("negative-infinity") {
        Some(f64::NEG_INFINITY)
    } else if name.ends_with("infinity") {
        Some(f64::INFINITY)
    } else if name.ends_with("negative") {
        Some(-1.5)
    } else if name.ends_with("zero") {
        Some(0.0)
    } else if name.ends_with("nan") {
        Some(f64::NAN)
    } else if name.ends_with("fraction") {
        Some(1.5)
    } else {
        None
    }
}
fn numeric_events() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    static EVENTS: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();
    EVENTS.get_or_init(Mutex::default)
}
fn numeric_event(organization_id: &str, mut event: Value) -> AuthResult<()> {
    event["organizationId"] = json!(organization_id);
    numeric_events()
        .lock()
        .map_err(|_| AuthError::internal("Numeric observations unavailable"))?
        .entry(organization_id.to_owned())
        .or_default()
        .push(event);
    Ok(())
}
#[derive(Debug)]
struct NumericLimits {
    value: Option<f64>,
    database: DatabaseConnection,
}
#[async_trait::async_trait]
impl OrganizationLimitResolver for NumericLimits {
    async fn maximum_teams(
        &self,
        context: &alibi::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<f64>> {
        let organization = organization::Entity::find_by_id(&context.organization_id)
            .one(&self.database)
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        numeric_event(
            &context.organization_id,
            json!({"event":"maximumTeams", "userId":context.user.as_ref().map(|u| &u.id), "session":{"userId":context.session.as_ref().map(|s| &s.user_id)}, "activeOrganizationId":context.session.as_ref().and_then(|s| s.active_organization_id.as_ref()), "organizationName":organization.name, "header":context.request.as_ref().and_then(|r| r.header("x-numeric-policy")), "requestMethod":context.request.as_ref().map(|r| format!("{:?}",r.method()).to_uppercase())}),
        )?;
        if context
            .request
            .as_ref()
            .and_then(|r| r.header("x-numeric-policy"))
            .map(String::as_str)
            == Some("insert")
        {
            for i in 0..2 {
                team::ActiveModel {
                    id: Set(alibi::utils::id::generate_id(32)),
                    organization_id: Set(context.organization_id.clone()),
                    name: Set(format!("Callback team {i}")),
                    member_count: Set(0),
                    created_at: Set(Utc::now()),
                    updated_at: Set(Some(Utc::now())),
                }
                .insert(&self.database)
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
            }
        }
        Ok(self.value)
    }
    async fn maximum_team_members(
        &self,
        context: &alibi::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<f64>> {
        numeric_event(
            &context.organization_id,
            json!({"event":"maximumMembersPerTeam", "teamId":context.team_id,"userId":context.user.as_ref().map(|u| &u.id),"session":{"userId":context.session.as_ref().map(|s| &s.user_id)},"activeOrganizationId":context.session.as_ref().and_then(|s| s.active_organization_id.as_ref())}),
        )?;
        Ok(self.value)
    }
    async fn maximum_roles(&self, organization_id: &str) -> AuthResult<Option<f64>> {
        let organization = organization::Entity::find_by_id(organization_id)
            .one(&self.database)
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        numeric_event(
            organization_id,
            json!({"event":"maximumRolesPerOrganization","organizationName":organization.name}),
        )?;
        if organization.name == "Callback writes roles" {
            for i in 0..2 {
                organization_role::ActiveModel {
                    id: Set(alibi::utils::id::generate_id(32)),
                    organization_id: Set(organization_id.to_owned()),
                    role: Set(format!("callback{i}")),
                    permission: Set("{}".into()),
                    created_at: Set(Utc::now()),
                    updated_at: Set(None),
                }
                .insert(&self.database)
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
            }
        }
        Ok(self.value)
    }
}
#[derive(Debug)]
struct NumericHooks(DatabaseConnection);
#[async_trait::async_trait]
impl alibi::plugins::organization::OrganizationTeamHooks for NumericHooks {
    async fn before_create(
        &self,
        _: &mut CreateTeam,
        context: &alibi::plugins::organization::extensions::TeamHookContext,
    ) -> AuthResult<()> {
        numeric_event(
            &context.organization.id,
            json!({"event":"beforeCreateTeam"}),
        )
    }
    async fn before_add_member(
        &self,
        team: &alibi::types::Team,
        user: &alibi::wire::UserView,
        context: &alibi::plugins::organization::extensions::TeamHookContext,
    ) -> AuthResult<()> {
        if context.organization.name == "Legacy seats" {
            use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
            self.0
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE team SET member_count=5 WHERE id=?",
                    [team.id.clone().into()],
                ))
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
        }
        numeric_event(
            &context.organization.id,
            json!({"event":"beforeAddTeamMember","teamId":team.id,"target":{"userId":user.id}}),
        )
    }
    async fn after_add_member(
        &self,
        _: &alibi::types::TeamMember,
        team: &alibi::types::Team,
        user: &alibi::wire::UserView,
        context: &alibi::plugins::organization::extensions::TeamHookContext,
    ) -> AuthResult<()> {
        numeric_event(
            &context.organization.id,
            json!({"event":"afterAddTeamMember","teamId":team.id,"target":{"userId":user.id}}),
        )
    }
}

#[derive(Debug)]
struct RequestTeamLimits;

#[derive(Debug)]
struct DatabaseRoleLimits(DatabaseConnection);

#[derive(Debug, Default)]
struct RolePolicyBarrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

fn role_policy_barriers() -> &'static Mutex<HashMap<String, Arc<RolePolicyBarrier>>> {
    static BARRIERS: OnceLock<Mutex<HashMap<String, Arc<RolePolicyBarrier>>>> = OnceLock::new();
    BARRIERS.get_or_init(Mutex::default)
}

fn role_policy_barrier(organization_id: &str) -> AuthResult<Option<Arc<RolePolicyBarrier>>> {
    Ok(role_policy_barriers()
        .lock()
        .map_err(|_| AuthError::internal("Role policy unavailable"))?
        .get(organization_id)
        .cloned())
}

#[async_trait::async_trait]
impl OrganizationLimitResolver for DatabaseRoleLimits {
    async fn maximum_roles(&self, organization_id: &str) -> AuthResult<Option<f64>> {
        if let Some(barrier) = role_policy_barrier(organization_id)? {
            barrier.entered.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                barrier.release.notified(),
            )
            .await
            .map_err(|_| AuthError::internal("Role policy release timed out"))?;
        }
        let organization = organization::Entity::find_by_id(organization_id)
            .one(&self.0)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        Ok(Some(if organization.name == "Two role budget" {
            2.0
        } else {
            1.0
        }))
    }
}

fn delegated_roles() -> std::collections::HashMap<String, RolePermissions> {
    [
        (
            "owner".to_owned(),
            RolePermissions {
                organization: vec!["update".to_owned(), "delete".to_owned()],
                member: vec![
                    "create".to_owned(),
                    "update".to_owned(),
                    "delete".to_owned(),
                ],
                invitation: vec!["create".to_owned(), "cancel".to_owned()],
                team: vec![
                    "create".to_owned(),
                    "update".to_owned(),
                    "delete".to_owned(),
                ],
                ac: vec![
                    "create".to_owned(),
                    "read".to_owned(),
                    "update".to_owned(),
                    "delete".to_owned(),
                ],
                api_key: vec![
                    "create".to_owned(),
                    "read".to_owned(),
                    "update".to_owned(),
                    "delete".to_owned(),
                ],
                ..Default::default()
            },
        ),
        (
            "delegator".to_owned(),
            RolePermissions {
                team: vec!["create".to_owned()],
                ac: vec!["create".to_owned(), "read".to_owned(), "update".to_owned()],
                ..Default::default()
            },
        ),
        (
            "auditor".to_owned(),
            RolePermissions {
                member: vec!["update".to_owned()],
                ..Default::default()
            },
        ),
        ("member".to_owned(), RolePermissions::default()),
    ]
    .into()
}

fn api_key_plugin() -> ApiKeyPlugin {
    use alibi::plugins::api_key::{ApiKeyConfig, ApiKeyReferences};
    let plugin = ApiKeyPlugin::builder()
        .enable_metadata(true)
        .build()
        .configuration(ApiKeyConfig {
            config_id: "secondary".to_owned(),
            enable_metadata: true,
            ..Default::default()
        })
        .configuration(ApiKeyConfig {
            config_id: "organization".to_owned(),
            references: ApiKeyReferences::Organization,
            enable_metadata: true,
            ..Default::default()
        })
        .configuration(ApiKeyConfig {
            config_id: "session".to_owned(),
            enable_session_for_api_keys: true,
            api_key_headers: vec!["x-api-key".to_owned(), "x-machine-key".to_owned()],
            ..Default::default()
        });
    ["shared-first", "shared-second"]
        .into_iter()
        .fold(plugin, |plugin, id| {
            plugin.configuration(ApiKeyConfig {
                config_id: id.to_owned(),
                enable_session_for_api_keys: true,
                api_key_headers: vec!["x-shared-key".to_owned()],
                ..Default::default()
            })
        })
}

#[async_trait::async_trait]
impl OrganizationLimitResolver for RequestTeamLimits {
    async fn maximum_teams(
        &self,
        context: &alibi::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<f64>> {
        let owner = context
            .user
            .as_ref()
            .is_some_and(|user| user.name.as_deref() == Some("limit-owner"));
        let expanded = context
            .request
            .as_ref()
            .and_then(|request| request.header("x-team-policy").map(String::as_str))
            == Some("expanded");
        Ok(Some(if owner && expanded { 3.0 } else { 1.0 }))
    }

    async fn maximum_team_members(
        &self,
        context: &alibi::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<f64>> {
        Ok(Some(f64::from(context.user.as_ref().is_some_and(|user| {
            user.name.as_deref() == Some("limit-owner")
        }))))
    }
}

pub(crate) async fn profiles(
    base: &AuthConfig,
    database: &DatabaseConnection,
    verification_sender: Arc<dyn alibi::plugins::email_verification::SendVerificationEmail>,
) -> AuthResult<Vec<TeamProfile>> {
    let mut profiles = Vec::new();
    for name in [
        "org-numeric-fixed-unset",
        "org-numeric-fixed-zero",
        "org-numeric-fixed-fraction",
        "org-numeric-fixed-negative",
        "org-numeric-fixed-nan",
        "org-numeric-fixed-infinity",
        "org-numeric-fixed-negative-infinity",
        "org-numeric-async-zero",
        "org-numeric-async-fraction",
        "org-numeric-async-negative",
        "org-numeric-async-nan",
        "org-numeric-async-infinity",
        "org-numeric-async-negative-infinity",
        "org-deletion-disabled",
        "org-team-hooks",
        "org-team-factory",
        "org-teams",
        "org-teams-no-default",
        "org-teams-limited",
        "org-teams-removable",
        "org-teams-dynamic",
        "org-roles-limited",
        "org-roles-no-ac",
        "org-roles-delegated",
        "org-roles-callback",
    ] {
        let mut config = base
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"));
        if name == "org-roles-callback" {
            config.advanced.database.default_find_many_limit = 1;
        }
        let numeric = name.starts_with("org-numeric-");
        let numeric_resolver = (numeric && name.contains("-async-")).then(|| {
            Arc::new(NumericLimits {
                value: numeric_value(name),
                database: database.clone(),
            }) as Arc<dyn OrganizationLimitResolver>
        });
        let dynamic = numeric || name == "org-teams-dynamic" || name.starts_with("org-roles-");
        let mut organization = OrganizationConfig {
            disable_organization_deletion: name == "org-deletion-disabled",
            teams: TeamsConfig {
                enabled: true,
                create_default_team: !numeric && name != "org-teams-no-default",
                maximum_teams: if numeric { numeric_value(name) } else { None },
                maximum_members_per_team: if numeric { numeric_value(name) } else { None },
                hooks: numeric.then(|| {
                    Arc::new(NumericHooks(database.clone()))
                        as Arc<dyn alibi::plugins::organization::OrganizationTeamHooks>
                }),
                allow_removing_all_teams: name == "org-teams-removable",
                limit_resolver: numeric_resolver.clone().or_else(|| {
                    (name == "org-teams-limited")
                        .then(|| Arc::new(RequestTeamLimits) as Arc<dyn OrganizationLimitResolver>)
                }),
                ..Default::default()
            },
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: dynamic,
                maximum_roles_per_organization: if numeric {
                    numeric_value(name)
                } else {
                    (name == "org-roles-limited").then_some(1.0)
                },
                limit_resolver: numeric_resolver.or_else(|| {
                    (name == "org-roles-callback").then(|| {
                        Arc::new(DatabaseRoleLimits(database.clone()))
                            as Arc<dyn OrganizationLimitResolver>
                    })
                }),
            },
            access_control: (dynamic && name != "org-roles-no-ac")
                .then(default_organization_statements),
            roles: (name == "org-roles-delegated").then(delegated_roles),
            ..Default::default()
        };
        super::team_config_fixture::configure(name, database, &mut organization);
        if name == "org-roles-delegated" {
            let _ = organization
                .access_control
                .as_mut()
                .expect("Delegated access control configured")
                .insert(
                    "apiKey".to_owned(),
                    vec![
                        "create".to_owned(),
                        "read".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                );
        }
        let auth = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(
                EmailVerificationPlugin::new()
                    .custom_send_verification_email(verification_sender.clone()),
            )
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(AdminPlugin::new())
            .plugin(TwoFactorPlugin::new())
            .plugin(api_key_plugin())
            .plugin(OrganizationPlugin::with_config(organization.clone()))
            .build()
            .await?;
        profiles.push(TeamProfile {
            name,
            auth: Arc::new(auth),
            config: organization,
        });
    }
    Ok(profiles)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationQuery {
    organization_id: String,
    profile: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum TeamOperation {
    SetTeamStorage {
        #[serde(rename = "teamId")]
        team_id: String,
        #[serde(rename = "organizationId")]
        organization_id: Option<String>,
        #[serde(default)]
        restore: bool,
    },
    SeedStrayTeamMember {
        #[serde(rename = "teamId")]
        team_id: String,
        #[serde(rename = "userId")]
        user_id: String,
    },
    TeamConfigEvidence {
        #[serde(rename = "organizationId")]
        organization_id: String,
    },
    NumericEvents {
        #[serde(rename = "organizationId")]
        organization_id: String,
    },
    OrphanOrganization {
        #[serde(rename = "organizationId")]
        organization_id: String,
    },
    ListUserInvitations {
        email: String,
    },
    RolePolicy {
        #[serde(rename = "organizationId")]
        organization_id: String,
        stage: RolePolicyStage,
    },
    CreateTeam {
        #[serde(rename = "organizationId")]
        organization_id: String,
        name: String,
    },
    RemoveTeam {
        #[serde(rename = "organizationId")]
        organization_id: String,
        #[serde(rename = "teamId")]
        team_id: String,
    },
    SeedMember {
        #[serde(rename = "organizationId")]
        organization_id: String,
        id: String,
        email: String,
        name: String,
    },
    StoredRole {
        #[serde(rename = "organizationId")]
        organization_id: String,
        #[serde(rename = "roleId")]
        role_id: String,
    },
    SeedRole {
        #[serde(rename = "organizationId")]
        organization_id: String,
        role: String,
        permission: Option<OrganizationPermissions>,
        #[serde(rename = "permissionJson")]
        permission_json: Option<String>,
    },
    SetMemberRole {
        #[serde(rename = "organizationId")]
        organization_id: String,
        #[serde(rename = "memberId")]
        member_id: String,
        role: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RolePolicyStage {
    Arm,
    Wait,
    Release,
}

async fn control_role_policy(
    profile: &TeamProfile,
    organization_id: String,
    stage: RolePolicyStage,
) -> AuthResult<Value> {
    if profile.name != "org-roles-callback"
        || profile
            .auth
            .store()
            .get_organization_by_id(&organization_id)
            .await?
            .is_none()
    {
        return Err(AuthError::bad_request("Role policy organization not found"));
    }
    let stage = match stage {
        RolePolicyStage::Arm => {
            let mut barriers = role_policy_barriers()
                .lock()
                .map_err(|_| AuthError::internal("Role policy unavailable"))?;
            if barriers.contains_key(&organization_id) {
                return Err(AuthError::bad_request("Role policy already armed"));
            }
            let _ = barriers.insert(
                organization_id.clone(),
                Arc::new(RolePolicyBarrier::default()),
            );
            "arm"
        }
        RolePolicyStage::Wait => {
            let barrier = role_policy_barrier(&organization_id)?
                .ok_or_else(|| AuthError::bad_request("Role policy is not armed"))?;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                barrier.entered.notified(),
            )
            .await
            .map_err(|_| AuthError::internal("Role policy entry timed out"))?;
            "wait"
        }
        RolePolicyStage::Release => {
            let barrier = role_policy_barriers()
                .lock()
                .map_err(|_| AuthError::internal("Role policy unavailable"))?
                .remove(&organization_id)
                .ok_or_else(|| AuthError::bad_request("Role policy is not armed"))?;
            barrier.release.notify_one();
            "release"
        }
    };
    Ok(json!({"organizationId":organization_id,"stage":stage}))
}

#[derive(Deserialize)]
struct ServerRequest {
    profile: Option<String>,
    #[serde(flatten)]
    operation: TeamOperation,
    authority: Option<String>,
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn failure(error: AuthError) -> (StatusCode, Json<Value>) {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = match error {
        AuthError::Upstream { message, code, .. } => json!({"message":message,"code":code}),
        error if error.status_code() >= 500 => json!({"message":"Internal server error"}),
        error => json!({"message":error.to_string()}),
    };
    (status, Json(body))
}

pub(crate) fn router(database: DatabaseConnection, profiles: Vec<TeamProfile>) -> Router<Auth> {
    let mut router = Router::new();
    for profile in &profiles {
        let routes: Router<Auth> = profile
            .auth
            .clone()
            .axum_router()
            .with_state(profile.auth.clone());
        router = router.nest(
            &format!("/__test/profiles/{}/api/auth", profile.name),
            routes,
        );
    }
    let operation_profiles = profiles.clone();
    let operation_database = database.clone();
    let team_backups = Arc::new(tokio::sync::Mutex::new(
        HashMap::<String, team::Model>::new(),
    ));
    router
        .route("/__test/organization-api", post(move |headers: axum::http::HeaderMap, Json(body): Json<ServerRequest>| {
            let profiles = operation_profiles.clone();
            let database = operation_database.clone();
            let team_backups = team_backups.clone();
            async move {
                let name = body.profile.as_deref().unwrap_or("org-teams");
                let Some(profile) = profiles.iter().find(|profile| profile.name == name) else {
                    return failure(AuthError::bad_request("Unknown fixture profile"));
                };
                let plugin = OrganizationPlugin::with_config(profile.config.clone());
                let headers = headers.iter().filter_map(|(name,value)|value.to_str().ok().map(|value|(name.as_str().to_owned(),value.to_owned()))).collect::<HashMap<_,_>>();
                let signed = body.authority.as_deref() == Some("headers");
                let result = match body.operation {
                    TeamOperation::SetTeamStorage {team_id, organization_id, restore} => async {
                        let mut backups = team_backups.lock().await;
                        if restore {
                            let original = backups.remove(&team_id).ok_or_else(|| AuthError::internal("missing original team"))?;
                            team::Entity::delete_by_id(&team_id).exec(&database).await.map_err(|e| AuthError::internal(e.to_string()))?;
                            let model: team::ActiveModel = original.into();
                            model.reset_all().insert(&database).await.map_err(|e| AuthError::internal(e.to_string()))?;
                        } else {
                            let original = team::Entity::find_by_id(&team_id).one(&database).await.map_err(|e| AuthError::internal(e.to_string()))?.ok_or_else(|| AuthError::internal("missing team"))?;
                            backups.insert(team_id.clone(), original.clone());
                            if let Some(organization_id) = organization_id {let mut model: team::ActiveModel = original.into();model.organization_id = Set(organization_id);model.update(&database).await.map_err(|e| AuthError::internal(e.to_string()))?;}
                            else {team::Entity::delete_by_id(&team_id).exec(&database).await.map_err(|e| AuthError::internal(e.to_string()))?;}
                        }
                        Ok(json!({"changed": true}))
                    }.await,
                    TeamOperation::SeedStrayTeamMember {team_id, user_id} => profile.auth.store().add_team_member(&team_id, &user_id, None).await.map(|_| json!({"inserted": true})),
                    TeamOperation::TeamConfigEvidence {organization_id} => super::team_config_fixture::evidence(&database, &organization_id).await,
                    TeamOperation::NumericEvents {organization_id} => numeric_events().lock().map_err(|_| AuthError::internal("Numeric observations unavailable")).map(|events| json!(events.get(&organization_id).cloned().unwrap_or_default())),
                    TeamOperation::OrphanOrganization { organization_id } => {
                        async {
                            if profile.auth.store().get_organization_by_id(&organization_id)
                                .await?.is_none()
                            {
                                return Err(AuthError::bad_request("Organization not found"));
                            }
                            let mut connection = database.get_sqlite_connection_pool().acquire()
                                .await.map_err(|error| AuthError::internal(error.to_string()))?;
                            // A controlled legacy-row fixture operation; never return a
                            // connection with altered enforcement after failure/cancellation.
                            connection.close_on_drop();
                            let enabled: i64 = alibi::seaorm::sea_orm::sqlx::query_scalar(
                                "PRAGMA foreign_keys",
                            ).fetch_one(&mut *connection).await
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            let _ = alibi::seaorm::sea_orm::sqlx::query("PRAGMA foreign_keys=OFF")
                                .execute(&mut *connection).await
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            let result = alibi::seaorm::sea_orm::sqlx::query(
                                "DELETE FROM organization WHERE id=?",
                            ).bind(&organization_id).execute(&mut *connection).await;
                            let _ = alibi::seaorm::sea_orm::sqlx::query(
                                if enabled == 0 { "PRAGMA foreign_keys=OFF" } else { "PRAGMA foreign_keys=ON" },
                            ).execute(&mut *connection).await
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            connection.return_to_pool().await;
                            let _ = result.map_err(|error| AuthError::internal(error.to_string()))?;
                            Ok(json!({"removed":true}))
                        }.await
                    },
                    TeamOperation::ListUserInvitations { email } => {
                        plugin.list_user_invitations(profile.auth.context(), &email).await
                            .and_then(|invitations| serde_json::to_value(invitations).map_err(AuthError::from))
                    },
                    TeamOperation::RolePolicy { organization_id, stage } => {
                        control_role_policy(profile, organization_id, stage).await
                    },
                    TeamOperation::CreateTeam { organization_id, name } => {
                        let data = CreateTeam {organization_id, name, updated_at: Some(Utc::now())};
                        let result = if signed {plugin.create_team_with_headers(profile.auth.context(), &headers, data).await} else {plugin.create_team(profile.auth.context(), data).await};
                        result.and_then(|team| serde_json::to_value(team).map_err(AuthError::from))
                    }
                    TeamOperation::RemoveTeam { organization_id, team_id } => {
                        let result = if signed {plugin.remove_team_with_headers(profile.auth.context(), &headers, &organization_id, &team_id).await} else {plugin.remove_team(profile.auth.context(), &organization_id, &team_id).await};
                        result.map(|()| json!({"message":"Team removed successfully."}))
                    }
                    TeamOperation::SeedMember { organization_id, id, email, name } => {
                        async {
                            let user = profile.auth.store().create_user(CreateUser {
                                id: Some(id), email: Some(email), name: Some(name), email_verified: Some(true), role: Some("user".to_owned()),
                                ..Default::default()
                            }).await?;
                            let member = profile.auth.store().create_member(CreateMember {
                                organization_id, user_id: user.id().into_owned(), role: "member".to_owned(),
                            }).await?;
                            Ok::<_, AuthError>(json!({"userId":user.id(),"memberId":member.id}))
                        }.await
                    },
                    TeamOperation::StoredRole {organization_id,role_id} => {
                        async {
                            let row = organization_role::Entity::find_by_id(role_id)
                                .filter(organization_role::Column::OrganizationId.eq(organization_id))
                                .one(&database).await.map_err(|error| AuthError::internal(error.to_string()))?;
                            Ok::<_, AuthError>(row.map_or(Value::Null, |row| json!({"role":row.role,"permission":row.permission,"updatedAt":row.updated_at})))
                        }.await
                    },
                    TeamOperation::SeedRole {organization_id,role,permission,permission_json} => {
                        async {
                            // Explicit raw-only seeds exercise legacy SQL, including malformed
                            // JSON. Typed seeds still verify their literal representation.
                            if let (Some(raw), Some(permission)) = (&permission_json, &permission) {
                                let parsed: OrganizationPermissions = serde_json::from_str(raw)?;
                                if &parsed != permission {
                                    return Err(AuthError::bad_request("Legacy permission mismatch"));
                                }
                            }
                            if profile.auth.store().get_organization_by_id(&organization_id).await?.is_none() {
                                return Err(AuthError::bad_request("Organization not found"));
                            }
                            if permission.is_none() && permission_json.is_none() {
                                return Err(AuthError::bad_request("Missing legacy permission"));
                            }
                            let role = profile.auth.store().create_organization_role(CreateOrganizationRole {organization_id,role,permission:permission.unwrap_or_default()}).await?;
                            if let Some(raw) = permission_json {
                                let mut row: organization_role::ActiveModel = organization_role::Entity::find_by_id(&role.id)
                                    .one(&database).await.map_err(|error| AuthError::internal(error.to_string()))?
                                    .ok_or_else(|| AuthError::internal("Seeded role missing"))?.into();
                                row.permission = Set(raw);
                                row.update(&database).await.map_err(|error| AuthError::internal(error.to_string()))?;
                            }
                            Ok(json!({"roleId":role.id,"organizationId":role.organization_id,"role":role.role}))
                        }.await
                    },
                    TeamOperation::SetMemberRole {organization_id,member_id,role} => {
                        async {
                            let member = profile.auth.store().get_member_by_id(&member_id).await?
                                .filter(|member| member.organization_id == organization_id)
                                .ok_or_else(|| AuthError::bad_request("Member not found"))?;
                            let updated = profile.auth.store().update_member_role(&member.id, &role).await?;
                            Ok::<_, AuthError>(json!({"memberId":updated.id,"organizationId":updated.organization_id,"role":updated.role}))
                        }.await
                    },
                };
                match result { Ok(value) => (StatusCode::OK, Json(value)), Err(error) if signed => (StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), Json(json!({"status":error.status_code()}))), Err(error) => failure(error) }
            }
        }))
        .route("/__test/organization-state", get(move |Query(query): Query<OrganizationQuery>| {
            let database = database.clone();
            let profiles = profiles.clone();
            async move {
                if !profiles.iter().any(|profile| profile.name == query.profile.as_deref().unwrap_or("org-teams")) {
                    return failure(AuthError::bad_request("Unknown fixture profile"));
                }
                let result = async {
                    let teams = team::Entity::find().filter(team::Column::OrganizationId.eq(&query.organization_id)).order_by_asc(team::Column::CreatedAt).all(&database).await?;
                    let members = member::Entity::find().filter(member::Column::OrganizationId.eq(&query.organization_id)).order_by_asc(member::Column::CreatedAt).all(&database).await?;
                    let invitations = invitation::Entity::find().filter(invitation::Column::OrganizationId.eq(&query.organization_id)).order_by_asc(invitation::Column::CreatedAt).all(&database).await?;
                    let roles = organization_role::Entity::find().filter(organization_role::Column::OrganizationId.eq(&query.organization_id)).order_by_asc(organization_role::Column::CreatedAt).all(&database).await?;
                    let mut team_members = Vec::new();
                    for parent in &teams {
                        team_members.extend(team_member::Entity::find().filter(team_member::Column::TeamId.eq(&parent.id)).order_by_asc(team_member::Column::CreatedAt).all(&database).await?);
                    }
                    Ok::<_, alibi::seaorm::sea_orm::DbErr>(json!({
                        "teams":teams.into_iter().map(|team|json!({"id":team.id,"name":team.name,"organizationId":team.organization_id,"createdAt":timestamp(team.created_at),"updatedAt":team.updated_at.map(timestamp),"memberCount":team.member_count})).collect::<Vec<_>>(),
                        "teamMembers":team_members.into_iter().map(|member|json!({"id":member.id,"teamId":member.team_id,"userId":member.user_id,"createdAt":timestamp(member.created_at)})).collect::<Vec<_>>(),
                        "roles":roles.into_iter().map(|role|json!({"id":role.id,"organizationId":role.organization_id,"role":role.role,"permission":role.permission,"createdAt":timestamp(role.created_at),"updatedAt":role.updated_at.map(timestamp)})).collect::<Vec<_>>(),
                        "members":members.into_iter().map(|member|json!({"id":member.id,"organizationId":member.organization_id,"userId":member.user_id,"role":member.role,"createdAt":timestamp(member.created_at)})).collect::<Vec<_>>(),
                        "invitations":invitations.into_iter().map(|invitation|json!({"id":invitation.id,"organizationId":invitation.organization_id,"email":invitation.email,"role":invitation.role,"status":invitation.status,"teamId":invitation.team_id,"inviterId":invitation.inviter_id,"expiresAt":timestamp(invitation.expires_at),"createdAt":timestamp(invitation.created_at)})).collect::<Vec<_>>(),
                    }))
                }.await;
                match result {
                    Ok(value) => (StatusCode::OK, Json(value)),
                    Err(error) => failure(AuthError::Internal(error.to_string())),
                }
            }
        }))
}
