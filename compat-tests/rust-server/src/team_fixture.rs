//! Private fixture configuration and server-side organization team operations.

use super::TestSchema;
use axum::{
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::organization::{
    default_organization_statements, DynamicAccessControlConfig, OrganizationConfig,
    OrganizationLimitResolver, RolePermissions, TeamsConfig,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin, OrganizationPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::types::{
    CreateMember, CreateOrganizationRole, CreateTeam, CreateUser, OrganizationPermissions,
};
use better_auth_core::AuthUser;
use better_auth_seaorm::sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
};
use better_auth_seaorm::store::entities::{
    invitation, member, organization, organization_role, team, team_member,
};
use better_auth_seaorm::SeaOrmStore;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

type Auth = Arc<BetterAuth<TestSchema>>;

#[derive(Clone)]
pub(super) struct TeamProfile {
    name: &'static str,
    auth: Auth,
    config: OrganizationConfig,
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
    async fn maximum_roles(&self, organization_id: &str) -> AuthResult<Option<usize>> {
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
            2
        } else {
            1
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
    use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyReferences};
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
        context: &better_auth::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<usize>> {
        let owner = context
            .user
            .as_ref()
            .is_some_and(|user| user.name.as_deref() == Some("limit-owner"));
        let expanded = context
            .request
            .as_ref()
            .and_then(|request| request.header("x-team-policy").map(String::as_str))
            == Some("expanded");
        Ok(Some(if owner && expanded { 3 } else { 1 }))
    }

    async fn maximum_team_members(
        &self,
        context: &better_auth::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<usize>> {
        Ok(Some(usize::from(context.user.as_ref().is_some_and(
            |user| user.name.as_deref() == Some("limit-owner"),
        ))))
    }
}

pub(super) async fn profiles(
    base: &AuthConfig,
    database: &DatabaseConnection,
) -> AuthResult<Vec<TeamProfile>> {
    let mut profiles = Vec::new();
    for name in [
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
        let dynamic = name == "org-teams-dynamic" || name.starts_with("org-roles-");
        let mut organization = OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                create_default_team: name != "org-teams-no-default",
                allow_removing_all_teams: name == "org-teams-removable",
                limit_resolver: (name == "org-teams-limited")
                    .then(|| Arc::new(RequestTeamLimits) as Arc<dyn OrganizationLimitResolver>),
                ..Default::default()
            },
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: dynamic,
                maximum_roles_per_organization: (name == "org-roles-limited").then_some(1),
                limit_resolver: (name == "org-roles-callback").then(|| {
                    Arc::new(DatabaseRoleLimits(database.clone()))
                        as Arc<dyn OrganizationLimitResolver>
                }),
            },
            access_control: (dynamic && name != "org-roles-no-ac")
                .then(default_organization_statements),
            roles: (name == "org-roles-delegated").then(delegated_roles),
            ..Default::default()
        };
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
            .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
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
    SeedRole {
        #[serde(rename = "organizationId")]
        organization_id: String,
        role: String,
        permission: OrganizationPermissions,
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

pub(super) fn router(database: DatabaseConnection, profiles: Vec<TeamProfile>) -> Router<Auth> {
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
    router
        .route("/__test/organization-api", post(move |Json(body): Json<ServerRequest>| {
            let profiles = operation_profiles.clone();
            async move {
                let name = body.profile.as_deref().unwrap_or("org-teams");
                let Some(profile) = profiles.iter().find(|profile| profile.name == name) else {
                    return failure(AuthError::bad_request("Unknown fixture profile"));
                };
                let plugin = OrganizationPlugin::with_config(profile.config.clone());
                let result = match body.operation {
                    TeamOperation::RolePolicy { organization_id, stage } => {
                        control_role_policy(profile, organization_id, stage).await
                    },
                    TeamOperation::CreateTeam { organization_id, name } => {
                        plugin.create_team(profile.auth.context(), CreateTeam {
                            organization_id, name, updated_at: Some(Utc::now()),
                        }).await.and_then(|team| serde_json::to_value(team).map_err(AuthError::from))
                    }
                    TeamOperation::RemoveTeam { organization_id, team_id } => {
                        plugin.remove_team(profile.auth.context(), &organization_id, &team_id).await
                            .map(|()| json!({"message":"Team removed successfully."}))
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
                    TeamOperation::SeedRole {organization_id,role,permission} => {
                        profile.auth.store().create_organization_role(CreateOrganizationRole {organization_id,role,permission}).await
                            .map(|role|json!({"roleId":role.id,"organizationId":role.organization_id,"role":role.role}))
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
                match result { Ok(value) => (StatusCode::OK, Json(value)), Err(error) => failure(error) }
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
                    Ok::<_, better_auth_seaorm::sea_orm::DbErr>(json!({
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
