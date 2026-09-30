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
    OrganizationConfig, OrganizationLimitResolver, TeamsConfig,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, EmailPasswordPlugin, OrganizationPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::types::{CreateMember, CreateTeam, CreateUser};
use better_auth_core::AuthUser;
use better_auth_seaorm::sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
};
use better_auth_seaorm::store::entities::{invitation, member, team, team_member};
use better_auth_seaorm::SeaOrmStore;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

type Auth = Arc<BetterAuth<TestSchema>>;

#[derive(Clone)]
pub(super) struct TeamProfile {
    name: &'static str,
    auth: Auth,
    config: OrganizationConfig,
}

#[derive(Debug)]
struct RequestTeamLimits;

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
    ] {
        let config = base
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"));
        let organization = OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                create_default_team: name != "org-teams-no-default",
                allow_removing_all_teams: name == "org-teams-removable",
                limit_resolver: (name == "org-teams-limited")
                    .then(|| Arc::new(RequestTeamLimits) as Arc<dyn OrganizationLimitResolver>),
                ..Default::default()
            },
            ..Default::default()
        };
        let auth = AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(AdminPlugin::new())
            .plugin(TwoFactorPlugin::new())
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
                    }
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
                    let mut team_members = Vec::new();
                    for parent in &teams {
                        team_members.extend(team_member::Entity::find().filter(team_member::Column::TeamId.eq(&parent.id)).order_by_asc(team_member::Column::CreatedAt).all(&database).await?);
                    }
                    Ok::<_, better_auth_seaorm::sea_orm::DbErr>(json!({
                        "teams":teams.into_iter().map(|team|json!({"id":team.id,"name":team.name,"organizationId":team.organization_id,"createdAt":timestamp(team.created_at),"updatedAt":team.updated_at.map(timestamp),"memberCount":team.member_count})).collect::<Vec<_>>(),
                        "teamMembers":team_members.into_iter().map(|member|json!({"id":member.id,"teamId":member.team_id,"userId":member.user_id,"createdAt":timestamp(member.created_at)})).collect::<Vec<_>>(),
                        "roles":[],
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
