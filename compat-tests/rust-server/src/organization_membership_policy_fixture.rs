//! Immutable policies and observations of actual member admission/read SQL.
use crate::{CompatVerificationSender, EmailOutboxRecord, TestSchema};
use async_trait::async_trait;
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use better_auth::plugins::organization::{
    extensions::TeamLimitContext,
    types::{AddOrganizationMemberRequest, OrganizationResponse},
    MembershipLimit, OrganizationConfig, OrganizationLimitResolver,
    OrganizationMembershipLimitResolver, TeamsConfig,
};
use better_auth::wire::UserView;
use better_auth::{
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin, SessionManagementPlugin,
    },
    AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth,
};
use better_auth_seaorm::{
    sea_orm::{ConnectionTrait, DbBackend, Statement},
    DatabaseConnection, SeaOrmStore,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut result = serde_json::Map::new();
    for (name, sql, columns) in [
        (
            "organizations",
            "SELECT id,name,slug,logo,metadata FROM organization ORDER BY rowid",
            &["id", "name", "slug", "logo", "metadata"][..],
        ),
        (
            "members",
            "SELECT id,organization_id AS organizationId,user_id AS userId,role,created_at AS createdAt FROM member ORDER BY rowid",
            &["id", "organizationId", "userId", "role", "createdAt"][..],
        ),
        (
            "invitations",
            "SELECT id,organization_id AS organizationId,email,role,status,inviter_id AS inviterId,expires_at AS expiresAt,created_at AS createdAt,team_id AS teamId FROM invitation ORDER BY rowid",
            &[
                "id",
                "organizationId",
                "email",
                "role",
                "status",
                "inviterId",
                "expiresAt",
                "createdAt",
                "teamId",
            ][..],
        ),
        (
            "teams",
            "SELECT id,organization_id AS organizationId,name,member_count AS memberCount,created_at AS createdAt,updated_at AS updatedAt FROM team ORDER BY rowid",
            &[
                "id",
                "organizationId",
                "name",
                "memberCount",
                "createdAt",
                "updatedAt",
            ][..],
        ),
    ] {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut value = serde_json::Map::new();
            for key in columns {
                let field =
                    match *key {
                        "memberCount" => json!(
                            row.try_get::<i64>("", key)
                                .map_err(|e| AuthError::internal(e.to_string()))?
                        ),
                        "createdAt" | "updatedAt" | "expiresAt" => json!(
                            row.try_get::<Option<chrono::DateTime<chrono::Utc>>>("", key)
                                .map_err(|e| AuthError::internal(e.to_string()))?
                                .map(|value| value
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                        ),
                        _ => json!(
                            row.try_get::<Option<String>>("", key)
                                .map_err(|e| AuthError::internal(e.to_string()))?
                        ),
                    };
                let _ = value.insert((*key).into(), field);
            }
            values.push(Value::Object(value));
        }
        let _ = result.insert(name.into(), Value::Array(values));
    }
    Ok(Value::Object(result))
}
struct Policy {
    profile: &'static str,
    database: DatabaseConnection,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
#[async_trait]
impl OrganizationMembershipLimitResolver for Policy {
    async fn maximum_members(
        &self,
        user: &UserView,
        organization: &OrganizationResponse,
    ) -> AuthResult<f64> {
        tokio::task::yield_now().await;
        self.receipts.lock().await.push(json!({"phase":"membership-limit","profile":self.profile,"user":user,"organization":organization,"snapshot":snapshot(&self.database).await?}));
        if self.profile.ends_with("error") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("MEMBERSHIP_POLICY_REJECTED".into()),
                message: "Actual membership policy rejected".into(),
            });
        }
        Ok(if self.profile.contains("resolver-zero") {
            0.0
        } else if self.profile.ends_with("nan") {
            f64::NAN
        } else {
            1.5
        })
    }
}
#[async_trait]
impl OrganizationLimitResolver for Policy {
    async fn maximum_team_members(&self, context: &TeamLimitContext) -> AuthResult<Option<usize>> {
        tokio::task::yield_now().await;
        self.receipts.lock().await.push(json!({"phase":"team-limit","context":{"teamId":context.team_id,"organizationId":context.organization_id,"session":{"user":context.user,"session":context.session}},"snapshot":snapshot(&self.database).await?}));
        Ok(Some(0))
    }
}
fn failure(error: AuthError) -> Response {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if matches!(error, AuthError::Database(_) | AuthError::Unauthenticated) {
        return status.into_response();
    }
    let (_, code, message) = error.error_payload();
    (
        status,
        Json(match code {
            Some(code) => json!({"code":code,"message":message}),
            None => json!({"message":message}),
        }),
    )
        .into_response()
}
pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
) -> AuthResult<Router> {
    let receipts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let mut router = Router::new();
    let mut profiles = HashMap::<String, (Arc<BetterAuth<TestSchema>>, OrganizationConfig)>::new();
    for name in [
        "org-membership-default",
        "org-membership-none",
        "org-membership-zero",
        "org-membership-nan",
        "org-membership-one",
        "org-membership-fractional",
        "org-membership-negative",
        "org-membership-infinity",
        "org-membership-resolver-zero",
        "org-membership-resolver-nan",
        "org-membership-resolver-fractional",
        "org-membership-resolver-error",
        "org-membership-page-one",
        "org-membership-page-zero",
        "org-membership-resolver-zero-team-limit",
        "org-membership-team-limit",
        "org-membership-pending-one",
    ] {
        let policy = Arc::new(Policy {
            profile: name,
            database: database.clone(),
            receipts: receipts.clone(),
        });
        let limit = if name.contains("resolver") {
            Some(MembershipLimit::Resolver(policy.clone()))
        } else {
            match name {
                "org-membership-none" => None,
                "org-membership-zero" => Some(MembershipLimit::Fixed(0.0)),
                "org-membership-nan" => Some(MembershipLimit::Fixed(f64::NAN)),
                "org-membership-one" | "org-membership-pending-one" => {
                    Some(MembershipLimit::Fixed(1.0))
                }
                "org-membership-fractional" => Some(MembershipLimit::Fixed(1.5)),
                "org-membership-negative" => Some(MembershipLimit::Fixed(-0.5)),
                "org-membership-infinity" => Some(MembershipLimit::Fixed(f64::INFINITY)),
                _ => Some(MembershipLimit::Fixed(100.0)),
            }
        };
        let organization = OrganizationConfig {
            membership_limit: limit,
            invitation_limit: if name == "org-membership-pending-one" {
                Some(1)
            } else {
                Some(100)
            },
            require_email_verification_on_invitation: Some(true),
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                limit_resolver: if name.ends_with("team-limit") {
                    Some(policy)
                } else {
                    None
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name.contains("page-") {
            config.advanced.database.default_find_many_limit =
                if name.ends_with("one") { 1 } else { 0 };
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(
                    EmailVerificationPlugin::new().custom_send_verification_email(Arc::new(
                        CompatVerificationSender {
                            outbox: outbox.clone(),
                        },
                    )),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(organization.clone()))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name.to_owned(), (auth, organization));
    }
    let state = database.clone();
    let observe = receipts.clone();
    let reset = receipts.clone();
    Ok(router.route("/__test/organization-membership-policy/configure",post(move||{let receipts=reset.clone();async move{receipts.lock().await.clear();Json(json!({"configured":true}))}}))
 .route("/__test/organization-membership-policy/state",get(move|Query(_query):Query<HashMap<String,String>>|{let database=state.clone();let receipts=observe.clone();async move{Ok::<_,AuthError>(Json(json!({"receipts":receipts.lock().await.clone(),"snapshot":snapshot(&database).await?})))}}))
 .route("/__test/organization-membership-policy/server",post(move|headers:HeaderMap,Json(input):Json<Value>|{let profiles=profiles.clone();async move{
  let Some((auth,config))=input["profile"].as_str().and_then(|name|profiles.get(name))else{return StatusCode::NOT_FOUND.into_response();};
  let body=match serde_json::from_value::<AddOrganizationMemberRequest>(input["body"].clone()){Ok(body)=>body,Err(error)=>return failure(AuthError::bad_request(error.to_string()))};
  let headers=if input["useHeaders"].as_bool()==Some(true){headers.iter().filter_map(|(key,value)|value.to_str().ok().map(|value|(key.to_string(),value.to_owned()))).collect()}else{HashMap::new()};
  match OrganizationPlugin::with_config(config.clone()).add_member_with_headers(auth.context(),&headers,&body).await{Ok(member)=>Json(member).into_response(),Err(error)=>failure(error)}
 }})))
}
