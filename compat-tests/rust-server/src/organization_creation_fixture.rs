//! Private organization creation configurations and real SQLite state observations.
use crate::TestSchema;
use axum::{
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationCreationPolicy, RolePermissions,
};
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::wire::UserView;
use better_auth_core::{store::OrganizationStore, UpdateOrganization};
use better_auth_seaorm::sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    Statement,
};
use better_auth_seaorm::store::entities::{member, organization, session, user};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
#[derive(Debug)]
struct Policy {
    database: DatabaseConnection,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl Policy {
    async fn record(&self, operation: &str, user: &UserView) {
        self.receipts.lock().await.push(
            json!({"operation":operation,"userId":user.id,"email":user.email,"name":user.name}),
        );
    }
}
#[async_trait::async_trait]
impl OrganizationCreationPolicy for Policy {
    async fn allow_creation(&self, user: &UserView) -> AuthResult<Option<bool>> {
        self.record("allow", user).await;
        if user.name.as_deref() == Some("Reject Allow") {
            return Err(AuthError::Upstream {
                status: 403,
                code: "CREATION_ALLOW_REJECTED",
                message: "Creation allow callback rejected",
            });
        }
        Ok(Some(
            user.name
                .as_deref()
                .is_some_and(|name| name.starts_with("Paid")),
        ))
    }
    async fn limit_reached(&self, user: &UserView) -> AuthResult<Option<bool>> {
        self.record("limit", user).await;
        if user.name.as_deref() == Some("Paid Reject Limit") {
            return Err(AuthError::Upstream {
                status: 403,
                code: "CREATION_LIMIT_REJECTED",
                message: "Creation limit callback rejected",
            });
        }
        let count = member::Entity::find()
            .filter(member::Column::UserId.eq(&user.id))
            .count(&self.database)
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
        Ok(Some(count >= 1))
    }
}
#[derive(Deserialize)]
struct StateQuery {
    email: String,
    #[serde(default, rename = "includeMetadata")]
    include_metadata: bool,
    #[serde(default, rename = "includeLogo")]
    include_logo: bool,
}
#[derive(Deserialize)]
struct ServerRequest {
    profile: String,
    user_id: String,
    name: String,
    slug: String,
}
#[derive(Clone)]
struct Profile {
    name: &'static str,
    auth: Arc<BetterAuth<TestSchema>>,
    config: OrganizationConfig,
}
fn failure(error: AuthError) -> (StatusCode, Json<Value>) {
    let status = StatusCode::from_u16(error.status_code()).unwrap();
    let value = match error {
        AuthError::Upstream { code, message, .. } => json!({"code":code,"message":message}),
        AuthError::Api { code, message, .. } => match code {
            Some(code) => json!({"code":code,"message":message}),
            None => json!({"message":message}),
        },
        AuthError::Unauthenticated => Value::Null,
        error => json!({"message":error.to_string()}),
    };
    (status, Json(value))
}
pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let mut router = Router::new();
    let mut profiles = Vec::new();
    for name in [
        "org-creation-denied",
        "org-creation-limit",
        "org-creation-negative",
        "org-creation-infinity",
        "org-creation-nan",
        "org-creation-callback",
        "org-creation-founder",
        "org-creation-empty-role",
    ] {
        let mut config = OrganizationConfig::default();
        match name {
            "org-creation-denied" => config.allow_user_to_create_organization = false,
            "org-creation-limit" => config.organization_limit = Some(1.5),
            "org-creation-negative" => config.organization_limit = Some(-0.5),
            "org-creation-infinity" => config.organization_limit = Some(f64::INFINITY),
            "org-creation-nan" => config.organization_limit = Some(f64::NAN),
            "org-creation-callback" => {
                config.allow_user_to_create_organization = false;
                config.organization_limit = Some(-0.5);
                config.creation_policy = Some(Arc::new(Policy {
                    database: database.clone(),
                    receipts: receipts.clone(),
                }))
            }
            "org-creation-empty-role" => config.creator_role = String::new(),
            "org-creation-founder" => {
                config.creator_role = "founder".into();
                config.roles = Some(HashMap::from([
                    (
                        "founder".into(),
                        RolePermissions {
                            invitation: vec!["create".into()],
                            ..Default::default()
                        },
                    ),
                    (
                        "editor".into(),
                        RolePermissions {
                            organization: vec!["update".into()],
                            ..Default::default()
                        },
                    ),
                ]));
            }
            _ => unreachable!(),
        }
        let path = format!("/__test/profiles/{name}/api/auth");
        let auth_config = base.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(auth_config.clone())
                .store(SeaOrmStore::<TestSchema>::new(
                    auth_config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(config.clone()))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.push(Profile { name, auth, config });
    }
    let state_database = database.clone();
    router = router.route(
        "/__test/organization-creation-state",
        get(move |Query(query): Query<StateQuery>| {
            let db = state_database.clone();
            let receipts = receipts.clone();
            async move {
                let found = user::Entity::find()
                    .filter(user::Column::Email.eq(&query.email))
                    .one(&db)
                    .await
                    .unwrap();
                let mut organizations = Vec::new();
                let mut sessions = Vec::new();
                if let Some(found) = found {
                    let mut joined = Vec::new();
                    for row in member::Entity::find()
                        .filter(member::Column::UserId.eq(&found.id))
                        .all(&db)
                        .await
                        .unwrap()
                    {
                        if let Some(org) = organization::Entity::find_by_id(&row.organization_id)
                            .one(&db)
                            .await
                            .unwrap()
                        {
                            let mut value = json!({
                                "id": org.id, "name": org.name, "slug": org.slug,
                                "memberId": row.id, "userId": row.user_id, "role": row.role
                            });
                            if query.include_logo {
                                value["logo"] = json!(org.logo);
                            }
                            if query.include_metadata {
                                let metadata = db
                                    .query_one_raw(Statement::from_sql_and_values(
                                        DbBackend::Sqlite,
                                        "SELECT metadata FROM organization WHERE id = ?",
                                        [org.id.clone().into()],
                                    ))
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .try_get::<Option<String>>("", "metadata")
                                    .unwrap();
                                value["metadata"] = json!(metadata);
                            }
                            joined.push((org.created_at, org.id.clone(), value));
                        }
                    }
                    joined.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
                    organizations = joined.into_iter().map(|(_, _, value)| value).collect();
                    sessions = session::Entity::find()
                        .filter(session::Column::UserId.eq(&found.id))
                        .order_by_asc(session::Column::CreatedAt)
                        .order_by_asc(session::Column::Id)
                        .all(&db)
                        .await
                        .unwrap()
                        .into_iter()
                        .map(|row| {
                            json!({
                                "id": row.id, "token": row.token, "userId": row.user_id,
                                "activeOrganizationId": row.active_organization_id
                            })
                        })
                        .collect();
                }
                let mut orphan_organizations = Vec::new();
                for org in organization::Entity::find()
                    .order_by_asc(organization::Column::CreatedAt)
                    .order_by_asc(organization::Column::Id)
                    .all(&db)
                    .await
                    .unwrap()
                {
                    if member::Entity::find()
                        .filter(member::Column::OrganizationId.eq(&org.id))
                        .count(&db)
                        .await
                        .unwrap()
                        == 0
                    {
                        orphan_organizations
                            .push(json!({"id":org.id,"name":org.name,"slug":org.slug}));
                    }
                }
                Json(json!({
                    "orphanOrganizations": orphan_organizations,
                    "organizations": organizations,
                    "sessions": sessions,
                    "receipts": receipts.lock().await.iter()
                        .filter(|receipt| receipt["email"] == query.email)
                        .cloned().collect::<Vec<_>>()
                }))
            }
        }),
    );
    let legacy_store = Arc::new(SeaOrmStore::<TestSchema>::new(base.clone(), database));
    router = router.route(
        "/__test/organization-metadata-legacy",
        post(move |Json(body): Json<Value>| {
            let store = legacy_store.clone();
            async move {
                let Some(id) = body["organizationId"].as_str() else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message":"organizationId required"})),
                    );
                };
                match store
                    .update_organization(
                        id,
                        UpdateOrganization {
                            metadata: Some(Value::Null),
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(value) => (StatusCode::OK, Json(json!({"id":value.id}))),
                    Err(error) => failure(error),
                }
            }
        }),
    );
    Ok(router.route(
        "/__test/organization-create",
        post(move |Json(body): Json<Value>| {
            let profiles = profiles.clone();
            async move {
                let request: ServerRequest = match serde_json::from_value(json!({
                    "profile": body["profile"], "user_id": body["userId"],
                    "name": body["name"], "slug": body["slug"]
                })) {
                    Ok(request) => request,
                    Err(error) => return failure(AuthError::bad_request(error.to_string())),
                };
                let Some(profile) = profiles
                    .iter()
                    .find(|profile| profile.name == request.profile)
                else {
                    return failure(AuthError::bad_request("Unknown fixture profile"));
                };
                let data = better_auth::plugins::organization::types::CreateOrganizationRequest {
                    name: request.name,
                    slug: request.slug,
                    logo: None,
                    metadata: body.get("metadata").cloned(),
                    keep_current_active_organization: None,
                };
                match OrganizationPlugin::with_config(profile.config.clone())
                    .create_organization_for_user(profile.auth.context(), &request.user_id, &data)
                    .await
                {
                    Ok(value) => (StatusCode::OK, Json(serde_json::to_value(value).unwrap())),
                    Err(error) => failure(error),
                }
            }
        }),
    ))
}
