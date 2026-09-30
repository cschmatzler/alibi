//! Fixture-only persisted-state inspection; these are not authentication endpoints.

use crate::TestSchema;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use better_auth::{
    prelude::{AuthAccount, AuthSession, AuthUser},
    BetterAuth,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

type Auth = Arc<BetterAuth<TestSchema>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserQuery {
    user_id: String,
    profile: Option<String>,
}

async fn user_state(
    State(auth): State<Auth>,
    Query(query): Query<UserQuery>,
    axum::Extension(runtimes): axum::Extension<crate::phone_profiles::Runtimes>,
) -> (StatusCode, Json<Value>) {
    let result = async {
        let selected = if let Some(profile) = query.profile.as_ref() {
            &runtimes.get(profile).ok_or_else(||better_auth::AuthError::bad_request("unknown fixture profile"))?.auth
        } else { &auth };
        let store = selected.store();
        let user = store.get_user_by_id(&query.user_id).await?;
        let mut accounts = store.get_user_accounts(&query.user_id).await?;
        accounts.sort_by(|left, right| left.provider_id().cmp(right.provider_id()).then_with(|| left.account_id().cmp(right.account_id())));
        let mut sessions = store.get_user_sessions(&query.user_id).await?;
        sessions.sort_by_key(AuthSession::created_at);
        let two_factor = store.get_two_factor_by_user_id(&query.user_id).await?;
        Ok::<_, better_auth::AuthError>(json!({
            "user": user.map(|user| {
                let mut value=json!({"id":user.id(),"email":user.email(),"emailVerified":user.email_verified(),"twoFactorEnabled":user.two_factor_enabled_value()});
                if query.profile.is_some() {
                    value["phoneNumber"]=json!(user.phone_number());
                    value["phoneNumberVerified"]=json!(user.phone_number_verified());
                }
                value
            }),
            "accounts": accounts.iter().map(|account| json!({"id":account.id(),"userId":account.user_id(),"accountId":account.account_id(),"providerId":account.provider_id()})).collect::<Vec<_>>(),
            "sessions": sessions.iter().map(|session| json!({"id":session.id(),"token":session.token(),"userId":session.user_id(),"expiresAt":session.expires_at().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)})).collect::<Vec<_>>(),
            "twoFactorExists": two_factor.is_some()
        }))
    }.await;
    match result {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message":error.to_string()})),
        ),
    }
}

pub(super) fn router(runtimes: crate::phone_profiles::Runtimes) -> Router<Auth> {
    Router::new()
        .route("/__test/user-state", get(user_state))
        .layer(axum::Extension(runtimes))
}
