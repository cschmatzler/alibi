//! Trusted fixture writes for exercising actual persisted timestamp precision.

use axum::{Json, Router, http::StatusCode, routing::post};
use alibi_seaorm::sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Set,
};
use alibi_seaorm::store::entities::{member, organization};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimestampRequest {
    organization_id: String,
    member_id: String,
    created_at: DateTime<Utc>,
}

async fn write_timestamp(
    database: &DatabaseConnection,
    body: TimestampRequest,
) -> Result<Value, alibi_seaorm::sea_orm::DbErr> {
    let org = organization::Entity::find_by_id(&body.organization_id)
        .one(database)
        .await?;
    let member = member::Entity::find_by_id(&body.member_id)
        .one(database)
        .await?;
    let (Some(org), Some(member)) = (org, member) else {
        return Ok(Value::Null);
    };
    if member.organization_id != org.id {
        return Ok(Value::Null);
    }
    let mut org = org.into_active_model();
    org.created_at = Set(body.created_at);
    org.updated_at = Set(body.created_at);
    org.update(database).await?;
    let mut member = member.into_active_model();
    member.created_at = Set(body.created_at);
    member.update(database).await?;
    let org = organization::Entity::find_by_id(body.organization_id)
        .one(database)
        .await?
        .unwrap();
    let member = member::Entity::find_by_id(body.member_id)
        .one(database)
        .await?
        .unwrap();
    Ok(
        json!({"organizationId":org.id,"memberId":member.id,"userId":member.user_id,"organizationCreatedAtMillis":org.created_at.timestamp_millis(),"memberCreatedAtMillis":member.created_at.timestamp_millis()}),
    )
}

pub(crate) fn router(
    database: DatabaseConnection,
) -> Router<Arc<alibi::BetterAuth<crate::TestSchema>>> {
    Router::new().route(
        "/__test/organization-timestamps",
        post(move |Json(body): Json<TimestampRequest>| {
            let database = database.clone();
            async move {
                match write_timestamp(&database, body).await {
                    Ok(Value::Null) => {
                        (StatusCode::NOT_FOUND, Json(json!({"message":"Not found"})))
                    }
                    Ok(value) => (StatusCode::OK, Json(value)),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"message":error.to_string()})),
                    ),
                }
            }
        }),
    )
}
