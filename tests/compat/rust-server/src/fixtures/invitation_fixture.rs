//! Controlled invitation clocks; these routes are outside the auth router.

use crate::TestSchema;
use alibi::BetterAuth;
use alibi::seaorm::sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use alibi::seaorm::store::entities::invitation;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpireInvitation {
    invitation_id: String,
    expires_at: DateTime<Utc>,
}

pub(crate) fn router(database: DatabaseConnection) -> Router<Arc<BetterAuth<TestSchema>>> {
    Router::new().route(
        "/__test/expire-invitation",
        post(
            move |State(_): State<Arc<BetterAuth<TestSchema>>>,
                  Json(body): Json<ExpireInvitation>| {
                let database = database.clone();
                async move {
                    match invitation::Entity::update_many()
                        .col_expr(
                            invitation::Column::ExpiresAt,
                            alibi::seaorm::sea_orm::sea_query::Expr::value(body.expires_at),
                        )
                        .filter(invitation::Column::Id.eq(body.invitation_id))
                        .exec(&database)
                        .await
                    {
                        Ok(result) => (
                            StatusCode::OK,
                            Json(json!({"updated": result.rows_affected})),
                        ),
                        Err(error) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(Value::String(error.to_string())),
                        ),
                    }
                }
            },
        ),
    )
}
