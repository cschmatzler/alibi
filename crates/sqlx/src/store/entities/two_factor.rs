use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "two_factor")]
pub struct Model {
    pub id: String,
    pub secret: String,
    pub backup_codes: String,
    pub user_id: String,
    pub verified: Option<bool>,
    pub failed_verification_count: Option<f64>,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Model> for alibi_core::TwoFactor {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone(),
            verified: model.verified,
            failed_verification_count: model.failed_verification_count,
            locked_until: model.locked_until,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
