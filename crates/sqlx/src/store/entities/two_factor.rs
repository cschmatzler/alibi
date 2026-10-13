use crate::SqlxModel;
use alibi_core::TwoFactor;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, SqlxModel)]
#[auth(table = "twoFactor")]
pub struct Model {
    pub id: String,
    pub secret: String,
    #[sqlx(rename = "backupCodes")]
    pub backup_codes: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    pub verified: Option<bool>,
    #[sqlx(rename = "failedVerificationCount")]
    pub failed_verification_count: Option<crate::Number>,
    #[sqlx(rename = "lockedUntil")]
    pub locked_until: Option<DateTime<Utc>>,
}

impl From<&Model> for TwoFactor {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone(),
            verified: model.verified,
            failed_verification_count: model.failed_verification_count.map(|value| value.0),
            locked_until: model.locked_until,
        }
    }
}
