use chrono::{DateTime, Utc};

bundled_model! {
    table = "two_factor", primary_key = "id";
    #[derive(Clone, Debug, PartialEq)]
    pub struct Model {
        pub id: String = "id",
        pub secret: String = "secret",
        pub backup_codes: String = "backup_codes",
        pub user_id: String = "user_id",
        pub verified: Option<bool> = "verified",
        pub failed_verification_count: Option<f64> = "failed_verification_count",
        pub locked_until: Option<DateTime<Utc>> = "locked_until",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: DateTime<Utc> = "updated_at",
    }
}

impl From<&Model> for better_auth_core::TwoFactor {
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
