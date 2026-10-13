use crate::SqlxModel;
use alibi_core::types::Jwk;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "jwks")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "publicKey")]
    pub public_key: String,
    #[sqlx(rename = "privateKey")]
    pub private_key: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

impl From<Model> for Jwk {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            public_key: row.public_key,
            private_key: row.private_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            alg: row.alg,
            crv: row.crv,
        }
    }
}
