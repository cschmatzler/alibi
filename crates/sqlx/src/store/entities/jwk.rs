use chrono::{DateTime, Utc};

bundled_model! {
    table = "jwks", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub public_key: String = "public_key",
        pub private_key: String = "private_key",
        pub created_at: DateTime<Utc> = "created_at",
        pub expires_at: Option<DateTime<Utc>> = "expires_at",
        pub alg: Option<String> = "alg",
        pub crv: Option<String> = "crv",
    }
}

impl From<Model> for better_auth_core::types::Jwk {
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
