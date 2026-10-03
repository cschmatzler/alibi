use chrono::{DateTime, Utc};

bundled_model! {
    table = "passkeys", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub name: Option<String> = "name",
        pub public_key: String = "public_key",
        pub user_id: String = "user_id",
        pub credential_id: String = "credential_id",
        pub counter: i64 = "counter",
        pub device_type: String = "device_type",
        pub backed_up: bool = "backed_up",
        pub transports: Option<String> = "transports",
        pub credential: String = "credential",
        pub aaguid: Option<String> = "aaguid",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: DateTime<Utc> = "updated_at",
    }
}

impl From<&Model> for better_auth_core::Passkey {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model.transports.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
            aaguid: model.aaguid.clone(),
            credential: model.credential.clone(),
        }
    }
}
