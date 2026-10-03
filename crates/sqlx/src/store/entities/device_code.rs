use chrono::{DateTime, Utc};

bundled_model! {
    table = "device_code", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub device_code: String = "device_code",
        pub user_code: String = "user_code",
        pub user_id: Option<String> = "user_id",
        pub expires_at: DateTime<Utc> = "expires_at",
        pub status: String = "status",
        pub last_polled_at: Option<DateTime<Utc>> = "last_polled_at",
        pub polling_interval: Option<i64> = "polling_interval",
        pub client_id: Option<String> = "client_id",
        pub scope: Option<String> = "scope",
    }
}

impl From<&Model> for better_auth_core::DeviceCode {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            device_code: model.device_code.clone(),
            user_code: model.user_code.clone(),
            user_id: model.user_id.clone(),
            expires_at: model.expires_at,
            status: model.status.clone(),
            last_polled_at: model.last_polled_at,
            polling_interval: model.polling_interval,
            client_id: model.client_id.clone(),
            scope: model.scope.clone(),
        }
    }
}
