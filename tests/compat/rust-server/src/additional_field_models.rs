//! Actual user, session and account columns with canonical accessor names.
pub(super) mod application_user {
    use better_auth::seaorm::{self, sea_orm::entity::prelude::*};
    use seaorm::sea_orm;
    use serde::Serialize;
    #[derive(seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "app_user")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "display_name")]
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "user_label")]
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
        pub readonly: Option<String>,
        pub role: Option<String>,
        #[sea_orm(default_value = "physical-private")]
        #[serde(rename = "private_column")]
        pub private_column: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_session {
    use better_auth::seaorm::{self, sea_orm::entity::prelude::*};
    use seaorm::sea_orm;
    use serde::Serialize;
    #[derive(seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "app_session")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        #[serde(skip)]
        pub active: bool,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_account {
    use better_auth::seaorm::{self, sea_orm::entity::prelude::*};
    use seaorm::sea_orm;
    use serde::Serialize;
    #[derive(seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "app_account")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) struct ApplicationSchema;
impl better_auth::AuthSchema for ApplicationSchema {
    type User = application_user::Model;
    type Session = application_session::Model;
    type Account = application_account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}
