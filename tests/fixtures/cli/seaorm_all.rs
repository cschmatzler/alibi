use better_auth::AuthSchema;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
use better_auth::seaorm::{AuthEntity, DatabaseConnection};
mod user {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub is_anonymous: Option<bool>,
        pub phone_number: Option<String>,
        pub phone_number_verified: Option<bool>,
        pub last_login_method: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: Option<bool>,
        pub role: Option<String>,
        pub banned: Option<bool>,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "sessions")]
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
        pub active: bool,
        pub active_team_id: Option<String>,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod account {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "accounts")]
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
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod verification {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod wallet_address {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "wallet_address")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub user_id: String,
        pub address: String,
        pub chain_id: f64,
        pub is_primary: bool,
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod jwk {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "jwks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub public_key: String,
        pub private_key: String,
        pub created_at: DateTimeUtc,
        pub expires_at: Option<DateTimeUtc>,
        pub alg: Option<String>,
        pub crv: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod team {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "team")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub organization_id: String,
        pub member_count: i64,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod team_member {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "team_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub team_id: String,
        pub user_id: String,
        pub membership_key: Option<String>,
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod organization_role {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "organization_role")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub role: String,
        pub permission: String,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<DateTimeUtc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod two_factor {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "two_factor")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub secret: String,
        pub backup_codes: String,
        pub user_id: String,
        pub verified: Option<bool>,
        pub failed_verification_count: Option<f64>,
        pub locked_until: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod device_code {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "device_code")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub device_code: String,
        pub user_code: String,
        pub user_id: Option<String>,
        pub expires_at: DateTimeUtc,
        pub status: String,
        pub last_polled_at: Option<DateTimeUtc>,
        pub polling_interval: Option<i64>,
        pub client_id: Option<String>,
        pub scope: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod organization {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "organization")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        pub metadata: Option<Json>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod member {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        pub role: String,
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod invitation {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "invitation")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub email: String,
        pub role: String,
        pub team_id: Option<String>,
        pub status: String,
        pub inviter_id: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod api_key {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "api_keys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub start: Option<String>,
        pub prefix: Option<String>,
        #[sea_orm(column_name = "key")]
        pub key_hash: String,
        pub reference_id: String,
        #[sea_orm(default_value = "default")]
        pub config_id: String,
        pub refill_interval: Option<f64>,
        pub refill_amount: Option<f64>,
        pub last_refill_at: Option<DateTimeUtc>,
        pub enabled: bool,
        pub rate_limit_enabled: bool,
        pub rate_limit_time_window: Option<f64>,
        pub rate_limit_max: Option<f64>,
        pub request_count: Option<f64>,
        pub remaining: Option<f64>,
        pub last_request: Option<DateTimeUtc>,
        pub expires_at: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub permissions: Option<String>,
        pub metadata: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod passkey {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "passkeys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub public_key: String,
        pub user_id: String,
        pub credential_id: String,
        pub counter: i64,
        pub device_type: String,
        pub backed_up: bool,
        pub transports: Option<String>,
        pub credential: String,
        pub aaguid: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
pub async fn run_app_migrations(
    database: &DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(user::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(session::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(account::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(verification::Entity).if_not_exists().to_owned(),
        schema
            .create_table_from_entity(wallet_address::Entity)
            .if_not_exists()
            .to_owned(),
        schema.create_table_from_entity(jwk::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(team::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(team_member::Entity).if_not_exists().to_owned(),
        schema
            .create_table_from_entity(organization_role::Entity)
            .if_not_exists()
            .to_owned(),
        schema.create_table_from_entity(two_factor::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(device_code::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(organization::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(member::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(invitation::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(api_key::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(passkey::Entity).if_not_exists().to_owned(),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}
