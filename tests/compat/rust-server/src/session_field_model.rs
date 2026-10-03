//! A concrete application-owned session schema shared by SDK and native consumers.
#[cfg_attr(
    feature = "seaorm",
    expect(
        unreachable_pub,
        reason = "SeaORM public Entity requires public Model and Relation associated types"
    )
)]
pub mod application_session {
    #[cfg(feature = "seaorm")]
    use better_auth::seaorm::JsonMetadata;
    #[cfg(feature = "seaorm")]
    use better_auth::seaorm::sea_orm::{self, entity::prelude::*};
    #[cfg(not(feature = "seaorm"))]
    use better_auth::sqlx::JsonMetadata;
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm",
        derive(better_auth::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "sessions")
    )]
    #[cfg_attr(
        not(feature = "seaorm"),
        derive(better_auth::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "sessions")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "session", secondary_storage)]
    pub struct Model {
        #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        pub expires_at: DateTime<Utc>,
        pub token: String,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
        pub active_team_id: Option<String>,
        pub active: bool,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub number: Option<f64>,
        pub server_only: Option<String>,
        pub transformed: Option<String>,
        pub validated: Option<String>,
        pub callback: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_type = "JsonBinary"))]
        pub payload: JsonMetadata,
    }
    #[cfg(feature = "seaorm")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    // Each consumer implements `ActiveModelBehavior` for SeaORM: the native
    // integration tests observe model save hooks, while the fixture server
    // keeps the default behavior so both stores serve identical scenarios.
}
// The including module supplies the bundled `entities` of its store backend.
use super::entities::{account, user, verification};
use better_auth::AuthSchema;

#[expect(
    unreachable_pub,
    reason = "The private fixture module shares its concrete schema with SDK and native integration consumers"
)]
pub struct ApplicationSchema;
impl AuthSchema for ApplicationSchema {
    type User = user::Model;
    type Session = application_session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
