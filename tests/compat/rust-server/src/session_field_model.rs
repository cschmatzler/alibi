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
    use alibi::seaorm::JsonMetadata;
    #[cfg(feature = "seaorm")]
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    #[cfg(not(feature = "seaorm"))]
    use alibi::sqlx::JsonMetadata;
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm",
        derive(alibi::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "session")
    )]
    #[cfg_attr(
        not(feature = "seaorm"),
        derive(alibi::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "session")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "session", secondary_storage)]
    pub struct Model {
        #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "expiresAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "expiresAt"))]
        pub expires_at: DateTime<Utc>,
        pub token: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "createdAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "createdAt"))]
        pub created_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "updatedAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "updatedAt"))]
        pub updated_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "ipAddress"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "ipAddress"))]
        pub ip_address: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "userAgent"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "userAgent"))]
        pub user_agent: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "userId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "userId"))]
        pub user_id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "impersonatedBy"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "impersonatedBy"))]
        pub impersonated_by: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "activeOrganizationId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "activeOrganizationId"))]
        pub active_organization_id: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "activeTeamId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "activeTeamId"))]
        pub active_team_id: Option<String>,
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
use alibi::AuthSchema;

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
