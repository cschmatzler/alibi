//! A concrete application-owned session schema shared by SDK and native consumers.
#[expect(
    unreachable_pub,
    reason = "SeaORM public Entity requires public Model and Relation associated types"
)]
pub mod application_session {
    use better_auth::seaorm::{self, sea_orm::entity::prelude::*};
    use seaorm::sea_orm::{self, Set, Statement};
    use serde::Serialize;
    #[derive(seaorm::AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
    #[auth(role = "session", secondary_storage)]
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
        #[sea_orm(column_type = "JsonBinary")]
        pub payload: seaorm::JsonMetadata,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[async_trait::async_trait]
    impl ActiveModelBehavior for ActiveModel {
        async fn before_save<C>(mut self, db: &C, insert: bool) -> Result<Self, DbErr>
        where
            C: ConnectionTrait,
        {
            let label = self.label.clone().unwrap();
            _ = db
                .execute_raw(Statement::from_sql_and_values(
                    db.get_database_backend(),
                    "INSERT INTO session_model_events (phase, label, is_insert) VALUES (?, ?, ?)",
                    ["before".into(), label.clone().into(), insert.into()],
                ))
                .await?;
            if label.as_deref() == Some("native-hook") {
                self.label = Set(Some("model-override".into()));
            }
            Ok(self)
        }
        async fn after_save<C>(model: Model, db: &C, insert: bool) -> Result<Model, DbErr>
        where
            C: ConnectionTrait,
        {
            _ = db
                .execute_raw(Statement::from_sql_and_values(
                    db.get_database_backend(),
                    "INSERT INTO session_model_events (phase, label, is_insert) VALUES (?, ?, ?)",
                    ["after".into(), model.label.clone().into(), insert.into()],
                ))
                .await?;
            Ok(model)
        }
    }
}
use better_auth::AuthSchema;
use better_auth_seaorm::store::entities::{account, user, verification};

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
