#[cfg(feature = "seaorm")]
use alibi_seaorm::store::entities;

/// The application-owned session schema the Rust fixture server also serves.
#[cfg(feature = "seaorm")]
#[path = "../../../compat/rust-server/src/session_field_model.rs"]
mod application_model;

/// SeaORM model save hooks: record each save and override the native label,
/// as an application's `ActiveModelBehavior` would.
#[cfg(feature = "seaorm")]
#[async_trait::async_trait]
impl alibi_seaorm::sea_orm::ActiveModelBehavior
    for application_model::application_session::ActiveModel
{
    async fn before_save<C>(
        mut self,
        db: &C,
        insert: bool,
    ) -> Result<Self, alibi_seaorm::sea_orm::DbErr>
    where
        C: alibi_seaorm::sea_orm::ConnectionTrait,
    {
        use alibi_seaorm::sea_orm::{ActiveValue, Statement};
        let label = self.label.clone().unwrap();
        _ = db
            .execute_raw(Statement::from_sql_and_values(
                db.get_database_backend(),
                "INSERT INTO session_model_events (phase, label, is_insert) VALUES (?, ?, ?)",
                ["before".into(), label.clone().into(), insert.into()],
            ))
            .await?;
        if label.as_deref() == Some("native-hook") {
            self.label = ActiveValue::Set(Some("model-override".into()));
        }
        Ok(self)
    }

    async fn after_save<C>(
        model: application_model::application_session::Model,
        db: &C,
        insert: bool,
    ) -> Result<application_model::application_session::Model, alibi_seaorm::sea_orm::DbErr>
    where
        C: alibi_seaorm::sea_orm::ConnectionTrait,
    {
        _ = db
            .execute_raw(alibi_seaorm::sea_orm::Statement::from_sql_and_values(
                db.get_database_backend(),
                "INSERT INTO session_model_events (phase, label, is_insert) VALUES (?, ?, ?)",
                ["after".into(), model.label.clone().into(), insert.into()],
            ))
            .await?;
        Ok(model)
    }
}

#[cfg(feature = "seaorm")]
mod cookie_cache;
mod cookie_name;
#[cfg(feature = "seaorm")]
mod fields;
mod policy_error;
mod refresh;
