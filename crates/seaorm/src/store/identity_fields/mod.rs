//! Add plugin identity fields without changing the installed migration history.

#[cfg(test)]
mod tests;

use super::entities::{session, user};
use sea_orm::EntityName;
use sea_orm_migration::prelude::*;

pub(super) struct PluginIdentityFields;

impl MigrationName for PluginIdentityFields {
    fn name(&self) -> &'static str {
        "m20260930_000001_plugin_identity_fields"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for PluginIdentityFields {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (column, mut definition) in [
            (
                "is_anonymous",
                ColumnDef::new(user::Column::IsAnonymous)
                    .boolean()
                    .to_owned(),
            ),
            (
                "phone_number",
                ColumnDef::new(user::Column::PhoneNumber)
                    .string()
                    .to_owned(),
            ),
            (
                "phone_number_verified",
                ColumnDef::new(user::Column::PhoneNumberVerified)
                    .boolean()
                    .to_owned(),
            ),
            (
                "last_login_method",
                ColumnDef::new(user::Column::LastLoginMethod)
                    .string()
                    .to_owned(),
            ),
        ] {
            if !manager
                .has_column(user::Entity.table_name(), column)
                .await?
            {
                manager
                    .alter_table(
                        Table::alter()
                            .table(user::Entity)
                            .add_column(&mut definition)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        manager
            .create_index(
                Index::create()
                    .name("idx_users_phone_number_unique")
                    .table(user::Entity)
                    .col(user::Column::PhoneNumber)
                    .unique()
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        if !manager
            .has_column(session::Entity.table_name(), "active_team_id")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .add_column(ColumnDef::new(session::Column::ActiveTeamId).string())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
