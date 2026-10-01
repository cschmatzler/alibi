//! OAuth account rows have identities; duplicate provider keys require fail-closed lookup.
use sea_orm::{DbBackend, Statement};
use sea_orm_migration::prelude::*;

pub(super) struct AccountKeyMultiplicity;

impl MigrationName for AccountKeyMultiplicity {
    fn name(&self) -> &'static str {
        "m20261001_000016_account_key_multiplicity"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for AccountKeyMultiplicity {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const INDEX: &str = "idx_accounts_provider_account";
        // Keep the recorded initial schema unchanged. Fresh databases and
        // populated installations remove only this extra pair restriction.
        if manager.has_index("accounts", INDEX).await? {
            if manager.get_database_backend() == DbBackend::Sqlite {
                ensure_no_dependent_pair_reference(manager).await?;
            }
            manager
                .drop_index(
                    Index::drop()
                        .name(INDEX)
                        .table(Alias::new("accounts"))
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_index("accounts", "idx_accounts_provider_account_lookup")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("idx_accounts_provider_account_lookup")
                        .table(Alias::new("accounts"))
                        .col(Alias::new("provider_id"))
                        .col(Alias::new("account_id"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    #[expect(
        elided_lifetimes_in_paths,
        reason = "MigrationTrait requires late-bound manager lifetime"
    )]
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let duplicate = manager.get_connection().query_one_raw(Statement::from_string(manager.get_database_backend(), "SELECT provider_id,account_id FROM accounts GROUP BY provider_id,account_id HAVING COUNT(*) > 1 LIMIT 1")).await?;
        if duplicate.is_some() {
            return Err(DbErr::Migration("Cannot restore account provider-key uniqueness while duplicate rows exist; resolve their row identities before rollback".into()));
        }
        if !manager
            .has_index("accounts", "idx_accounts_provider_account")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("idx_accounts_provider_account")
                        .table(Alias::new("accounts"))
                        .col(Alias::new("provider_id"))
                        .col(Alias::new("account_id"))
                        .unique()
                        .to_owned(),
                )
                .await?;
        }
        if manager
            .has_index("accounts", "idx_accounts_provider_account_lookup")
            .await?
        {
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_accounts_provider_account_lookup")
                        .table(Alias::new("accounts"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

// SQLite permits dropping the parent index but leaves an incoming composite FK
// unusable. Read catalog names as bound data, and refuse before the first write.
async fn ensure_no_dependent_pair_reference(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    let tables = connection
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_schema WHERE type = 'table'",
        ))
        .await?;
    for table in tables {
        let name: String = table.try_get("", "name")?;
        let references = connection
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                r#"SELECT id,seq,"to" FROM pragma_foreign_key_list(?) WHERE "table" = ? COLLATE NOCASE"#,
                [name.clone().into(), "accounts".into()],
            ))
            .await?;
        let mut groups = std::collections::BTreeMap::<
            i64,
            std::collections::BTreeMap<i64, Option<String>>,
        >::new();
        for reference in references {
            drop(
                groups
                    .entry(reference.try_get("", "id")?)
                    .or_default()
                    .insert(reference.try_get("", "seq")?, reference.try_get("", "to")?),
            );
        }
        for columns in groups.values() {
            if columns.len() == 2
                && ["provider_id", "account_id"].iter().all(|expected| {
                    columns.values().any(|column| {
                        column
                            .as_deref()
                            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                    })
                })
            {
                return Err(DbErr::Migration(format!(
                    "Cannot remove account provider-key index: application table {name:?} references accounts(provider_id,account_id); migrate that foreign key to accounts(id) first"
                )));
            }
        }
    }
    Ok(())
}
