//! Published organization members have row identities, not unique user/org pairs.
use sea_orm::{DbBackend, Statement};
use sea_orm_migration::prelude::*;

pub(super) struct MemberPairMultiplicity;

impl MigrationName for MemberPairMultiplicity {
    fn name(&self) -> &'static str {
        "m20261001_000015_member_pair_multiplicity"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for MemberPairMultiplicity {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const INDEX: &str = "idx_member_org_user_unique";
        // Keep the recorded initial schema unchanged. Fresh databases and
        // populated installations remove only this extra pair restriction.
        if manager.has_index("member", INDEX).await? {
            if manager.get_database_backend() == DbBackend::Sqlite {
                ensure_no_dependent_pair_reference(manager).await?;
            }
            manager
                .drop_index(
                    Index::drop()
                        .name(INDEX)
                        .table(Alias::new("member"))
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
                [name.clone().into(), "member".into()],
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
                && ["organization_id", "user_id"].iter().all(|expected| {
                    columns.values().any(|column| {
                        column
                            .as_deref()
                            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                    })
                })
            {
                return Err(DbErr::Migration(format!(
                    "Cannot remove member pair index: application table {name:?} references member(organization_id,user_id); migrate that foreign key to member(id) first"
                )));
            }
        }
    }
    Ok(())
}
