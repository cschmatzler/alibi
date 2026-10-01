//! Published organization members have row identities, not unique user/org pairs.
use sea_orm_migration::prelude::*;

pub(super) struct MemberPairMultiplicity;

impl MigrationName for MemberPairMultiplicity {
    fn name(&self) -> &str {
        "m20261001_000015_member_pair_multiplicity"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for MemberPairMultiplicity {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const INDEX: &str = "idx_member_org_user_unique";
        // Keep the recorded initial schema unchanged. Fresh databases and
        // populated installations remove only this extra pair restriction.
        if manager.has_index("member", INDEX).await? {
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
