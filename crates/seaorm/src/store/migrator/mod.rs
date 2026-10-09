//! The bundled auth schema as one `SeaORM` migration.

use super::entities::{
    account, api_key, device_code, invitation, jwk, member, organization, organization_role,
    passkey, session, team, team_member, two_factor, user, verification, wallet_address,
};
use sea_orm::EntityName;
use sea_orm::sea_query::IntoIden;
use sea_orm_migration::prelude::*;

/// Bundled authentication schema migrations, recorded in `better_auth_migrations`.
#[derive(Debug)]
pub struct AuthMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(AuthSchemaMigration)]
    }

    fn migration_table_name() -> DynIden {
        "better_auth_migrations".into_iden()
    }
}

///
/// # Errors
///
/// Propagates database or migration errors.
pub async fn run_migrations(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    AuthMigrator::up(db, None).await
}

struct AuthSchemaMigration;

impl MigrationName for AuthSchemaMigration {
    fn name(&self) -> &'static str {
        "m20261003_000001_auth_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for AuthSchemaMigration {
    // Every table and index is created or none is.
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_users(manager).await?;
        create_sessions(manager).await?;
        create_accounts(manager).await?;
        create_verifications(manager).await?;
        create_organizations(manager).await?;
        create_members(manager).await?;
        create_invitations(manager).await?;
        create_two_factor(manager).await?;
        create_api_keys(manager).await?;
        create_passkeys(manager).await?;
        create_device_codes(manager).await?;
        create_teams(manager).await?;
        create_organization_roles(manager).await?;
        create_jwks(manager).await?;
        create_wallet_addresses(manager).await?;
        Ok(())
    }

    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            wallet_address::Entity.table_ref(),
            jwk::Entity.table_ref(),
            organization_role::Entity.table_ref(),
            team_member::Entity.table_ref(),
            team::Entity.table_ref(),
            device_code::Entity.table_ref(),
            passkey::Entity.table_ref(),
            api_key::Entity.table_ref(),
            two_factor::Entity.table_ref(),
            invitation::Entity.table_ref(),
            member::Entity.table_ref(),
            organization::Entity.table_ref(),
            verification::Entity.table_ref(),
            account::Entity.table_ref(),
            session::Entity.table_ref(),
            user::Entity.table_ref(),
        ] {
            manager
                .drop_table(Table::drop().table(table).if_exists().to_owned())
                .await?;
        }
        Ok(())
    }
}

async fn create_index<T: IntoTableRef>(
    manager: &SchemaManager<'_>,
    name: &str,
    table: T,
    columns: &[&str],
    unique: bool,
) -> Result<(), DbErr> {
    let mut index = Index::create();
    let _ignored_table = index.name(name).table(table);
    for column in columns {
        let _ignored_column = index.col(Alias::new(*column));
    }
    if unique {
        let _ignored_unique = index.unique();
    }
    manager.create_index(index.clone()).await
}

fn cascade_to_user<F: IntoTableRef, C: IntoIden>(
    name: &str,
    from: F,
    column: C,
) -> ForeignKeyCreateStatement {
    ForeignKey::create()
        .name(name)
        .from(from, column)
        .to(user::Entity, user::Column::Id)
        .on_delete(ForeignKeyAction::Cascade)
        .to_owned()
}

fn timestamp<C: IntoIden>(column: C) -> ColumnDef {
    ColumnDef::new(column)
        .timestamp_with_time_zone()
        .not_null()
        .to_owned()
}

fn primary_key<C: IntoIden>(column: C) -> ColumnDef {
    ColumnDef::new(column)
        .string()
        .not_null()
        .primary_key()
        .to_owned()
}

fn required<C: IntoIden>(column: C) -> ColumnDef {
    ColumnDef::new(column).string().not_null().to_owned()
}

async fn create_users(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(user::Entity)
                .col(primary_key(user::Column::Id))
                .col(ColumnDef::new(user::Column::Name).string())
                .col(ColumnDef::new(user::Column::Email).string().unique_key())
                .col(
                    ColumnDef::new(user::Column::EmailVerified)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(user::Column::Image).string())
                .col(ColumnDef::new(user::Column::Username).string().unique_key())
                .col(ColumnDef::new(user::Column::DisplayUsername).string())
                .col(ColumnDef::new(user::Column::TwoFactorEnabled).boolean())
                .col(ColumnDef::new(user::Column::Role).string())
                .col(ColumnDef::new(user::Column::Banned).boolean())
                .col(ColumnDef::new(user::Column::BanReason).string())
                .col(ColumnDef::new(user::Column::BanExpires).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(user::Column::Metadata)
                        .json_binary()
                        .not_null(),
                )
                .col(timestamp(user::Column::CreatedAt))
                .col(timestamp(user::Column::UpdatedAt))
                .col(ColumnDef::new(user::Column::IsAnonymous).boolean())
                .col(ColumnDef::new(user::Column::PhoneNumber).string())
                .col(ColumnDef::new(user::Column::PhoneNumberVerified).boolean())
                .col(ColumnDef::new(user::Column::LastLoginMethod).string())
                .to_owned(),
        )
        .await?;
    create_index(manager, "idx_users_email", user::Entity, &["email"], false).await?;
    create_index(
        manager,
        "idx_users_username",
        user::Entity,
        &["username"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_users_phone_number_unique",
        user::Entity,
        &["phone_number"],
        true,
    )
    .await
}

async fn create_sessions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(session::Entity)
                .col(primary_key(session::Column::Id))
                .col(timestamp(session::Column::ExpiresAt))
                .col(required(session::Column::Token).unique_key())
                .col(ColumnDef::new(session::Column::IpAddress).string())
                .col(ColumnDef::new(session::Column::UserAgent).string())
                .col(required(session::Column::UserId))
                .col(ColumnDef::new(session::Column::ImpersonatedBy).string())
                .col(ColumnDef::new(session::Column::ActiveOrganizationId).string())
                .col(
                    ColumnDef::new(session::Column::Active)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(timestamp(session::Column::CreatedAt))
                .col(timestamp(session::Column::UpdatedAt))
                .col(ColumnDef::new(session::Column::ActiveTeamId).string())
                .foreign_key(&mut cascade_to_user(
                    "fk_sessions_user_id",
                    session::Entity,
                    session::Column::UserId,
                ))
                .to_owned(),
        )
        .await?;
    for (name, column) in [
        ("idx_sessions_token", "token"),
        ("idx_sessions_user_id", "user_id"),
        ("idx_sessions_expires_at", "expires_at"),
    ] {
        create_index(manager, name, session::Entity, &[column], false).await?;
    }
    Ok(())
}

async fn create_accounts(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(account::Entity)
                .col(primary_key(account::Column::Id))
                .col(required(account::Column::AccountId))
                .col(required(account::Column::ProviderId))
                .col(required(account::Column::UserId))
                .col(ColumnDef::new(account::Column::AccessToken).string())
                .col(ColumnDef::new(account::Column::RefreshToken).string())
                .col(ColumnDef::new(account::Column::IdToken).string())
                .col(
                    ColumnDef::new(account::Column::AccessTokenExpiresAt)
                        .timestamp_with_time_zone(),
                )
                .col(
                    ColumnDef::new(account::Column::RefreshTokenExpiresAt)
                        .timestamp_with_time_zone(),
                )
                .col(ColumnDef::new(account::Column::Scope).string())
                .col(ColumnDef::new(account::Column::Password).string())
                .col(timestamp(account::Column::CreatedAt))
                .col(timestamp(account::Column::UpdatedAt))
                .foreign_key(&mut cascade_to_user(
                    "fk_accounts_user_id",
                    account::Entity,
                    account::Column::UserId,
                ))
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_accounts_user_id",
        account::Entity,
        &["user_id"],
        false,
    )
    .await?;
    // Provider identities are not unique: duplicate rows make lookups fail closed.
    create_index(
        manager,
        "idx_accounts_provider_account_lookup",
        account::Entity,
        &["provider_id", "account_id"],
        false,
    )
    .await
}

async fn create_verifications(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(verification::Entity)
                .col(primary_key(verification::Column::Id))
                .col(required(verification::Column::Identifier))
                .col(required(verification::Column::Value))
                .col(timestamp(verification::Column::ExpiresAt))
                .col(timestamp(verification::Column::CreatedAt))
                .col(timestamp(verification::Column::UpdatedAt))
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_verifications_identifier",
        verification::Entity,
        &["identifier"],
        false,
    )
    .await
}

async fn create_organizations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(organization::Entity)
                .col(primary_key(organization::Column::Id))
                .col(required(organization::Column::Name))
                .col(required(organization::Column::Slug).unique_key())
                .col(ColumnDef::new(organization::Column::Logo).string())
                .col(ColumnDef::new(organization::Column::Metadata).json_binary())
                .col(timestamp(organization::Column::CreatedAt))
                .col(timestamp(organization::Column::UpdatedAt))
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_organization_slug",
        organization::Entity,
        &["slug"],
        false,
    )
    .await
}

async fn create_members(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(member::Entity)
                .col(primary_key(member::Column::Id))
                .col(required(member::Column::OrganizationId))
                .col(required(member::Column::UserId))
                .col(required(member::Column::Role))
                .col(timestamp(member::Column::CreatedAt))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_member_organization_id")
                        .from(member::Entity, member::Column::OrganizationId)
                        .to(organization::Entity, organization::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(&mut cascade_to_user(
                    "fk_member_user_id",
                    member::Entity,
                    member::Column::UserId,
                ))
                .to_owned(),
        )
        .await?;
    // Memberships have row identities; the organization/user pair is not unique.
    create_index(
        manager,
        "idx_member_organization_id",
        member::Entity,
        &["organization_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_member_user_id",
        member::Entity,
        &["user_id"],
        false,
    )
    .await
}

async fn create_invitations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(invitation::Entity)
                .col(primary_key(invitation::Column::Id))
                .col(required(invitation::Column::OrganizationId))
                .col(required(invitation::Column::Email))
                .col(required(invitation::Column::Role))
                .col(required(invitation::Column::Status))
                .col(required(invitation::Column::InviterId))
                .col(timestamp(invitation::Column::ExpiresAt))
                .col(timestamp(invitation::Column::CreatedAt))
                .col(ColumnDef::new(invitation::Column::TeamId).string())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_invitation_organization_id")
                        .from(invitation::Entity, invitation::Column::OrganizationId)
                        .to(organization::Entity, organization::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(&mut cascade_to_user(
                    "fk_invitation_inviter_id",
                    invitation::Entity,
                    invitation::Column::InviterId,
                ))
                .to_owned(),
        )
        .await?;
    for (name, column) in [
        ("idx_invitation_organization_id", "organization_id"),
        ("idx_invitation_email", "email"),
        ("idx_invitation_status", "status"),
    ] {
        create_index(manager, name, invitation::Entity, &[column], false).await?;
    }
    Ok(())
}

async fn create_two_factor(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // SQLite keeps INTEGER affinity for the counter; reads project it as REAL.
    let mut count = ColumnDef::new(two_factor::Column::FailedVerificationCount);
    if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
        let _ignored_integer = count.integer();
    } else {
        let _ignored_double = count.double();
    }
    let _ignored_default = count.default(0);
    manager
        .create_table(
            Table::create()
                .table(two_factor::Entity)
                .col(primary_key(two_factor::Column::Id))
                .col(required(two_factor::Column::Secret))
                .col(required(two_factor::Column::BackupCodes))
                .col(required(two_factor::Column::UserId))
                .col(timestamp(two_factor::Column::CreatedAt))
                .col(timestamp(two_factor::Column::UpdatedAt))
                .col(
                    ColumnDef::new(two_factor::Column::Verified)
                        .boolean()
                        .default(true),
                )
                .col(&mut count)
                .col(ColumnDef::new(two_factor::Column::LockedUntil).timestamp_with_time_zone())
                .to_owned(),
        )
        .await?;
    // Factors outlive user deletion, so the user reference carries no foreign key.
    create_index(
        manager,
        "idx_two_factor_user_id",
        two_factor::Entity,
        &["user_id"],
        true,
    )
    .await
}

async fn create_api_keys(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(api_key::Entity)
                .col(primary_key(api_key::Column::Id))
                .col(ColumnDef::new(api_key::Column::Name).string())
                .col(ColumnDef::new(api_key::Column::Start).string())
                .col(ColumnDef::new(api_key::Column::Prefix).string())
                .col(required(api_key::Column::KeyHash).unique_key())
                .col(required(api_key::Column::ReferenceId))
                .col(required(api_key::Column::ConfigId).default("default"))
                .col(ColumnDef::new(api_key::Column::RefillInterval).double())
                .col(ColumnDef::new(api_key::Column::RefillAmount).double())
                .col(ColumnDef::new(api_key::Column::LastRefillAt).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(api_key::Column::Enabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(
                    ColumnDef::new(api_key::Column::RateLimitEnabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(ColumnDef::new(api_key::Column::RateLimitTimeWindow).double())
                .col(ColumnDef::new(api_key::Column::RateLimitMax).double())
                .col(ColumnDef::new(api_key::Column::RequestCount).double())
                .col(ColumnDef::new(api_key::Column::Remaining).double())
                .col(ColumnDef::new(api_key::Column::LastRequest).timestamp_with_time_zone())
                .col(ColumnDef::new(api_key::Column::ExpiresAt).timestamp_with_time_zone())
                .col(timestamp(api_key::Column::CreatedAt))
                .col(timestamp(api_key::Column::UpdatedAt))
                .col(ColumnDef::new(api_key::Column::Permissions).string())
                .col(ColumnDef::new(api_key::Column::Metadata).string())
                // No foreign key to users: `reference_id` holds a user id or an
                // organization id depending on the key's configuration, which is
                // why upstream declares the field as a plain indexed string.
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_api_keys_reference_id",
        api_key::Entity,
        &["reference_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_api_keys_config_id",
        api_key::Entity,
        &["config_id"],
        false,
    )
    .await
}

async fn create_passkeys(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(passkey::Entity)
                .col(primary_key(passkey::Column::Id))
                .col(ColumnDef::new(passkey::Column::Name).string())
                .col(required(passkey::Column::PublicKey))
                .col(required(passkey::Column::UserId))
                .col(required(passkey::Column::CredentialId).unique_key())
                .col(
                    ColumnDef::new(passkey::Column::Counter)
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .col(required(passkey::Column::DeviceType))
                .col(
                    ColumnDef::new(passkey::Column::BackedUp)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(passkey::Column::Transports).string())
                .col(
                    ColumnDef::new(passkey::Column::Credential)
                        .text()
                        .not_null(),
                )
                .col(ColumnDef::new(passkey::Column::Aaguid).string())
                .col(timestamp(passkey::Column::CreatedAt))
                .col(timestamp(passkey::Column::UpdatedAt))
                .foreign_key(&mut cascade_to_user(
                    "fk_passkeys_user_id",
                    passkey::Entity,
                    passkey::Column::UserId,
                ))
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_passkeys_user_id",
        passkey::Entity,
        &["user_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_passkeys_credential_id",
        passkey::Entity,
        &["credential_id"],
        false,
    )
    .await
}

async fn create_device_codes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(device_code::Entity)
                .col(primary_key(device_code::Column::Id))
                .col(required(device_code::Column::DeviceCode).unique_key())
                .col(required(device_code::Column::UserCode).unique_key())
                // The optional user reference is unconstrained.
                .col(ColumnDef::new(device_code::Column::UserId).string())
                .col(timestamp(device_code::Column::ExpiresAt))
                .col(required(device_code::Column::Status))
                .col(ColumnDef::new(device_code::Column::LastPolledAt).timestamp_with_time_zone())
                .col(ColumnDef::new(device_code::Column::PollingInterval).big_integer())
                .col(ColumnDef::new(device_code::Column::ClientId).string())
                .col(ColumnDef::new(device_code::Column::Scope).string())
                .to_owned(),
        )
        .await?;
    for (name, column) in [
        ("idx_device_code_device_code", "device_code"),
        ("idx_device_code_user_code", "user_code"),
        ("idx_device_code_user_id", "user_id"),
        ("idx_device_code_expires_at", "expires_at"),
    ] {
        create_index(manager, name, device_code::Entity, &[column], false).await?;
    }
    Ok(())
}

async fn create_teams(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Teams outlive organization deletion, matching the pinned default adapter,
    // so they carry no organization foreign key.
    manager
        .create_table(
            Table::create()
                .table(team::Entity)
                .col(primary_key(team::Column::Id))
                .col(required(team::Column::Name))
                .col(required(team::Column::OrganizationId))
                .col(
                    ColumnDef::new(team::Column::MemberCount)
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .col(timestamp(team::Column::CreatedAt))
                .col(ColumnDef::new(team::Column::UpdatedAt).timestamp_with_time_zone())
                .to_owned(),
        )
        .await?;
    manager
        .create_table(
            Table::create()
                .table(team_member::Entity)
                .col(primary_key(team_member::Column::Id))
                .col(required(team_member::Column::TeamId))
                .col(required(team_member::Column::UserId))
                .col(
                    ColumnDef::new(team_member::Column::MembershipKey)
                        .string()
                        .unique_key(),
                )
                .col(timestamp(team_member::Column::CreatedAt))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_team_member_team")
                        .from(team_member::Entity, team_member::Column::TeamId)
                        .to(team::Entity, team::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_team_organization",
        team::Entity,
        &["organization_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_team_member_team",
        team_member::Entity,
        &["team_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_team_member_user",
        team_member::Entity,
        &["user_id"],
        false,
    )
    .await
}

async fn create_organization_roles(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Roles outlive organization deletion, as teams do.
    manager
        .create_table(
            Table::create()
                .table(organization_role::Entity)
                .col(primary_key(organization_role::Column::Id))
                .col(required(organization_role::Column::OrganizationId))
                .col(required(organization_role::Column::Role))
                .col(required(organization_role::Column::Permission))
                .col(timestamp(organization_role::Column::CreatedAt))
                .col(
                    ColumnDef::new(organization_role::Column::UpdatedAt).timestamp_with_time_zone(),
                )
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_organization_role_org",
        organization_role::Entity,
        &["organization_id"],
        false,
    )
    .await?;
    create_index(
        manager,
        "idx_organization_role_role",
        organization_role::Entity,
        &["role"],
        false,
    )
    .await
}

async fn create_jwks(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(jwk::Entity)
                .col(primary_key(jwk::Column::Id))
                .col(required(jwk::Column::PublicKey))
                .col(required(jwk::Column::PrivateKey))
                .col(timestamp(jwk::Column::CreatedAt))
                .col(ColumnDef::new(jwk::Column::ExpiresAt).timestamp_with_time_zone())
                .col(ColumnDef::new(jwk::Column::Alg).string())
                .col(ColumnDef::new(jwk::Column::Crv).string())
                .to_owned(),
        )
        .await
}

async fn create_wallet_addresses(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Wallets support application-owned user tables, so the store checks and
    // cascades their owner in a transaction instead of a foreign key.
    manager
        .create_table(
            Table::create()
                .table(wallet_address::Entity)
                .col(primary_key(wallet_address::Column::Id))
                .col(required(wallet_address::Column::UserId))
                .col(required(wallet_address::Column::Address))
                .col(
                    ColumnDef::new(wallet_address::Column::ChainId)
                        .integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(wallet_address::Column::IsPrimary)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(timestamp(wallet_address::Column::CreatedAt))
                .to_owned(),
        )
        .await?;
    create_index(
        manager,
        "idx_wallet_address_user",
        wallet_address::Entity,
        &["user_id"],
        false,
    )
    .await
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    #[derive(DeriveIden)]
    enum Todo {
        Table,
        Id,
        Title,
    }

    #[derive(DeriveMigrationName)]
    struct CreateTodoTable;

    #[async_trait::async_trait]
    impl MigrationTrait for CreateTodoTable {
        #[expect(
            elided_lifetimes_in_paths,
            reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
        )]
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_table(
                    Table::create()
                        .table(Todo::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(Todo::Id).integer().not_null().primary_key())
                        .col(ColumnDef::new(Todo::Title).string().not_null())
                        .to_owned(),
                )
                .await
        }

        #[expect(
            elided_lifetimes_in_paths,
            reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
        )]
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(Todo::Table).if_exists().to_owned())
                .await
        }
    }

    struct AppMigrator;

    #[async_trait::async_trait]
    impl MigratorTrait for AppMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(CreateTodoTable)]
        }
    }

    // Rust-specific surface: Better Auth owns a separate SeaORM migration table so app migrators can keep the default `seaql_migrations`.
    #[tokio::test]
    async fn auth_migrator_uses_namespaced_history_table() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        run_migrations(&database).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(!manager.has_table("seaql_migrations").await.unwrap());
    }

    // Rust-specific surface: Better Auth migration composition with app-owned SeaORM migrations is a Rust integration concern with no direct TS analogue.
    #[tokio::test]
    async fn auth_and_app_migrators_can_run_against_the_same_database() {
        let database = Database::connect("sqlite::memory:").await.unwrap();

        AppMigrator::up(&database, None).await.unwrap();
        AuthMigrator::up(&database, None).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("seaql_migrations").await.unwrap());
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(manager.has_table("todo").await.unwrap());
        assert!(manager.has_table(user::Entity.table_name()).await.unwrap());
    }
}
// LCOV_EXCL_STOP
