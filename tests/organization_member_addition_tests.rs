//! Direct server API callers retain typed real storage/application failures.
#![expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "the actual failing public helper operations must return errors"
)]
use async_trait::async_trait;
use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationMemberAddedContext, OrganizationMemberAdditionHooks,
    OrganizationPlugin,
    types::{AddOrganizationMemberRequest, RoleInput},
};
use better_auth::{AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthContext, CreateOrganization, CreateUser,
    store::{MemberStore, OrganizationStore, UserStore},
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use std::{collections::HashMap, sync::Arc};
type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Debug)]
struct RejectAfter;
#[async_trait]
impl OrganizationMemberAdditionHooks for RejectAfter {
    async fn after_add_member(&self, _: &OrganizationMemberAddedContext) -> AuthResult<()> {
        Err(AuthError::Api {
            status: 500,
            code: Some("APPLICATION_AFTER_ERROR".into()),
            message: "Explicit application after error".into(),
        })
    }
}
#[tokio::test]
async fn server_addition_keeps_database_error_distinct_from_after_api_error_and_rows() -> TestResult
{
    let database = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let config = AuthConfig::new("member-addition-native-secret-at-least-32-bytes");
    let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database.clone()));
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("target@admission-native.test")
                .with_name("Target"),
        )
        .await?;
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@admission-native.test"))
        .await?;
    let organization = store
        .create_organization(CreateOrganization {
            name: "Admission".into(),
            slug: "admission-native".into(),
            id: None,
            logo: None,
            metadata: None,
        })
        .await?;
    let other = store
        .create_organization(CreateOrganization {
            name: "Foreign".into(),
            slug: "foreign-native".into(),
            id: None,
            logo: None,
            metadata: None,
        })
        .await?;
    let foreign_before = serde_json::to_value(store.get_user_by_id(&foreign.id).await?)?;
    let other_before = serde_json::to_value(store.get_organization_by_id(&other.id).await?)?;
    let context = AuthContext::new(Arc::new(config), store.clone());
    let body = AddOrganizationMemberRequest {
        user_id: user.id.clone(),
        organization_id: Some(organization.id.clone()),
        role: RoleInput::One("member".into()),
        team_id: None,
    };
    let _ = database
        .execute_unprepared("CREATE TABLE __test_admission_guard(userId TEXT)")
        .await?;
    let _ = database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO __test_admission_guard(userId) VALUES(?)",
            [user.id.clone().into()],
        ))
        .await?;
    let _=database.execute_unprepared("CREATE TRIGGER native_admission_veto BEFORE INSERT ON member WHEN NEW.user_id=(SELECT userId FROM __test_admission_guard) BEGIN SELECT RAISE(ABORT,'native admission veto'); END").await?;
    let error = OrganizationPlugin::new()
        .add_member_with_headers(&context, &HashMap::new(), &body)
        .await
        .expect_err("the actual SQLite write must fail");
    assert!(
        matches!(error, AuthError::Database(_)),
        "native callers receive the actual database failure: {error}"
    );
    assert!(
        store
            .get_member(&organization.id, &user.id)
            .await?
            .is_none()
    );
    let _ = database
        .execute_unprepared("DROP TRIGGER native_admission_veto")
        .await?;
    let error = OrganizationPlugin::with_config(OrganizationConfig {
        member_addition_hooks: Some(Arc::new(RejectAfter)),
        ..Default::default()
    })
    .add_member_with_headers(&context, &HashMap::new(), &body)
    .await
    .expect_err("the actual after callback must reject");
    assert!(
        matches!(error,AuthError::Api{status:500,code:Some(ref code),ref message}if code=="APPLICATION_AFTER_ERROR"&&message=="Explicit application after error")
    );
    let committed = store
        .get_member(&organization.id, &user.id)
        .await?
        .ok_or("after rejection must retain the committed member")?;
    assert_eq!(committed.role, "member");
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&foreign.id).await?)?,
        foreign_before
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
        other_before
    );
    let duplicate = OrganizationPlugin::new()
        .add_member_with_headers(&context, &HashMap::new(), &body)
        .await
        .expect_err("retry cannot silently duplicate an admitted member");
    assert!(matches!(
        duplicate,
        AuthError::Upstream {
            status: 400,
            code: "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
            ..
        }
    ));
    Ok(())
}
