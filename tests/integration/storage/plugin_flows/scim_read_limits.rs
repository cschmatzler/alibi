//! Group writes and role mapping read every row past the default findMany limit.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::scim::{
    ScimAuthorizationSource, ScimConnectionOptions, ScimCredential, ScimPlugin,
    ScimProjectedUserState, ScimProjection, ScimRoleExistenceInput, ScimRoleMappingInput,
    ScimRoleProjection,
};
use alibi::store::AuthTransaction;
backend_tests!(
    scim_groups_past_the_find_many_limit_keep_every_member,
    scim_oversized_persisted_groups_empty_and_delete_completely,
    scim_group_roles_past_the_find_many_limit_follow_every_member,
    scim_roles_from_102_groups_follow_the_user_lifecycle,
    scim_roles_ignore_a_small_default_find_many_limit
);
postgres_tests!(
    scim_groups_past_the_find_many_limit_keep_every_member,
    scim_oversized_persisted_groups_empty_and_delete_completely,
    scim_group_roles_past_the_find_many_limit_follow_every_member,
    scim_roles_from_102_groups_follow_the_user_lifecycle,
    scim_roles_ignore_a_small_default_find_many_limit
);
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const TOKEN: &str = "read-limits-token";
const STAMP: &str = "'2026-01-02T03:04:05.000Z'";

/// Maps every Group whose display name starts with "Admins" to the existing `admin` role.
struct AdminGroups;
#[async_trait::async_trait]
impl<S: AuthSchema> ScimProjection<S> for AdminGroups {
    async fn reconcile_user(
        &self,
        _input: &ScimProjectedUserState,
        _database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<()> {
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimRoleProjection<S> for AdminGroups {
    async fn map(
        &self,
        input: &ScimRoleMappingInput,
        _database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<Option<Vec<String>>> {
        let ScimAuthorizationSource::Group { display_name, .. } = &input.source;
        Ok(Some(if display_name.starts_with("Admins") {
            vec!["admin".into()]
        } else {
            Vec::new()
        }))
    }
    async fn exists(
        &self,
        input: &ScimRoleExistenceInput,
        _database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<bool> {
        Ok(input.role == "admin")
    }
}

async fn app<B: Backend>(
    connection: &B::Connection,
    find_many_limit: usize,
) -> TestResult<Alibi<B::Schema>> {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.advanced.database.default_find_many_limit = find_many_limit;
    let roles = Arc::new(AdminGroups);
    Ok(AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(
            ScimPlugin::new()
                .connections(vec![ScimConnectionOptions {
                    id: "workforce".into(),
                    provisioning_domain_id: Some("tenant-a".into()),
                    credentials: vec![ScimCredential::new("bearer", TOKEN)],
                }])
                .projection::<B::Schema>(roles.clone())
                .roles(roles),
        )
        .build()
        .await?)
}

async fn send<S: AuthSchema, T>(
    auth: &Alibi<S>,
    endpoint: ServerEndpoint<T>,
) -> TestResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers: Some(
                [("authorization".into(), format!("Bearer {TOKEN}"))]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        },
    ))
    .await;
    Ok(match result {
        Ok(output) => output.into_response()?,
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            response.to_response()?
        }
    })
}

fn members(ids: &[String]) -> Value {
    ids.iter().map(|id| json!({"value":id})).collect()
}

async fn create_group<S: AuthSchema>(
    auth: &Alibi<S>,
    name: &str,
    ids: &[String],
) -> TestResult<String> {
    let response = send(
        auth,
        ScimPlugin::create_group_endpoint().with_body(
            &json!({"schemas":[GROUP_SCHEMA],"displayName":name,"members":members(ids)}),
        )?,
    )
    .await?;
    assert_eq!(response.status, 201, "{}", String::from_utf8_lossy(&response.body));
    Ok(body(&response)["id"].as_str().unwrap().to_owned())
}

async fn patch_members<S: AuthSchema>(
    auth: &Alibi<S>,
    group: &str,
    op: &str,
    ids: &[String],
) -> TestResult {
    let response = send(
        auth,
        ScimPlugin::patch_group_endpoint(group)?.with_body(&json!({"schemas":[PATCH_SCHEMA],"Operations":[{"op":op,"path":"members","value":members(ids)}]}))?,
    )
    .await?;
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
    Ok(())
}

async fn set_active<S: AuthSchema>(auth: &Alibi<S>, user: &str, active: bool) -> TestResult {
    let response = send(
        auth,
        ScimPlugin::patch_user_endpoint(user)?.with_body(&json!({"schemas":[PATCH_SCHEMA],"Operations":[{"op":"replace","path":"active","value":active}]}))?,
    )
    .await?;
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
    Ok(())
}

/// Insert literal rows in a few multi-row statements instead of one round trip per row.
async fn insert(db: &Db, table: &str, columns: &str, rows: &[String]) -> TestResult {
    for chunk in rows.chunks(250) {
        _ = db
            .execute(
                &format!("INSERT INTO \"{table}\" ({columns}) VALUES {}", chunk.join(",")),
                &[],
            )
            .await?;
    }
    Ok(())
}

/// Seed active connection Users, each with its own subject, as zero-padded `{prefix}-NNNN`.
async fn seed_users(db: &Db, prefix: &str, count: usize) -> TestResult<Vec<String>> {
    seed_domain_users(db, prefix, count, "tenant-a").await
}

async fn seed_domain_users(
    db: &Db,
    prefix: &str,
    count: usize,
    domain: &str,
) -> TestResult<Vec<String>> {
    let ids = (0..count)
        .map(|index| format!("{prefix}-{index:04}"))
        .collect::<Vec<_>>();
    let rows = |row: &dyn Fn(&str) -> String| ids.iter().map(|id| row(id)).collect::<Vec<_>>();
    insert(
        db,
        "user",
        "\"id\",\"name\",\"email\",\"emailVerified\",\"createdAt\",\"updatedAt\"",
        &rows(&|id| format!("('user-{id}','{id}','{id}@example.com',FALSE,{STAMP},{STAMP})")),
    )
    .await?;
    insert(
        db,
        "scimSubject",
        "\"id\",\"userId\",\"profileSourceId\",\"revision\",\"createdAt\",\"updatedAt\"",
        &rows(&|id| format!("('subject-{id}','user-{id}','{id}',1,{STAMP},{STAMP})")),
    )
    .await?;
    insert(
        db,
        "scimUser",
        "\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\"",
        &rows(&|id| format!("('{id}','workforce','{domain}','user-{id}','{id}','{id}@example.com','{id}','{id}@example.com','[]','[]','{id}','{id}','[]',TRUE,'{id}',{STAMP},{STAMP})")),
    )
    .await?;
    Ok(ids)
}

/// Seed `count` Admin Groups that each hold `member` directly.
async fn seed_admin_groups(db: &Db, member: &str, count: usize) -> TestResult {
    let ids = (0..count)
        .map(|index| format!("seeded-admin-{index:04}"))
        .collect::<Vec<_>>();
    insert(
        db,
        "scimGroup",
        "\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"orderKey\",\"createdAt\",\"updatedAt\"",
        &ids.iter()
            .map(|id| format!("('{id}','workforce','tenant-a',0,'Admins {id}','{id}','{id}',{STAMP},{STAMP})"))
            .collect::<Vec<_>>(),
    )
    .await?;
    insert(
        db,
        "scimGroupMember",
        "\"id\",\"connectionId\",\"groupId\",\"scimUserId\",\"membershipKey\",\"createdAt\"",
        &ids.iter()
            .map(|id| format!("('membership-{id}','workforce','{id}','{member}','membership-{id}',{STAMP})"))
            .collect::<Vec<_>>(),
    )
    .await?;
    Ok(())
}

async fn member_count(db: &Db, group: &str) -> TestResult<i64> {
    db.count_where(
        "SELECT COUNT(*) FROM \"scimGroupMember\" WHERE \"groupId\" = $1",
        &[group],
    )
    .await
}

async fn users_with_admin_grant(db: &Db) -> TestResult<i64> {
    db.count_where(
        "SELECT COUNT(DISTINCT \"userId\") FROM \"scimProjectionGrant\" WHERE \"role\" = 'admin'",
        &[],
    )
    .await
}

async fn admin_grants_of(db: &Db, scim_user: &str) -> TestResult<i64> {
    db.count_where(
        "SELECT COUNT(*) FROM \"scimProjectionGrant\" WHERE \"scimUserId\" = $1 AND \"role\" = 'admin'",
        &[scim_user],
    )
    .await
}

fn member_values(resource: &Value) -> Vec<String> {
    let mut values = resource["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["value"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    values.sort();
    values
}

/// Create a 100-member Group, then grow it to `ids.len()` members through PATCH add.
async fn grown_group<S: AuthSchema>(auth: &Alibi<S>, name: &str, ids: &[String]) -> TestResult<String> {
    let group = create_group(auth, name, &ids[..100]).await?;
    patch_members(auth, &group, "add", &ids[100..]).await?;
    Ok(group)
}

async fn scim_groups_past_the_find_many_limit_keep_every_member<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = app::<B>(&connection, 100).await?;
    let ids = seed_users(&db, "grown", 150).await?;
    let created = create_group(&auth, "Engineering", &ids).await?;
    assert_eq!(member_count(&db, &created).await?, 150);
    let group = grown_group(&auth, "Platform", &ids).await?;
    assert_eq!(member_count(&db, &group).await?, 150);
    let read = send(&auth, ScimPlugin::group_endpoint(&group)?).await?;
    assert_eq!(read.status, 200);
    assert_eq!(member_values(&body(&read)), ids);
    let listed = send(&auth, ScimPlugin::groups_endpoint().with_query(&json!({}))?).await?;
    assert_eq!(listed.status, 200);
    for resource in body(&listed)["Resources"].as_array().unwrap() {
        assert_eq!(member_values(resource), ids);
    }
    let kept = &ids[..100];
    let replaced = send(
        &auth,
        ScimPlugin::replace_group_endpoint(&group)?.with_body(
            &json!({"schemas":[GROUP_SCHEMA],"displayName":"Platform","members":members(kept)}),
        )?,
    )
    .await?;
    assert_eq!(replaced.status, 200);
    let left_out = "SELECT COUNT(*) FROM \"scimGroupMember\" WHERE \"groupId\" = $1 AND \"scimUserId\" >= 'grown-0100'";
    assert_eq!(member_count(&db, &group).await?, 100);
    assert_eq!(db.count_where(left_out, &[&group]).await?, 0);
    patch_members(&auth, &group, "add", &ids[100..]).await?;
    assert_eq!(member_count(&db, &group).await?, 150);
    patch_members(&auth, &group, "replace", kept).await?;
    assert_eq!(member_count(&db, &group).await?, 100);
    assert_eq!(db.count_where(left_out, &[&group]).await?, 0);
    patch_members(&auth, &group, "add", &ids[100..]).await?;
    patch_members(&auth, &group, "remove", &ids).await?;
    assert_eq!(member_count(&db, &group).await?, 0);
    assert_eq!(member_count(&db, &created).await?, 150);
    Ok(())
}

async fn scim_oversized_persisted_groups_empty_and_delete_completely<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = app::<B>(&connection, 100).await?;
    let replaced = create_group(&auth, "Engineering", &[]).await?;
    let deleted = create_group(&auth, "Platform", &[]).await?;
    // Persisted state above the 1000-member invariant, owned by Users outside the domain.
    for group in [&replaced, &deleted] {
        let users = seed_domain_users(&db, group, 1010, "tenant-elsewhere").await?;
        let memberships = users
            .iter()
            .map(|user| format!("('membership-{user}','workforce','{group}','{user}','membership-{user}',{STAMP})"))
            .collect::<Vec<_>>();
        insert(
            &db,
            "scimGroupMember",
            "\"id\",\"connectionId\",\"groupId\",\"scimUserId\",\"membershipKey\",\"createdAt\"",
            &memberships,
        )
        .await?;
    }
    let emptied = send(
        &auth,
        ScimPlugin::replace_group_endpoint(&replaced)?.with_body(
            &json!({"schemas":[GROUP_SCHEMA],"displayName":"Engineering","members":[]}),
        )?,
    )
    .await?;
    assert_eq!(emptied.status, 200, "{}", String::from_utf8_lossy(&emptied.body));
    let removed = send(&auth, ScimPlugin::delete_group_endpoint(&deleted)?).await?;
    assert_eq!(removed.status, 204);
    assert_eq!(db.count("scimGroupMember").await?, 0);
    assert_eq!(db.count("scimGroup").await?, 1);
    Ok(())
}

async fn scim_group_roles_past_the_find_many_limit_follow_every_member<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = app::<B>(&connection, 100).await?;
    let ids = seed_users(&db, "admin", 150).await?;
    let group = grown_group(&auth, "Admins", &ids).await?;
    assert_eq!(users_with_admin_grant(&db).await?, 150);
    let removed = send(&auth, ScimPlugin::delete_group_endpoint(&group)?).await?;
    assert_eq!(removed.status, 204);
    assert_eq!(users_with_admin_grant(&db).await?, 0);
    // 50 Users in two unmapped Groups hold 100 memberships before the mapped one is added.
    let teams = seed_users(&db, "team", 50).await?;
    _ = create_group(&auth, "Team A", &teams).await?;
    _ = create_group(&auth, "Team B", &teams).await?;
    _ = create_group(&auth, "Admins of teams", &teams).await?;
    assert_eq!(users_with_admin_grant(&db).await?, 50);
    Ok(())
}

async fn create_user<S: AuthSchema>(auth: &Alibi<S>, name: &str) -> TestResult<String> {
    let response = send(
        auth,
        ScimPlugin::create_user_endpoint()
            .with_body(&json!({"schemas":[USER_SCHEMA],"userName":name}))?,
    )
    .await?;
    assert_eq!(response.status, 201, "{}", String::from_utf8_lossy(&response.body));
    Ok(body(&response)["id"].as_str().unwrap().to_owned())
}

async fn scim_roles_from_102_groups_follow_the_user_lifecycle<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = app::<B>(&connection, 100).await?;
    let user = create_user(&auth, "user-0@example.com").await?;
    seed_admin_groups(&db, &user, 101).await?;
    _ = create_group(&auth, "Admins last", std::slice::from_ref(&user)).await?;
    assert_eq!(admin_grants_of(&db, &user).await?, 102);
    set_active(&auth, &user, false).await?;
    assert_eq!(admin_grants_of(&db, &user).await?, 0);
    set_active(&auth, &user, true).await?;
    assert_eq!(admin_grants_of(&db, &user).await?, 102);
    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"updatedAt\" = '2000-01-01T00:00:00.000Z'",
            &[],
        )
        .await?;
    let removed = send(&auth, ScimPlugin::delete_user_endpoint(&user)?).await?;
    assert_eq!(removed.status, 204);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"scimGroup\" WHERE \"updatedAt\" < '2001-01-01T00:00:00.000Z'",
            &[],
        )
        .await?,
        0
    );
    assert_eq!(db.count("scimGroupMember").await?, 0);
    Ok(())
}

async fn scim_roles_ignore_a_small_default_find_many_limit<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = app::<B>(&connection, 10).await?;
    let ids = seed_users(&db, "limited", 20).await?;
    _ = create_group(&auth, "Admins", &ids).await?;
    assert_eq!(users_with_admin_grant(&db).await?, 20);
    let user = create_user(&auth, "user-0@example.com").await?;
    seed_admin_groups(&db, &user, 11).await?;
    _ = create_group(&auth, "Admins last", std::slice::from_ref(&user)).await?;
    assert_eq!(admin_grants_of(&db, &user).await?, 12);
    Ok(())
}
