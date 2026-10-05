//! Native organization authority and lifetime through the public router.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use better_auth::plugins::{
    EmailPasswordPlugin,
    organization::{
        DynamicAccessControlConfig, OrganizationConfig, OrganizationPlugin, TeamsConfig,
        default_organization_statements,
    },
};
use better_auth::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "native-organization-172-secret-at-least-32";
const ORIGIN: &str = "http://localhost:43178";
backend_tests!(native_organization_workflow);
postgres_tests!(native_organization_workflow);
fn config() -> AuthConfig {
    AuthConfig::new(SECRET).base_url(ORIGIN)
}
fn plugins<S: AuthSchema>(builder: AuthBuilder<S>) -> AuthBuilder<S> {
    builder
        .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                allow_removing_all_teams: true,
                maximum_members_per_team: Some(1.0),
                ..Default::default()
            },
            access_control: Some(default_organization_statements()),
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|v| v.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    trace: &mut Vec<Value>,
    path: &str,
    input: Option<Value>,
    query: &[(&str, &str)],
    cookie: &str,
    expected: u16,
) -> TestResult<Value> {
    let mut req = AuthRequest::new(
        if input.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    for (key, value) in [
        ("origin", ORIGIN),
        ("content-type", "application/json"),
        ("cookie", cookie),
    ] {
        drop(req.headers.insert(key.into(), value.into()));
    }
    for (key, value) in query {
        drop(req.query.insert((*key).into(), (*value).into()));
    }
    req.body = input.map(|v| serde_json::to_vec(&v).unwrap());
    let response = Box::pin(auth.handle_request(req)).await?;
    trace.push(json!({"path":path,"status":response.status,"body":String::from_utf8(response.body.clone())?}));
    assert_eq!(
        response.status,
        expected,
        "{path}: {}",
        String::from_utf8_lossy(&response.body)
    );
    Ok(body(&response))
}
async fn signup<S: AuthSchema>(
    auth: &BetterAuth<S>,
    email: &str,
) -> TestResult<(String, String, String)> {
    let mut req = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    req.body = Some(serde_json::to_vec(
        &json!({"email":email,"password":"Password123!","name":email}),
    )?);
    let response = Box::pin(auth.handle_request(req)).await?;
    assert_eq!(response.status, 200, "{}", body(&response));
    Ok((
        cookies(&response),
        body(&response)["user"]["id"].as_str().unwrap().into(),
        body(&response)["token"].as_str().unwrap().into(),
    ))
}
struct Retained {
    organization: String,
    foreign: String,
    role: String,
    cookie: String,
    token: String,
}
async fn workflow<S: AuthSchema>(auth: &BetterAuth<S>, owner: &str) -> TestResult<Retained> {
    let mut trace = Vec::new();
    let (cookie, _, token) = signup(auth, "owner@native-org.test").await?;
    let (recipient, recipient_id, _) = signup(auth, "member@native-org.test").await?;
    let (outsider, outsider_id, _) = signup(auth, "outsider@native-org.test").await?;
    let created = call(
        auth,
        &mut trace,
        "/organization/create",
        Some(json!({"name":"Native","slug":"native","metadata":{"literal":null}})),
        &[],
        &cookie,
        200,
    )
    .await?;
    let org = created["id"].as_str().unwrap().to_owned();
    let foreign = call(
        auth,
        &mut trace,
        "/organization/create",
        Some(json!({"name":"Foreign","slug":"foreign"})),
        &[],
        &outsider,
        200,
    )
    .await?["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let role = call(auth, &mut trace, "/organization/create-role", Some(json!({"organizationId":org,"role":"reviewer","permission":{"organization":["update"]}})), &[], &cookie, 200).await?;
    let role_id = role["roleData"]["id"].as_str().unwrap().to_owned();
    let temporary = call(
        auth,
        &mut trace,
        "/organization/create-role",
        Some(json!({"organizationId":org,"role":"temporary","permission":{}})),
        &[],
        &cookie,
        200,
    )
    .await?["roleData"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let _response = call(
        auth,
        &mut trace,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":temporary})),
        &[],
        &cookie,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_organization_role(
                &org,
                &better_auth_core::types::OrganizationRoleSelector::Id(temporary)
            )
            .await?
            .is_none()
    );
    let team = call(
        auth,
        &mut trace,
        "/organization/create-team",
        Some(json!({"organizationId":org,"name":"One seat"})),
        &[],
        &cookie,
        200,
    )
    .await?["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let invite = call(auth, &mut trace, "/organization/invite-member", Some(json!({"organizationId":org,"email":"member@native-org.test","role":"reviewer","teamId":team})), &[], &cookie, 200).await?["id"].as_str().unwrap().to_owned();
    let pending = call(auth, &mut trace, "/organization/invite-member", Some(json!({"organizationId":org,"email":"outsider@native-org.test","role":"member","teamId":team})), &[], &cookie, 200).await?["id"].as_str().unwrap().to_owned();
    let denied = call(
        auth,
        &mut trace,
        "/organization/accept-invitation",
        Some(json!({"invitationId":invite})),
        &[],
        &outsider,
        403,
    )
    .await?;
    assert_eq!(
        denied["code"],
        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"
    );
    assert_eq!(
        auth.store()
            .get_invitation_by_id(&invite)
            .await?
            .unwrap()
            .status
            .to_string(),
        "pending"
    );
    let _response = call(
        auth,
        &mut trace,
        "/organization/accept-invitation",
        Some(json!({"invitationId":invite})),
        &[],
        &recipient,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_team_member(&team, &recipient_id)
            .await?
            .is_some()
    );
    let _response = call(
        auth,
        &mut trace,
        "/organization/accept-invitation",
        Some(json!({"invitationId":invite})),
        &[],
        &recipient,
        400,
    )
    .await?;
    let limited = call(
        auth,
        &mut trace,
        "/organization/accept-invitation",
        Some(json!({"invitationId":pending})),
        &[],
        &outsider,
        403,
    )
    .await?;
    assert_eq!(limited["code"], "TEAM_MEMBER_LIMIT_REACHED");
    assert_eq!(
        auth.store()
            .get_invitation_by_id(&pending)
            .await?
            .unwrap()
            .status
            .to_string(),
        "pending"
    );
    assert!(auth.store().get_member(&org, &outsider_id).await?.is_none());
    let _response = call(
        auth,
        &mut trace,
        "/organization/update",
        Some(json!({"organizationId":foreign,"data":{"name":"Forbidden"}})),
        &[],
        &recipient,
        400,
    )
    .await?;
    let _response = call(
        auth,
        &mut trace,
        "/organization/update",
        Some(json!({"organizationId":org,"data":{"name":"Reviewed"}})),
        &[],
        &recipient,
        200,
    )
    .await?;
    let _response = call(auth, &mut trace, "/organization/update-role", Some(json!({"organizationId":org,"roleId":role_id,"data":{"permission":{"organization":[]}}})), &[], &cookie, 200).await?;
    let read = call(
        auth,
        &mut trace,
        "/organization/get-role",
        None,
        &[("organizationId", &org), ("roleId", &role_id)],
        &cookie,
        200,
    )
    .await?;
    assert_eq!(read["permission"], json!({"organization":[]}));
    let member = auth.store().get_member(&org, &recipient_id).await?.unwrap();
    let _response = call(
        auth,
        &mut trace,
        "/organization/update-member-role",
        Some(json!({"organizationId":org,"memberId":member.id,"role":"member"})),
        &[],
        &cookie,
        200,
    )
    .await?;
    let _response = call(
        auth,
        &mut trace,
        "/organization/update",
        Some(json!({"organizationId":org,"data":{"name":"Denied"}})),
        &[],
        &recipient,
        403,
    )
    .await?;
    let _response = call(
        auth,
        &mut trace,
        "/organization/list-members",
        None,
        &[
            ("organizationId", &org),
            ("filterField", "role"),
            ("filterValue", "owner"),
            ("filterOperator", "ne"),
        ],
        &cookie,
        200,
    )
    .await?;
    let _response = call(
        auth,
        &mut trace,
        "/organization/remove-team",
        Some(json!({"organizationId":foreign,"teamId":team})),
        &[],
        &outsider,
        400,
    )
    .await?;
    assert!(auth.store().get_team(Some(&org), &team).await?.is_some());
    let _response = call(
        auth,
        &mut trace,
        "/organization/remove-team",
        Some(json!({"organizationId":org,"teamId":team})),
        &[],
        &cookie,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_team_member(&team, &recipient_id)
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_invitation_by_id(&pending)
            .await?
            .unwrap()
            .team_id
            .is_none()
    );
    let _response = call(
        auth,
        &mut trace,
        "/organization/remove-member",
        Some(json!({"organizationId":org,"memberIdOrEmail":member.id})),
        &[],
        &cookie,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_member(&org, &recipient_id)
            .await?
            .is_none()
    );
    if let Ok(dir) = std::env::var("ORG_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{owner}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    Ok(Retained {
        organization: org,
        foreign,
        role: role_id,
        cookie,
        token,
    })
}
async fn native_organization_workflow<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = config();
    config.session = config.session.stateless();
    let auth = plugins(
        AuthBuilder::new(config.clone()).store(B::store(Arc::new(config.clone()), &connection)),
    )
    .build()
    .await?;
    let retained = workflow(
        &auth,
        std::any::type_name::<B>().rsplit("::").next().unwrap(),
    )
    .await?;
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(db.count("organization").await?, 2);
    assert_eq!(db.count("member").await?, 2);
    assert_eq!(db.count("invitation").await?, 2);
    assert_eq!(db.count("team_member").await?, 0);
    assert_eq!(db.count("organization_role").await?, 1);
    assert_eq!(
        db.text("SELECT permission FROM organization_role LIMIT 1", &[])
            .await?,
        Some(r#"{"organization":[]}"#.into())
    );
    let restarted =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    assert!(
        restarted
            .store()
            .get_organization_by_id(&retained.organization)
            .await?
            .is_some()
    );
    assert!(
        restarted
            .store()
            .get_organization_role(
                &retained.organization,
                &better_auth_core::types::OrganizationRoleSelector::Id(retained.role)
            )
            .await?
            .is_some()
    );
    let foreign_before = db.table("organization").await?;
    let mut trace = Vec::new();
    let _response = call(
        &auth,
        &mut trace,
        "/organization/delete",
        Some(json!({"organizationId":retained.organization})),
        &[],
        &retained.cookie,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_organization_by_id(&retained.foreign)
            .await?
            .is_some()
    );
    assert_ne!(db.table("organization").await?, foreign_before);
    assert_eq!(db.count("invitation").await?, 0);
    assert_eq!(db.count("organization_role").await?, 1);
    B::close(connection).await
}
#[tokio::test]
async fn without_database_native_organization_workflow() -> TestResult {
    let auth = plugins(AuthBuilder::without_database(config()))
        .build()
        .await?;
    let retained = workflow(&auth, "without-database").await?;
    let restarted = plugins(AuthBuilder::without_database(config()))
        .build()
        .await?;
    assert!(
        restarted
            .store()
            .get_organization_by_id(&retained.organization)
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_organization_by_id(&retained.organization)
            .await?
            .is_some()
    );
    // Session scopes belong to the initialized wrapper and must not publish on abort.
    let original = auth.store().get_session(&retained.token).await?.unwrap();
    let token = retained.token.clone();
    let aborted =
        better_auth_core::store::transaction::<better_auth::store::StatelessSchema, (), _>(
            auth.store().as_ref(),
            move |tx| {
                Box::pin(async move {
                    drop(
                        tx.update_session_active_team(&token, Some("uncommitted"))
                            .await?,
                    );
                    drop(
                        tx.update_session_active_organization(&token, Some("uncommitted"))
                            .await?,
                    );
                    Err(better_auth_core::AuthError::bad_request(
                        "abort scope change",
                    ))
                })
            },
        )
        .await;
    assert!(aborted.is_err());
    let session = auth.store().get_session(&retained.token).await?.unwrap();
    assert_eq!(session.active_team_id, original.active_team_id);
    assert_eq!(
        session.active_organization_id,
        original.active_organization_id
    );
    let mut restart_trace = Vec::new();
    let _response = call(
        &restarted,
        &mut restart_trace,
        "/organization/update",
        Some(json!({"organizationId":retained.organization,"data":{"name":"Replay"}})),
        &[],
        &retained.cookie,
        400,
    )
    .await?;
    let mut trace = Vec::new();
    let _response = call(
        &auth,
        &mut trace,
        "/organization/delete",
        Some(json!({"organizationId":retained.organization})),
        &[],
        &retained.cookie,
        200,
    )
    .await?;
    assert!(
        auth.store()
            .get_organization_by_id(&retained.foreign)
            .await?
            .is_some()
    );
    assert!(
        auth.store()
            .get_organization_role(
                &retained.organization,
                &better_auth_core::types::OrganizationRoleSelector::Id(retained.role)
            )
            .await?
            .is_some()
    );
    Ok(())
}

/// Snapshot reconciliation must preserve concurrent untouched rows and deletion.
#[tokio::test]
async fn native_organization_transaction_merge_and_rollback() -> TestResult {
    use better_auth_core::store::{
        MemberStore, TeamStore,
        stateless::{StatelessSchema, StatelessStore},
        transaction,
    };
    use better_auth_core::{AuthError, CreateMember, CreateTeam};
    let store = Arc::new(StatelessStore::default());
    let team = store
        .create_team(CreateTeam {
            name: "Target".into(),
            organization_id: "org".into(),
            updated_at: None,
        })
        .await?;
    let (staged, staged_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let owned = Arc::clone(&store);
    let team_id = team.id.clone();
    let work = tokio::spawn(async move {
        transaction::<StatelessSchema, _, _>(owned.as_ref(), move |tx| {
            Box::pin(async move {
                drop(tx.add_team_member(&team_id, "member", Some(1.5)).await?);
                staged
                    .send(())
                    .map_err(|_| AuthError::internal("staging receiver closed"))?;
                release_rx
                    .await
                    .map_err(|_| AuthError::internal("release sender closed"))?;
                Ok(())
            })
        })
        .await
    });
    staged_rx.await?;
    assert!(store.get_team_member(&team.id, "member").await?.is_none());
    assert!(store.delete_team("org", &team.id).await?);
    let unrelated = store
        .create_team(CreateTeam {
            name: "Concurrent".into(),
            organization_id: "foreign".into(),
            updated_at: None,
        })
        .await?;
    release.send(()).map_err(|_| "release receiver closed")?;
    work.await??;
    assert!(
        store.get_team(None, &team.id).await?.is_none(),
        "transaction must not resurrect a concurrently deleted base row"
    );
    assert!(store.get_team(None, &unrelated.id).await?.is_some());
    // Published row merge can leave the newly created membership after the
    // concurrent team deletion. No stronger foreign-key isolation is claimed.
    assert!(store.get_team_member(&team.id, "member").await?.is_some());
    let result = transaction::<StatelessSchema, (), _>(store.as_ref(), |tx| {
        Box::pin(async move {
            drop(
                tx.create_member(CreateMember {
                    organization_id: "org".into(),
                    user_id: "rollback".into(),
                    role: "member".into(),
                })
                .await?,
            );
            Err(AuthError::bad_request("abort"))
        })
    })
    .await;
    assert!(result.is_err());
    assert!(store.get_member("org", "rollback").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn native_organization_pages_keep_source_slice_and_empty_patch_semantics() -> TestResult {
    use better_auth_core::store::MemberPageQuery;
    use better_auth_core::store::{MemberStore, OrganizationStore, stateless::StatelessStore};
    use better_auth_core::{CreateMember, CreateOrganization, UpdateOrganization};
    let store = StatelessStore::with_find_many_limit(2);
    let organization = store
        .create_organization(
            CreateOrganization::new("Literal", "literal").with_metadata(Value::Null),
        )
        .await?;
    let patched = store
        .patch_organization_if_present(&organization.id, UpdateOrganization::default())
        .await?
        .unwrap();
    assert_eq!(patched, organization);
    for role in ["owner", "alpha", "beta"] {
        drop(
            store
                .create_member(CreateMember {
                    organization_id: organization.id.clone(),
                    user_id: role.into(),
                    role: role.into(),
                })
                .await?,
        );
    }
    // Expected roles are retained independently from published 1.7.6 adapter execution.
    for (offset, limit, expected) in [
        (0.0, 1.9, vec!["owner"]),
        (-2.9, 1.9, vec!["alpha"]),
        (0.0, -1.9, vec!["owner", "alpha"]),
        (-0.5, 2.5, vec!["owner", "alpha"]),
    ] {
        let (rows, total) = store
            .query_organization_members_page(&MemberPageQuery {
                organization_id: organization.id.clone(),
                offset: Some(offset),
                limit: Some(limit),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 3);
        assert_eq!(
            rows.iter().map(|row| row.role.as_str()).collect::<Vec<_>>(),
            expected,
            "offset {offset}, limit {limit}"
        );
    }
    let (page, count) = store
        .query_organization_members_page(&MemberPageQuery {
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await?;
    assert_eq!(page.len(), 2);
    assert_eq!(count, 3);
    Ok(())
}
