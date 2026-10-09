//! Imported application tables exercised through the native plugin and store.
use super::*;
use alibi::prelude::{
    CreateInvitation, CreateMember, CreateOrganization, InvitationStatus, UpdateOrganization,
};
use alibi::sqlx::{OrganizationModels, SqlxModel};
use alibi::store::{InvitationStore, MemberStore, OrganizationStore, SessionStore};
use serde_json::{Value, json};

#[derive(Clone, Debug, sqlx::FromRow, SqlxModel)]
#[auth(table = "event")]
struct Event {
    #[auth(column_type = "bpchar")]
    id: String,
    name: String,
    slug: String,
    logo: Option<String>,
    metadata: Option<String>,
    created_at: NaiveDateTime,
    language: String,
    billing_key: String,
}
#[derive(Clone, Debug, sqlx::FromRow, SqlxModel)]
#[auth(table = "member")]
struct Membership {
    #[auth(column_type = "bpchar")]
    id: String,
    #[sqlx(rename = "event_id")]
    #[auth(column_type = "bpchar")]
    organization_id: String,
    #[auth(column_type = "bpchar")]
    user_id: String,
    role: String,
    created_at: NaiveDateTime,
}
#[derive(Clone, Debug, sqlx::FromRow, SqlxModel)]
#[auth(table = "invitation")]
struct Invite {
    #[auth(column_type = "bpchar")]
    id: String,
    #[sqlx(rename = "event_id")]
    #[auth(column_type = "bpchar")]
    organization_id: String,
    email: String,
    role: Option<String>,
    status: String,
    #[auth(column_type = "bpchar")]
    inviter_id: String,
    expires_at: NaiveDateTime,
    created_at: NaiveDateTime,
}
auth_model!(sqlx, session, "session", "sessions", [user_id: String], {
    pub token: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub active: bool,
    #[sqlx(rename = "active_event_id")]
    #[auth(column_type = "bpchar")]
    pub active_organization_id: Option<String>,
});
#[derive(Clone)]
struct Schema;
impl AuthSchema for Schema {
    type User = super::sqlx_char::user::Model;
    type Account = super::sqlx_char::account::Model;
    type Verification = super::sqlx_char::verification::Model;
    type Session = session::Model;
}
fn event_id() -> String {
    format!("evt_{}", &new_id()[4..])
}
fn member_id() -> String {
    format!("mem_{}", &new_id()[4..])
}
fn invitation_id() -> String {
    format!("inv_{}", &new_id()[4..])
}

#[tokio::test]
async fn sqlite_application_organization_plugin() -> TestResult {
    Box::pin(exercise(Db::sqlite().await?)).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_application_organization_plugin() -> TestResult {
    Box::pin(exercise(Db::postgres().await?)).await
}

async fn exercise(db: Db) -> TestResult {
    install_as(
        &db,
        if db.is_postgres() { "CHAR(30)" } else { "TEXT" },
        false,
        true,
    )
    .await?;
    let id_type = if db.is_postgres() { "CHAR(30)" } else { "TEXT" };
    for statement in [
        format!(
            "CREATE TABLE event (id {id_type} PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, logo TEXT, metadata TEXT, created_at TIMESTAMP NOT NULL, language TEXT NOT NULL, billing_key TEXT NOT NULL DEFAULT 'existing-billing')"
        ),
        format!(
            "CREATE TABLE member (id {id_type} PRIMARY KEY, event_id {id_type} NOT NULL REFERENCES event(id), user_id {id_type} NOT NULL REFERENCES users(id), role TEXT NOT NULL, created_at TIMESTAMP NOT NULL)"
        ),
        format!(
            "CREATE TABLE invitation (id {id_type} PRIMARY KEY, event_id {id_type} NOT NULL REFERENCES event(id), email TEXT NOT NULL, role TEXT, status TEXT NOT NULL, inviter_id {id_type} NOT NULL REFERENCES users(id), expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL)"
        ),
        format!("ALTER TABLE sessions ADD COLUMN active_event_id {id_type} REFERENCES event(id)"),
    ] {
        _ = db.execute(&statement, &[]).await?;
    }
    let config = AuthConfig::new("application-organization-secret-at-least-32")
        .base_url("http://mapped.fixture.test");
    let connection = super::super::Sqlx::connect(&db.url, Some(1)).await?;
    let bundled = alibi::sqlx::SqlxStore::<Schema>::new(config.clone(), connection.clone());
    let unsupported = bundled
        .get_organization_by_id("evt_00000000000000000000000001")
        .await
        .unwrap_err();
    assert!(unsupported.to_string().contains("organization"));
    let store = alibi::sqlx::SqlxStore::<Schema>::new(config.clone(), connection)
        .with_organization_models(OrganizationModels::new::<Event, Membership, Invite>(
            event_id,
            member_id,
            invitation_id,
        ));
    let owner = store
        .create_user(
            CreateUser::new()
                .with_email("owner@mapped.fixture.test")
                .with_name("Owner"),
        )
        .await?;
    let guest = store
        .create_user(
            CreateUser::new()
                .with_email("guest@mapped.fixture.test")
                .with_name("Guest"),
        )
        .await?;
    let owner_session = store
        .create_session(session_input(owner.id().into_owned()))
        .await?;
    let guest_session = store
        .create_session(session_input(guest.id().into_owned()))
        .await?;
    let mut imported = CreateOrganization::new("Imported", "imported");
    imported.id = Some("evt_00000000000000000000000001".into());
    _ = imported
        .additional_fields
        .insert("language".into(), json!("en").into());
    let imported = store.create_organization(imported).await?;
    assert_eq!(imported.id, "evt_00000000000000000000000001");
    let membership = store
        .create_member(CreateMember::new(
            &imported.id,
            owner.id().as_ref(),
            "owner",
        ))
        .await?;
    assert!(membership.id.starts_with("mem_"));
    assert_eq!(membership.id.len(), 30);
    assert_eq!(
        store.list_user_organizations(owner.id().as_ref()).await?[0].id,
        imported.id
    );
    assert_eq!(store.count_organization_owners(&imported.id).await?, 1);
    assert!(
        store
            .get_member(&imported.id, owner.id().as_ref())
            .await?
            .is_some()
    );
    let changed = store
        .update_organization(
            &imported.id,
            UpdateOrganization {
                name: Some("Retained".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(changed.additional_fields["language"], "en");
    assert_eq!(changed.additional_fields["billing_key"], "existing-billing");
    let invitation = store
        .create_invitation(CreateInvitation::new(
            &imported.id,
            guest.email().unwrap(),
            "member",
            owner.id().as_ref(),
            Utc::now() + Duration::hours(1),
        ))
        .await?;
    assert!(invitation.id.starts_with("inv_"));
    assert_eq!(invitation.id.len(), 30);
    assert_eq!(
        store
            .count_pending_organization_invitations(&imported.id)
            .await?,
        1
    );
    assert!(
        store
            .get_pending_invitation(&imported.id, guest.email().unwrap())
            .await?
            .is_some()
    );
    assert!(
        store
            .accept_invitation_with_teams(
                &invitation.id,
                guest.id().as_ref(),
                owner_session.token(),
                &[],
                None
            )
            .await
            .is_err()
    );
    assert!(
        store
            .get_member(&imported.id, guest.id().as_ref())
            .await?
            .is_none()
    );
    assert!(
        store
            .accept_invitation_with_teams(
                &invitation.id,
                guest.id().as_ref(),
                guest_session.token(),
                &[],
                Some(1)
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await?
            .unwrap()
            .status,
        InvitationStatus::Pending
    );
    let (_, joined) = store
        .accept_invitation_with_teams(
            &invitation.id,
            guest.id().as_ref(),
            guest_session.token(),
            &[],
            Some(2),
        )
        .await?
        .unwrap();
    assert!(joined.id.starts_with("mem_"));
    assert_eq!(joined.role, "member");
    assert_eq!(
        store
            .get_session(guest_session.token())
            .await?
            .unwrap()
            .active_organization_id(),
        Some(imported.id.as_str())
    );
    assert!(
        store
            .accept_invitation_with_teams(
                &invitation.id,
                guest.id().as_ref(),
                guest_session.token(),
                &[],
                None
            )
            .await?
            .is_none()
    );
    // An imported nullable role remains null on reads and status transitions.
    _ = db
        .execute(
            "UPDATE invitation SET role = NULL WHERE id = $1",
            &[&invitation.id],
        )
        .await?;
    let nullable = store.get_invitation_by_id(&invitation.id).await?.unwrap();
    assert_eq!(nullable.role, None);
    assert_eq!(
        serde_json::to_value(alibi::wire::InvitationView::from(&nullable))?["role"],
        Value::Null
    );
    assert_eq!(
        store
            .update_invitation_status_if_status(
                &invitation.id,
                InvitationStatus::Accepted,
                InvitationStatus::Rejected
            )
            .await?
            .unwrap()
            .role,
        None
    );

    let mut fields = alibi::field_policy::SessionFields::default();
    let mut language_field = alibi::field_policy::FieldConfig::new(json!({"type":"string"}));
    language_field.required = true;
    _ = fields.0.insert("language".into(), language_field);
    let callbacks = std::sync::Arc::new(AppCallbacks::default());
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(store.clone())
        .plugin(alibi::plugins::OrganizationPlugin::with_config(
            alibi::plugins::organization::OrganizationConfig {
                organization_fields: fields,
                creation_policy: Some(callbacks.clone()),
                creation_hooks: Some(callbacks.clone()),
                deletion_hooks: Some(callbacks.clone()),
                send_invitation_email: Some(callbacks.clone()),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let cookie = alibi::utils::cookie_utils::create_session_cookie(owner_session.token(), &config)?;
    let guest_cookie =
        alibi::utils::cookie_utils::create_session_cookie(guest_session.token(), &config)?;
    let (denied, _) = post(
        &auth,
        "/organization/create",
        json!({"name":"Guest", "slug":"guest", "language":"en"}),
        &guest_cookie,
    )
    .await?;
    assert_eq!(denied, 403);
    assert!(store.get_organization_by_slug("guest").await?.is_none());
    let (missing_status, missing) = post(
        &auth,
        "/organization/create",
        json!({"name":"Missing", "slug":"missing"}),
        &cookie,
    )
    .await?;
    assert_eq!(missing_status, 400);
    assert_eq!(missing["code"], "MISSING_FIELD");
    assert!(store.get_organization_by_slug("missing").await?.is_none());
    let (status, output) = post(
        &auth,
        "/organization/create",
        json!({"name":"Native", "slug":"native", "language":"de"}),
        &cookie,
    )
    .await?;
    assert_eq!(status, 200, "{output}");
    assert_eq!(output["language"], "de");
    let native_id = output["id"].as_str().unwrap();
    assert!(native_id.starts_with("evt_"));
    assert_eq!(native_id.len(), 30);
    let (status, updated) = post(
        &auth,
        "/organization/update",
        json!({"organizationId":native_id, "data":{"language":"fr"}}),
        &cookie,
    )
    .await?;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["language"], "fr");
    assert_eq!(
        db.text("SELECT language FROM event WHERE id = $1", &[native_id])
            .await?
            .as_deref(),
        Some("fr")
    );
    assert_eq!(
        db.text("SELECT billing_key FROM event WHERE id = $1", &[native_id])
            .await?
            .as_deref(),
        Some("existing-billing")
    );
    let typed = typed_organization_calls(&auth, &cookie).await?;
    assert_eq!(
        db.text("SELECT language FROM event WHERE id = $1", &[&typed])
            .await?
            .as_deref(),
        Some("it")
    );
    assert_eq!(
        db.text("SELECT billing_key FROM event WHERE id = $1", &[&typed])
            .await?
            .as_deref(),
        Some("existing-billing")
    );
    store.delete_organization(&typed).await?;
    _ = store
        .update_session_active_organization(guest_session.token(), None)
        .await?;
    store.delete_organization(&imported.id).await?;
    assert_eq!(store.count_organization_members(&imported.id).await?, 0);
    assert!(
        store
            .list_organization_invitations(&imported.id)
            .await?
            .is_empty()
    );
    assert!(store.get_organization_by_id(native_id).await?.is_some());
    let (denied, _) = post(
        &auth,
        "/organization/update",
        json!({"organizationId":native_id, "data":{"language":"guest-change"}}),
        &guest_cookie,
    )
    .await?;
    assert_eq!(denied, 400);
    let (status, sent) = post(
        &auth,
        "/organization/invite-member",
        json!({"organizationId":native_id, "email":"guest@mapped.fixture.test", "role":"member"}),
        &cookie,
    )
    .await?;
    assert_eq!(status, 200, "{sent}");
    let (status, accepted) = post(
        &auth,
        "/organization/accept-invitation",
        json!({"invitationId":sent["id"]}),
        &guest_cookie,
    )
    .await?;
    assert_eq!(status, 200, "{accepted}");
    assert!(
        store
            .get_member(native_id, guest.id().as_ref())
            .await?
            .unwrap()
            .id
            .starts_with("mem_")
    );
    assert_eq!(
        db.text(
            "SELECT active_event_id FROM sessions WHERE token = $1",
            &[guest_session.token()]
        )
        .await?
        .as_deref(),
        Some(native_id)
    );
    _ = store
        .update_session_active_organization(guest_session.token(), None)
        .await?;
    let (status, deleted) = post(
        &auth,
        "/organization/delete",
        json!({"organizationId":native_id}),
        &cookie,
    )
    .await?;
    assert_eq!(status, 200, "{deleted}");
    assert!(store.get_organization_by_id(native_id).await?.is_none());
    assert_eq!(
        *callbacks.receipts.lock().unwrap(),
        ["billing:de", "billing:nl", "email:fr", "cleanup:fr"]
    );
    Ok(())
}

/// Typed native create and update keep configured fields and drop unknown ones.
async fn typed_organization_calls(
    auth: &alibi::BetterAuth<Schema>,
    cookie: &str,
) -> TestResult<String> {
    use alibi::plugins::organization::types::{
        CreateOrganizationRequest, UpdateOrganizationData, UpdateOrganizationRequest,
    };
    let credentials = || alibi::endpoint::EndpointOptions {
        headers: Some([("cookie".into(), cookie.into())].into()),
        ..Default::default()
    };
    let created = Box::pin(auth.dispatch_endpoint(
        alibi::plugins::OrganizationPlugin::create_endpoint(
            &CreateOrganizationRequest {
                additional_fields: serde_json::from_value(
                    json!({"language":"nl", "billing_key":"forged"}),
                )?,
                name: "Typed".into(),
                slug: "typed".into(),
                logo: None,
                metadata: None,
                keep_current_active_organization: Some(true),
            },
            None,
        )?,
        credentials(),
    ))
    .await?
    .decode()?;
    assert_eq!(created.organization.additional_fields["language"], "nl");
    let id = created.organization.id;
    let updated = Box::pin(auth.dispatch_endpoint(
        alibi::plugins::OrganizationPlugin::update_endpoint(&UpdateOrganizationRequest {
            organization_id: Some(id.clone()),
            data: UpdateOrganizationData {
                additional_fields: serde_json::from_value(json!({"language":"it"}))?,
                name: None,
                slug: None,
                logo: None,
                metadata: None,
            },
        })?,
        credentials(),
    ))
    .await?
    .decode()?
    .unwrap();
    assert_eq!(updated.additional_fields["language"], "it");
    Ok(id)
}

async fn post(
    auth: &alibi::BetterAuth<Schema>,
    path: &str,
    body: Value,
    cookie: &str,
) -> TestResult<(u16, Value)> {
    let mut request = alibi::prelude::AuthRequest::new(alibi::prelude::HttpMethod::Post, path);
    _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    _ = request
        .headers
        .insert("origin".into(), "http://mapped.fixture.test".into());
    _ = request.headers.insert("cookie".into(), cookie.into());
    request.body = Some(serde_json::to_vec(&body)?);
    let response = Box::pin(auth.handle_request(request)).await?;
    Ok((response.status, serde_json::from_slice(&response.body)?))
}

fn session_input(user_id: String) -> CreateSession {
    CreateSession {
        user_id,
        token: None,
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
        additional_fields: Default::default(),
    }
}

use alibi::plugins::organization::{
    OrganizationCreatedContext, OrganizationCreationHooks, OrganizationCreationPolicy,
    OrganizationDeleteContext, OrganizationDeletionHooks, OrganizationInvitationDelivery,
    OrganizationInvitationEmailSender,
};
#[derive(Debug, Default)]
struct AppCallbacks {
    receipts: std::sync::Mutex<Vec<String>>,
}
#[async_trait::async_trait]
impl OrganizationCreationPolicy for AppCallbacks {
    async fn allow_creation(
        &self,
        user: &alibi::wire::UserView,
    ) -> alibi::AuthResult<Option<bool>> {
        Ok(Some(
            user.email.as_deref() != Some("guest@mapped.fixture.test"),
        ))
    }
}
#[async_trait::async_trait]
impl OrganizationCreationHooks for AppCallbacks {
    async fn after_create(&self, context: &OrganizationCreatedContext) -> alibi::AuthResult<()> {
        self.receipts.lock().unwrap().push(format!(
            "billing:{}",
            context.organization.additional_fields["language"]
                .as_str()
                .unwrap()
        ));
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationDeletionHooks for AppCallbacks {
    async fn after_delete(&self, context: &OrganizationDeleteContext) -> alibi::AuthResult<()> {
        self.receipts.lock().unwrap().push(format!(
            "cleanup:{}",
            context.organization.additional_fields["language"]
                .as_str()
                .unwrap()
        ));
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationInvitationEmailSender for AppCallbacks {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        _callback: &alibi::CallbackContext,
    ) -> alibi::AuthResult<()> {
        self.receipts.lock().unwrap().push(format!(
            "email:{}",
            delivery.organization.additional_fields["language"]
                .as_str()
                .unwrap()
        ));
        Ok(())
    }
}
