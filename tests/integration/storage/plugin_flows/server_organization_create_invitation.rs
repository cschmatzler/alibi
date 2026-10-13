//! Canonical server invitation creation owns delivery and subsequent admission.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationInvitationDelivery, OrganizationInvitationEmailSender,
};
use alibi::utils::json::JsValue;

backend_tests!(server_create_invitation_delivers_stored_invitation_without_request);
#[derive(Debug, Default)]
struct Delivery(Mutex<Vec<OrganizationInvitationDelivery>>);
#[async_trait::async_trait]
impl OrganizationInvitationEmailSender for Delivery {
    async fn send_invitation_email(
        &self,
        value: &OrganizationInvitationDelivery,
        callback: &alibi::CallbackContext,
    ) -> alibi::AuthResult<()> {
        assert!(callback.request.is_none());
        self.0.lock().unwrap().push(value.clone());
        Ok(())
    }
}
async fn server_create_invitation_delivers_stored_invitation_without_request<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let delivery = Arc::new(Delivery::default());
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            send_invitation_email: Some(delivery.clone()),
            invitation_expires_in: Some(7200.0),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "server-invitation-owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let outsider = signup(&auth, "server-invitation-outsider@example.test").await;
    let recipient = signup(&auth, "server-invitation-recipient@example.test").await;
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Server invitation organization","slug":"server-invitation-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let org_id = body(&created)["id"].as_str().unwrap().to_owned();
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db
        .tables(&["invitation", "member", "session", "organization"])
        .await?;
    for (input, headers, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!({"email":"server-invitation-recipient@example.test","role":7})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(
                json!({"email":"server-invitation-recipient@example.test","role":"member","organizationId":org_id}),
            ),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(
                json!({"email":"server-invitation-recipient@example.test","role":"member","organizationId":org_id}),
            ),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            Some(
                json!({"email":"server-invitation-recipient@example.test","role":"member","organizationId":org_id}),
            ),
            options(&outsider),
            400,
            "MEMBER_NOT_FOUND",
        ),
        (
            Some(json!({"email":"bad-email","role":"member","organizationId":org_id})),
            options(&owner),
            400,
            "INVALID_EMAIL",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("organization", "createInvitation");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth.dispatch_endpoint(endpoint, headers).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert!(delivery.0.lock().unwrap().is_empty());
    assert_eq!(
        db.tables(&["invitation", "member", "session", "organization"])
            .await?,
        before
    );
    let input = serde_json::from_value(
        json!({"email":"SERVER-INVITATION-RECIPIENT@EXAMPLE.TEST","role":["member","admin"],"organizationId":org_id}),
    )?;
    let output=auth.dispatch_endpoint(OrganizationPlugin::create_invitation_endpoint(&input)?
        .with_body(&json!({"email":"SERVER-INVITATION-RECIPIENT@EXAMPLE.TEST","role":["member","admin"],"organizationId":org_id,"status":"accepted","inviterId":"foreign"}))?
        .with_query(&json!({"organizationId":"wrong-org"}))?,options(&owner)).await?;
    assert_eq!(
        output.decode()?.email,
        "server-invitation-recipient@example.test"
    );
    let invitation = output.value();
    let id = invitation.get("id").and_then(JsValue::as_str).unwrap();
    assert_eq!(
        invitation.get("email"),
        Some(&JsValue::String(
            "server-invitation-recipient@example.test".into()
        ))
    );
    assert_eq!(
        invitation.get("status"),
        Some(&JsValue::String("pending".into()))
    );
    assert_eq!(
        invitation.get("inviterId"),
        Some(&JsValue::String(owner_id.clone()))
    );
    assert_eq!(
        invitation.get("role"),
        Some(&JsValue::String("member,admin".into()))
    );
    let sent = delivery.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].invitation.id, id);
    assert_eq!(sent[0].user.id, owner_id);
    assert_eq!(sent[0].email(), "server-invitation-recipient@example.test");
    assert_eq!(
        db.tables(&["member", "session", "organization"]).await?,
        before[1..]
    );
    let accepted = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":id})),
            &cookies(&recipient),
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["member"]["organizationId"], org_id);
    assert_eq!(body(&accepted)["member"]["role"], "member,admin");
    assert_eq!(
        body(&accepted)["member"]["userId"],
        body(&recipient)["user"]["id"]
    );
    B::close(connection).await
}
