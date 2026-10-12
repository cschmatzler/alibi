//! Administrative password updates preserve user, OAuth and session ownership.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, AdminSetUserPasswordRequest, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthAccount, CreateAccount, UpdateUser};

backend_tests!(server_admin_set_user_password_creates_or_replaces_credentials);

async fn server_admin_set_user_password_creates_or_replaces_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let admin = signup(&auth, "server-password-admin@example.test").await;
    let admin_id = body(&admin)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &admin_id,
                UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let target = signup(&auth, "server-password-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let fresh = signup(&auth, "server-password-no-credential@example.test").await;
    let fresh_id = body(&fresh)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-password-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let credential = auth
        .store()
        .get_user_accounts(&fresh_id)
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential")
        .unwrap();
    auth.store().delete_account(&credential.id()).await?;
    for owner in [&id, &fresh_id] {
        drop(
            auth.store()
                .create_account(CreateAccount {
                    user_id: owner.clone(),
                    account_id: format!("remote-{owner}"),
                    provider_id: "mock".into(),
                    access_token: Some("private-access".into()),
                    refresh_token: Some("private-refresh".into()),
                    id_token: None,
                    password: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    additional_fields: Default::default(),
                })
                .await?,
        );
    }
    assert_eq!(auth.store().get_user_accounts(&id).await?.len(), 2);
    assert_eq!(auth.store().get_user_accounts(&fresh_id).await?.len(), 1);
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for (input, headers, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!(null)),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id,"newPassword":""})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":"","newPassword":"Changed123!"})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id,"newPassword":7})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id,"newPassword":"Changed123!"})),
            EndpointOptions::default(),
            401,
            "",
        ),
        (
            Some(json!({"userId":id,"newPassword":"short"})),
            options(&foreign),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
        ),
        (
            Some(json!({"userId":"missing-user","newPassword":"short"})),
            options(&admin),
            400,
            "PASSWORD_TOO_SHORT",
        ),
        (
            Some(json!({"userId":id,"newPassword":"x".repeat(129)})),
            options(&admin),
            400,
            "PASSWORD_TOO_LONG",
        ),
        (
            Some(json!({"userId":id,"newPassword":"🔐".repeat(65)})),
            options(&admin),
            400,
            "PASSWORD_TOO_LONG",
        ),
        (
            Some(json!({"userId":null,"newPassword":"Changed123!"})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "setUserPassword");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth.dispatch_endpoint(endpoint, headers).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        } else {
            assert_eq!(body(&error.error.to_auth_response())["code"], code);
        }
    }
    let restricted = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update"]),
        )])))
        .build()
        .await?;
    let error = restricted
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "setUserPassword")
                .with_body(&json!({"userId":id,"newPassword":"Changed123!"}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let original_foreign =
        serde_json::to_value(auth.store().get_user_accounts(&foreign_id).await?)?;
    for (owner, owner_id, email, new_password) in [
        (
            &target,
            &id,
            "server-password-target@example.test",
            "🔐🔐🔐🔐",
        ),
        (
            &fresh,
            &fresh_id,
            "server-password-no-credential@example.test",
            "Fresh123!",
        ),
        (
            &admin,
            &admin_id,
            "server-password-admin@example.test",
            "AdminNew123!",
        ),
    ] {
        let immutable = db.tables(&["users", "sessions"]).await?;
        let prior = auth.store().get_user_accounts(owner_id).await?;
        let remote = serde_json::to_value(
            prior
                .iter()
                .filter(|account| account.provider_id() != "credential")
                .collect::<Vec<_>>(),
        )?;
        let old_credential = prior
            .iter()
            .find(|account| account.provider_id() == "credential")
            .map(|account| account.id().into_owned());
        let input = AdminSetUserPasswordRequest::new(owner_id.clone(), new_password);
        let output=auth.dispatch_endpoint(AdminPlugin::set_user_password_endpoint(&input)?
            .with_body(&json!({"userId":owner_id,"newPassword":new_password,"revokeOtherSessions":true}))?
            .with_query(&json!({"userId":foreign_id}))?,options(&admin)).await?;
        assert!(output.decode()?.status);
        assert_eq!(output.value().get("status"), Some(&JsValue::Bool(true)));
        assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
        assert_eq!(
            output
                .headers()
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "application_a=first; Path=/; HttpOnly",
                "application_b=second; Path=/; HttpOnly"
            ]
        );
        assert_eq!(db.tables(&["users", "sessions"]).await?, immutable);
        let accounts = auth.store().get_user_accounts(owner_id).await?;
        assert_eq!(
            serde_json::to_value(
                accounts
                    .iter()
                    .filter(|account| account.provider_id() != "credential")
                    .collect::<Vec<_>>()
            )?,
            remote
        );
        let credentials = accounts
            .iter()
            .filter(|account| account.provider_id() == "credential")
            .collect::<Vec<_>>();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].account_id(), owner_id.as_str());
        if let Some(old_id) = old_credential {
            assert_eq!(credentials[0].id(), old_id);
        }
        assert_eq!(
            serde_json::to_value(auth.store().get_user_accounts(&foreign_id).await?)?,
            original_foreign
        );
        assert_eq!(
            body(&call(&auth, request("/get-session", None, &cookies(owner)), 200).await)["user"]["id"],
            *owner_id
        );
        let old = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(body(&old)["code"], "INVALID_EMAIL_OR_PASSWORD");
        let login = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":new_password})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&login)["user"]["id"], *owner_id);
    }
    B::close(connection).await
}
