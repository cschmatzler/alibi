//! Public server provisioning distinguishes trusted callers from authenticated grants.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminCreateUserRequest, AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthUser, UpdateUser};

backend_tests!(server_admin_create_user_scopes_provisioning_and_creates_usable_credentials);

async fn server_admin_create_user_scopes_provisioning_and_creates_usable_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().default_role("admin"))
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let administrator = signup(&auth, "provision-admin@example.test").await;
    let admin_id = body(&administrator)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let member = signup(&auth, "provision-member@example.test").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &member_id,
                UpdateUser {
                    role: Some("user".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let creator_auth =
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(AdminPlugin::new().default_role("creator").roles(
                std::collections::HashMap::from([
                    (
                        "creator".into(),
                        RolePermissions::new().allow("user", ["create"]),
                    ),
                    ("user".into(), RolePermissions::new()),
                ]),
            ))
            .endpoint_hook(super::server_admin_support::AdminObserver)
            .build()
            .await?;
    let creator = signup(&creator_auth, "provision-creator@example.test").await;
    let creator_id = body(&creator)["user"]["id"].as_str().unwrap().to_owned();
    let headers = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, options, status) in [
        (None, EndpointOptions::default(), 400),
        (Some(json!(null)), EndpointOptions::default(), 400),
        (Some(json!({})), EndpointOptions::default(), 400),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked","password":null})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked","data":null})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked","role":null})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked"})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
        ),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked"})),
            headers(&member),
            403,
        ),
        (
            Some(json!({"email":"invalid","name":"Blocked"})),
            headers(&member),
            403,
        ),
        (
            Some(json!({"email":"blocked@example.test","name":"Blocked","data":{"role":7}})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"email":"invalid","name":"Blocked"})),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(
                json!({"email":"blocked@example.test","name":"Blocked","password":"x".repeat(129)}),
            ),
            EndpointOptions::default(),
            400,
        ),
        (
            Some(json!({"email":"provision-member@example.test","name":"Blocked"})),
            EndpointOptions::default(),
            400,
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "createUser");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth.dispatch_endpoint(endpoint, options).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
    }
    for (data, code) in [
        (json!({"role":"user"}), "change users role"),
        (json!({"banned":false}), "ban users"),
    ] {
        let error = creator_auth
            .dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("admin", "createUser").with_body(
                    &json!({"email":"blocked@example.test","name":"Blocked","data":data}),
                )?,
                headers(&creator),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 403);
        assert!(error.error.to_string().contains(code));
    }
    let error = creator_auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "createUser").with_body(
                &json!({"email":"blocked@example.test","name":"Blocked","role":"ghost"}),
            )?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 400);
    assert!(error.error.to_string().contains("non-existent"));
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let original_users = [
        auth.store().get_user_by_id(&admin_id).await?.unwrap(),
        auth.store().get_user_by_id(&member_id).await?.unwrap(),
        auth.store()
            .get_user_by_id(body(&creator)["user"]["id"].as_str().unwrap())
            .await?
            .unwrap(),
    ];
    let mut original_states = Vec::new();
    for other in &original_users {
        original_states.push(json!({"user":other,"accounts":auth.store().get_user_accounts(other.id().as_ref()).await?,"sessions":auth.store().get_user_sessions(other.id().as_ref()).await?}));
    }
    for (index, (extra, password, role, options, use_creator)) in [
        (json!({}), None, "admin", EndpointOptions::default(), false),
        (
            json!({"password":""}),
            None,
            "admin",
            EndpointOptions::default(),
            false,
        ),
        (
            json!({"password":"short","role":["user","admin"]}),
            Some("short"),
            "user,admin",
            headers(&administrator),
            false,
        ),
        (
            json!({"password":PASSWORD}),
            Some(PASSWORD),
            "creator",
            headers(&creator),
            true,
        ),
        (
            json!({"role":[],"data":{"role":7}}),
            None,
            "",
            EndpointOptions::default(),
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let active = if use_creator { &creator_auth } else { &auth };
        let email = format!("provisioned-{index}@example.test");
        let mut input = extra.as_object().unwrap().clone();
        drop(input.insert("email".into(), json!(email.to_uppercase())));
        drop(input.insert("name".into(), json!("Provisioned")));
        drop(input.insert("ignored".into(), json!("value")));
        let typed = if index == 0 {
            AdminCreateUserRequest::new(email.to_uppercase(), "Provisioned")
        } else {
            serde_json::from_value::<AdminCreateUserRequest>(json!(input))?
        };
        let output = active
            .dispatch_endpoint(
                AdminPlugin::create_user_endpoint(&typed)?
                    .with_body(&input)?
                    .with_query(&json!({"email":"blocked@example.test"}))?,
                options,
            )
            .await?;
        assert_eq!(
            output.decode()?.user.values().get("email"),
            Some(&json!(email))
        );
        let user = output.value().get("user").unwrap();
        let id = user.get("id").and_then(JsValue::as_str).unwrap();
        assert_eq!(user.get("email"), Some(&JsValue::String(email.clone())));
        assert_eq!(user.get("role"), Some(&JsValue::String(role.into())));
        assert!(user.get("password").is_none());
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
        let principal = output.headers().get("x-admin-principal");
        assert_eq!(
            principal,
            if use_creator {
                Some(&creator_id)
            } else if password.is_some() {
                Some(&admin_id)
            } else {
                None
            }
        );
        let stored = active.store().get_user_by_id(id).await?.unwrap();
        assert_eq!(stored.email(), Some(email.as_str()));
        assert_eq!(stored.role(), Some(role));
        assert!(active.store().get_user_sessions(id).await?.is_empty());
        let accounts = active.store().get_user_accounts(id).await?;
        assert_eq!(accounts.len(), usize::from(password.is_some()));
        if let Some(password) = password {
            let login = call(
                active,
                request(
                    "/sign-in/email",
                    Some(json!({"email":email,"password":password})),
                    "",
                ),
                200,
            )
            .await;
            assert_eq!(body(&login)["user"]["id"], id);
        }
        for (other, original) in original_users.iter().zip(&original_states) {
            assert_eq!(
                json!({"user":auth.store().get_user_by_id(other.id().as_ref()).await?.unwrap(),"accounts":auth.store().get_user_accounts(other.id().as_ref()).await?,"sessions":auth.store().get_user_sessions(other.id().as_ref()).await?}),
                *original
            );
        }
    }
    B::close(connection).await
}
