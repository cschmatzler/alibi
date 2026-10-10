//! Admin body coercion, unauthenticated access, remember-me impersonation,
//! date overflow and banned-user message callbacks.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::{AdminBannedUserMessage, AdminPlugin, RolePermissions};
use alibi::{AuthError, AuthResult, UpdateUser, entity::AuthUser};
use std::collections::{BTreeMap, HashMap};

backend_tests!(
    admin_input_and_session_matrix,
    admin_remember_me_impersonation,
    admin_banned_message_callback,
    admin_failure_modes,
    admin_user_validation,
    zero_admin_durations_and_empty_reason_use_effective_defaults
);

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            _ = jar.insert(name.to_owned(), value.to_owned());
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn promoted<B: Backend>(
    auth: &Alibi<B::Schema>,
    email: &str,
    role: &str,
) -> (String, String) {
    let response = signup(auth, email).await;
    let id = body(&response)["user"]["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .update_user(
            &id,
            UpdateUser {
                role: Some(role.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    (id, cookies(&response))
}

fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

async fn admin_input_and_session_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            AdminPlugin::new()
                .roles(HashMap::from([
                    (
                        "admin".into(),
                        RolePermissions::new()
                            .allow(
                                "user",
                                [
                                    "create",
                                    "list",
                                    "set-role",
                                    "ban",
                                    "impersonate",
                                    "delete",
                                    "set-password",
                                    "get",
                                    "update",
                                ],
                            )
                            .allow("session", ["list", "revoke", "delete"]),
                    ),
                    ("user".into(), RolePermissions::new()),
                ]))
                .impersonation_session_duration(1e300),
        )
        .build()
        .await?;
    let mut trace = Trace::default();
    let (admin_id, admin) = promoted::<B>(&auth, "policy-admin@example.com", "admin").await;
    let (member_id, _) = promoted::<B>(&auth, "policy-member@example.com", "user").await;
    trace.mask(&admin_id);
    trace.mask(&member_id);

    let routes = [
        "list-user-sessions",
        "ban-user",
        "unban-user",
        "impersonate-user",
        "revoke-user-sessions",
        "remove-user",
        "set-user-password",
        "revoke-user-session",
        "update-user",
        "has-permission",
    ];
    for route in routes {
        let path = format!("/admin/{route}");
        let mut inputs = vec![
            "[]".to_owned(),
            "null".into(),
            r#"{"newPassword":5,"sessionToken":5}"#.into(),
        ];
        if matches!(route, "list-user-sessions" | "set-user-password") {
            inputs.extend(
                [
                    r#"{"userId":null,"newPassword":"x"}"#,
                    r#"{"userId":true,"newPassword":"x"}"#,
                    r#"{"userId":[1,null,"a"],"newPassword":"x"}"#,
                    r#"{"userId":{},"newPassword":"x"}"#,
                    r#"{"userId":{"toString":1},"newPassword":"x"}"#,
                    r#"{"userId":[{"toString":1}],"newPassword":"x"}"#,
                    r#"{"userId":1.5,"newPassword":""}"#,
                    r#"{"userId":"","newPassword":""}"#,
                ]
                .map(str::to_owned),
            );
        }
        for text in inputs {
            trace.response(
                &format!("{route} {text}"),
                &Box::pin(auth.handle_request(raw(&path, &text, &admin))).await?,
            );
        }
    }
    for route in routes {
        trace.response(
            &format!("{route} anonymous"),
            &Box::pin(auth.handle_request(raw(
                &format!("/admin/{route}"),
                &format!(
                    r#"{{"userId":"{member_id}","newPassword":"long-enough-password","data":{{}},"sessionToken":"t"}}"#
                ),
                "",
            )))
            .await?,
        );
    }
    for email in [
        "plain",
        "@example.com",
        "a@b.c",
        "a@com",
        "a@-x.com",
        "a@x..com",
        ".a@example.com",
        "a..b@example.com",
        "a.@example.com",
        "a b@example.com",
        "a@exam_ple.com",
        "a@example.c0m",
    ] {
        trace.response(
            &format!("create {email}"),
            &Box::pin(auth.handle_request(request(
                "/admin/create-user",
                Some(json!({"email": email, "name": "N", "password": PASSWORD})),
                &admin,
            )))
            .await?,
        );
    }
    trace.response(
        "ban overflow",
        &Box::pin(auth.handle_request(request(
            "/admin/ban-user",
            Some(json!({"userId": member_id, "banExpiresIn": 1e300})),
            &admin,
        )))
        .await?,
    );
    trace.response(
        "impersonation overflow",
        &Box::pin(auth.handle_request(request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &admin,
        )))
        .await?,
    );
    for filter in [
        vec![
            ("filterField", "role"),
            ("filterValue", "user"),
            ("filterValue", "admin"),
        ],
        vec![("filterField", "role"), ("filterValue", "user")],
    ] {
        let mut list = request("/admin/list-users", None, &admin);
        list.set_query_pairs(filter.iter().copied());
        trace.response(
            &format!("list {filter:?}"),
            &Box::pin(auth.handle_request(list)).await?,
        );
    }
    trace.assert("admin/input-and-session-matrix");
    B::close(connection).await
}

async fn admin_remember_me_impersonation<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let (admin_id, _) = promoted::<B>(&auth, "remember-admin@example.com", "admin").await;
    let (member_id, _) = promoted::<B>(&auth, "remember-member@example.com", "user").await;
    trace.mask(&admin_id);
    trace.mask(&member_id);
    let sign_in = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({
                "email": "remember-admin@example.com",
                "password": PASSWORD,
                "rememberMe": false,
            })),
            "",
        ),
        200,
    )
    .await;
    let admin = cookies(&sign_in);
    assert!(admin.contains("dont_remember"));
    let impersonate = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &admin,
        ),
        200,
    )
    .await;
    trace.response("impersonate", &impersonate);
    let impersonating = merge(&admin, &cookies(&impersonate));
    assert!(impersonating.contains("admin_session"));
    for (label, cookie) in [
        (
            "without admin cookie",
            impersonating
                .split("; ")
                .filter(|pair| !pair.contains("admin_session"))
                .collect::<Vec<_>>()
                .join("; "),
        ),
        (
            "forged admin cookie",
            merge(&impersonating, "better-auth.admin_session=forged"),
        ),
    ] {
        trace.response(
            label,
            &Box::pin(auth.handle_request(request(
                "/admin/stop-impersonating",
                Some(json!({})),
                &cookie,
            )))
            .await?,
        );
    }
    let (second_id, second) = promoted::<B>(&auth, "second-admin@example.com", "admin").await;
    let second_impersonation = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &second,
        ),
        200,
    )
    .await;
    let foreign = cookies(&second_impersonation)
        .split("; ")
        .find(|pair| pair.starts_with("better-auth.admin_session="))
        .unwrap()
        .to_owned();
    let mismatched = merge(&impersonating, &foreign);
    trace.response(
        "admin cookie of another administrator",
        &Box::pin(auth.handle_request(request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &mismatched,
        )))
        .await?,
    );
    _ = db
        .execute("DELETE FROM sessions WHERE user_id = $1", &[&second_id])
        .await?;
    trace.response(
        "admin session no longer exists",
        &Box::pin(auth.handle_request(request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &mismatched,
        )))
        .await?,
    );
    let stopped = call(
        &auth,
        request("/admin/stop-impersonating", Some(json!({})), &impersonating),
        200,
    )
    .await;
    trace.response("stop restores remember-me", &stopped);
    assert!(cookies(&stopped).contains("dont_remember"));
    let restored = merge(&impersonating, &cookies(&stopped));
    let session = call(&auth, request("/get-session", None, &restored), 200).await;
    assert_eq!(
        body(&session)["user"]["email"],
        "remember-admin@example.com"
    );

    trace.assert("admin/remember-me-impersonation");
    B::close(connection).await
}

#[derive(Clone)]
struct Message(Arc<Mutex<&'static str>>);

#[async_trait::async_trait]
impl<U: AuthUser> AdminBannedUserMessage<U> for Message {
    async fn message(&self, user: &U) -> AuthResult<String> {
        match *self.0.lock().unwrap() {
            "fail" => Err(AuthError::internal("message unavailable")),
            "api" => Err(AuthError::forbidden("custom denial")),
            _ => Ok(format!("banned: {}", user.id())),
        }
    }
}

async fn admin_banned_message_callback<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mode = Arc::new(Mutex::new("ok"));
    let auth = builder::<B>(&connection)
        .plugin(
            AdminPlugin::new().banned_user_message_callback::<<B::Schema as AuthSchema>::User, _>(
                Message(mode.clone()),
            ),
        )
        .build()
        .await?;
    let mut trace = Trace::default();
    let (admin_id, admin) = promoted::<B>(&auth, "message-admin@example.com", "admin").await;
    let (member_id, _) = promoted::<B>(&auth, "message-member@example.com", "user").await;
    trace.mask(&admin_id);
    trace.mask(&member_id);
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId": member_id})),
            &admin,
        ),
        200,
    )
    .await;
    for name in ["ok", "fail", "api"] {
        *mode.lock().unwrap() = name;
        trace.response(
            &format!("sign-in {name}"),
            &Box::pin(auth.handle_request(request(
                "/sign-in/email",
                Some(json!({"email": "message-member@example.com", "password": PASSWORD})),
                "",
            )))
            .await?,
        );
        trace.response(
            &format!("impersonate {name}"),
            &Box::pin(auth.handle_request(request(
                "/admin/impersonate-user",
                Some(json!({"userId": member_id})),
                &admin,
            )))
            .await?,
        );
    }
    trace.assert("admin/banned-message-callback");
    B::close(connection).await
}

async fn admin_failure_modes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            AdminPlugin::new().roles(HashMap::from([
                (
                    "admin".into(),
                    RolePermissions::new()
                        .allow("user", ["ban", "impersonate", "create", "list"])
                        .allow("session", ["list"]),
                ),
                (
                    "support".into(),
                    RolePermissions::new().allow("user", ["list"]),
                ),
                ("user".into(), RolePermissions::new()),
            ])),
        )
        .build()
        .await?;
    let mut trace = Trace::default();
    let (admin_id, admin) = promoted::<B>(&auth, "failure-admin@example.com", "admin").await;
    let (support_id, support) =
        promoted::<B>(&auth, "failure-support@example.com", "support").await;
    let (member_id, _) = promoted::<B>(&auth, "failure-member@example.com", "user").await;
    for id in [&admin_id, &support_id, &member_id] {
        trace.mask(id);
    }
    for (label, path, input, cookie) in [
        (
            "ban an unknown user",
            "/admin/ban-user",
            json!({"userId": "missing"}),
            &admin,
        ),
        (
            "ban yourself",
            "/admin/ban-user",
            json!({"userId": admin_id}),
            &admin,
        ),
        (
            "unban without permission",
            "/admin/unban-user",
            json!({"userId": member_id}),
            &support,
        ),
        (
            "unban an unknown user",
            "/admin/unban-user",
            json!({"userId": "missing"}),
            &admin,
        ),
        (
            "stop impersonating anonymously",
            "/admin/stop-impersonating",
            json!({}),
            &String::new(),
        ),
    ] {
        trace.response(
            label,
            &Box::pin(auth.handle_request(request(path, Some(input), cookie))).await?,
        );
    }
    _ = db
        .execute(
            "CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    trace.response(
        "impersonate with a session storage failure",
        &Box::pin(auth.handle_request(request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &admin,
        )))
        .await?,
    );
    _ = db.execute("DROP TRIGGER fail_session_insert", &[]).await?;
    trace.assert("admin/failure-modes");
    B::close(connection).await
}

struct Admit;

#[async_trait::async_trait]
impl alibi::user_validation::UserInfoValidator for Admit {
    async fn validate(
        &self,
        _: &mut alibi::user_validation::UserValidationData,
        _: &alibi::hooks::RequestHookContext,
    ) -> AuthResult<Option<alibi::user_validation::UserValidationRejection>> {
        Ok(None)
    }
}

async fn admin_user_validation<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(Admit));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(alibi::plugins::AnonymousPlugin::new())
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let (admin_id, admin) = promoted::<B>(&auth, "validated-admin@example.com", "admin").await;
    trace.mask(&admin_id);
    _ = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    for (label, input) in [
        (
            "without data",
            json!({"email": "validated-one@example.com", "name": "One", "password": PASSWORD}),
        ),
        (
            "with data",
            json!({"email": "validated-two@example.com", "name": "Two", "password": PASSWORD, "data": {"image": "https://images.example/two"}}),
        ),
    ] {
        let response =
            Box::pin(auth.handle_request(request("/admin/create-user", Some(input), &admin)))
                .await?;
        trace.mask(body(&response)["user"]["id"].as_str().unwrap_or_default());
        trace.response(label, &response);
    }
    let listed = Box::pin(auth.handle_request(get("/admin/list-users", &[], &admin))).await?;
    let mut anonymity = body(&listed)["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| {
            format!(
                "{}={}",
                user["email"].as_str().unwrap().rsplit('@').next().unwrap(),
                user["isAnonymous"]
            )
        })
        .collect::<Vec<_>>();
    anonymity.sort();
    trace.value("anonymity of listed users", json!(anonymity));
    trace.assert("admin/user-validation");
    B::close(connection).await
}

fn get(path: &str, query: &[(&str, &str)], cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.set_query_pairs(query.iter().copied());
    request
}

async fn zero_admin_durations_and_empty_reason_use_effective_defaults<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            default_ban_reason: Some(String::new()),
            default_ban_expires_in: Some(0.0),
            impersonation_session_duration: Some(0.0),
            ..Default::default()
        }))
        .build()
        .await?;
    let (admin_id, admin) = promoted::<B>(&auth, "admin@example.test", "admin").await;
    let owner = signup(&auth, "owner@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "foreign@example.test").await;
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let original_accounts = db.table("accounts").await?;
    let banned = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":id,"banExpiresIn":0,"banReason":""})),
            &admin,
        ),
        200,
    )
    .await;
    assert_eq!(body(&banned)["user"]["banReason"], "No reason");
    assert!(body(&banned)["user"]["banExpires"].is_null());
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&id])
            .await?,
        0
    );
    assert!(auth.store().get_session(&foreign_token).await?.is_some());
    _ = call(
        &auth,
        request("/admin/unban-user", Some(json!({"userId":id})), &admin),
        200,
    )
    .await;
    let impersonated = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId":id})),
            &admin,
        ),
        200,
    )
    .await;
    let token = body(&impersonated)["session"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = auth.store().get_session(&token).await?.unwrap();
    assert_eq!(session.user_id(), id);
    assert_eq!(session.impersonated_by(), Some(admin_id.as_str()));
    assert!(
        (session.expires_at() - session.created_at() - chrono::Duration::hours(1))
            .num_milliseconds()
            .abs()
            < 100
    );
    assert_eq!(db.table("accounts").await?, original_accounts);
    authenticated(&auth, &admin, "admin@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
