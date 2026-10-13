//! Admin route input validation, role authority and moderation outcomes.
use super::*;
use crate::snapshot::Trace;
use alibi::UpdateUser;
use alibi::plugins::{AdminPlugin, RolePermissions};
use std::collections::HashMap;

backend_tests!(
    admin_route_matrix,
    admin_impersonation_and_bans,
    create_only_role_cannot_initialize_ban_properties,
    update_only_role_cannot_mutate_any_ban_property,
    update_only_role_cannot_change_email_verification,
    admin_password_bounds_preserve_credentials_until_valid_replacement,
    admin_email_replacement_moves_login_without_replacing_accounts_or_sessions,
    configured_role_validation_precedes_missing_target_lookup,
    admin_email_values_are_coerced_and_validated_before_any_update,
    demoted_admin_cannot_use_stale_cookie_cache_to_restore_grants,
    explicit_empty_admin_roles_deny_builtin_grants_without_losing_sessions,
    admin_role_tokens_with_whitespace_do_not_gain_privileges_or_admin_protection,
    blank_admin_role_falls_back_to_configured_user_permission,
    create_only_role_cannot_select_explicit_or_nested_roles,
    admin_password_field_rejects_accompanying_profile_mutations,
    admin_colliding_email_rejects_accompanying_profile_mutations,
    admin_update_ban_revokes_every_target_browser_and_preserves_foreign_sessions,
    admin_empty_update_authority_order,
    admin_self_ban_update_preserves_state_and_live_authority,
    admin_literal_role_input_admission,
    admin_create_role_selector_precedence,
    admin_array_filter_sql_operands,
    admin_repeated_query_validation_before_auth,
    admin_date_callback_error_identity,
    admin_stored_timestamp_precision_survives_public_projections,
    admin_impersonation_operator_metadata,
    admin_missing_tampered_and_revoked_sessions_reject_without_writes
);

async fn promote<S: AuthSchema>(auth: &Alibi<S>, response: &AuthResponse, role: &str) -> String {
    let id = body(response)["user"]["id"].as_str().unwrap().to_owned();
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
    id
}

fn roles() -> HashMap<String, RolePermissions> {
    HashMap::from([
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
                        "set-email",
                    ],
                )
                .allow("session", ["list", "revoke", "delete"]),
        ),
        (
            "support".into(),
            RolePermissions::new().allow("user", ["update", "get", "list"]),
        ),
        ("user".into(), RolePermissions::new()),
    ])
}

async fn admin_route_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            AdminPlugin::new()
                .roles(roles())
                .default_ban_reason("Policy violation".into()),
        )
        .build()
        .await?;
    let mut trace = Trace::default();
    let administrator = signup(&auth, "matrix-admin@example.com").await;
    let admin_id = promote(&auth, &administrator, "admin").await;
    let admin = cookies(&administrator);
    let supporter = signup(&auth, "matrix-support@example.com").await;
    _ = promote(&auth, &supporter, "support").await;
    let support = cookies(&supporter);
    let member = signup(&auth, "matrix-member@example.com").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&admin_id);
    trace.mask(&member_id);

    let post = |path: &str, input: Value| request(path, Some(input), "");
    let cases: Vec<(&str, &str, Value, &str)> = vec![
        ("create-user", "/admin/create-user", json!([]), "admin"),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": 5, "name": null, "password": true}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "invalid", "name": "Invalid", "password": PASSWORD}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "long@example.com", "name": "Long", "password": "x".repeat(200)}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "role@example.com", "name": "Role", "password": PASSWORD, "role": "ghost"}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "roles@example.com", "name": "Roles", "password": PASSWORD, "role": ["support", "user"]}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "meta@example.com", "name": "Meta", "data": {"image": "https://images.example/meta"}}),
            "admin",
        ),
        (
            "create-user",
            "/admin/create-user",
            json!({"email": "denied@example.com", "name": "Denied", "password": PASSWORD}),
            "support",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"password": "replacement"}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": admin_id, "data": {"banned": true}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"banned": true}}),
            "support",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"email": "new@example.com"}}),
            "support",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"email": "not an email"}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"email": "MATRIX-SUPPORT@example.com"}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"email": "Renamed@Example.com", "emailVerified": true, "name": "Renamed"}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": member_id, "data": {"banned": true, "banReason": "Manual"}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": "", "data": {"name": 1}}),
            "admin",
        ),
        (
            "update-user",
            "/admin/update-user",
            json!({"userId": 7, "data": []}),
            "admin",
        ),
        (
            "set-role",
            "/admin/set-role",
            json!({"userId": member_id, "role": 5}),
            "admin",
        ),
        (
            "set-role",
            "/admin/set-role",
            json!({"userId": member_id, "role": "ghost"}),
            "admin",
        ),
        (
            "set-role",
            "/admin/set-role",
            json!({"userId": member_id, "role": ["support", null]}),
            "admin",
        ),
        (
            "set-user-password",
            "/admin/set-user-password",
            json!({"userId": member_id, "newPassword": ""}),
            "admin",
        ),
        (
            "set-user-password",
            "/admin/set-user-password",
            json!({"userId": member_id, "newPassword": 5}),
            "admin",
        ),
        (
            "ban-user",
            "/admin/ban-user",
            json!({"userId": member_id, "banExpiresIn": "soon"}),
            "admin",
        ),
        (
            "ban-user",
            "/admin/ban-user",
            json!({"userId": member_id}),
            "admin",
        ),
        (
            "unban-user",
            "/admin/unban-user",
            json!({"userId": member_id}),
            "admin",
        ),
        (
            "has-permission",
            "/admin/has-permission",
            json!({"permission": {"user": ["ban"]}, "permissions": {"user": ["ban"]}}),
            "admin",
        ),
        (
            "has-permission",
            "/admin/has-permission",
            json!({}),
            "admin",
        ),
        (
            "has-permission",
            "/admin/has-permission",
            json!([1]),
            "admin",
        ),
        (
            "has-permission",
            "/admin/has-permission",
            json!({"permission": {"user": ["ban"]}}),
            "admin",
        ),
        (
            "has-permission",
            "/admin/has-permission",
            json!({"permissions": {"user": ["ban"]}, "role": "support"}),
            "support",
        ),
        (
            "remove-user",
            "/admin/remove-user",
            json!({"userId": admin_id}),
            "admin",
        ),
        (
            "revoke-user-sessions",
            "/admin/revoke-user-sessions",
            json!({"userId": member_id}),
            "admin",
        ),
        (
            "list-user-sessions",
            "/admin/list-user-sessions",
            json!({"userId": member_id}),
            "admin",
        ),
        (
            "impersonate-user",
            "/admin/impersonate-user",
            json!({"userId": member_id}),
            "anonymous",
        ),
        (
            "stop-impersonating",
            "/admin/stop-impersonating",
            json!({}),
            "admin",
        ),
    ];
    for (label, path, input, actor) in cases {
        let mut request = post(path, input);
        let cookie = match actor {
            "admin" => admin.as_str(),
            "support" => support.as_str(),
            _ => "",
        };
        _ = request.headers.insert("cookie".into(), cookie.into());
        trace.response(label, &Box::pin(auth.handle_request(request)).await?);
    }

    let get = |path: &str, query: &[(&str, &str)]| {
        let mut request = request(path, None, &admin);
        request.set_query_pairs(query.iter().copied());
        request
    };
    let queries: Vec<(&str, &str, Vec<(&str, &str)>)> = vec![
        ("get-user", "/admin/get-user", vec![]),
        (
            "get-user",
            "/admin/get-user",
            vec![("id", "a"), ("id", "b")],
        ),
        (
            "get-user",
            "/admin/get-user",
            vec![("id", member_id.as_str())],
        ),
        (
            "list-users",
            "/admin/list-users",
            vec![
                ("limit", "1"),
                ("limit", "2"),
                ("searchField", "phone"),
                ("sortDirection", "up"),
                ("filterOperator", "like"),
                ("searchValue", "a"),
                ("searchValue", "b"),
            ],
        ),
        (
            "list-users",
            "/admin/list-users",
            vec![
                ("searchValue", "nobody"),
                ("searchField", "email"),
                ("searchOperator", "contains"),
            ],
        ),
        (
            "list-users",
            "/admin/list-users",
            vec![
                ("filterField", "role"),
                ("filterValue", "support"),
                ("filterOperator", "in"),
                ("sortBy", "email"),
                ("sortDirection", "desc"),
                ("limit", "5"),
                ("offset", "0"),
            ],
        ),
        (
            "list-users",
            "/admin/list-users",
            vec![
                ("filterField", "banned"),
                ("filterValue", "true"),
                ("filterOperator", "eq"),
            ],
        ),
    ];
    for (label, path, query) in queries {
        trace.response(
            label,
            &Box::pin(auth.handle_request(get(path, &query))).await?,
        );
    }
    trace.assert("admin/route-matrix");
    B::close(connection).await
}

async fn admin_impersonation_and_bans<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(AdminPlugin::new().impersonation_session_duration(60.0))
        .build()
        .await?;
    let mut trace = Trace::default();
    let administrator = signup(&auth, "impersonator@example.com").await;
    let admin_id = promote(&auth, &administrator, "admin").await;
    let admin = cookies(&administrator);
    let member = signup(&auth, "impersonated@example.com").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&admin_id);
    trace.mask(&member_id);

    let impersonate = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id, "rememberMe": false})),
            &admin,
        ),
        200,
    )
    .await;
    trace.response("impersonate", &impersonate);
    let impersonating = cookies(&impersonate);
    trace.response(
        "impersonated session",
        &call(&auth, request("/get-session", None, &impersonating), 200).await,
    );
    trace.response(
        "stop",
        &Box::pin(auth.handle_request(request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &impersonating,
        )))
        .await?,
    );
    trace.response(
        "stop without impersonation",
        &Box::pin(auth.handle_request(request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &admin,
        )))
        .await?,
    );

    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId": member_id, "banExpiresIn": 3600, "banReason": "Spam"})),
            &admin,
        ),
        200,
    )
    .await;
    trace.response(
        "impersonate banned",
        &Box::pin(auth.handle_request(request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &admin,
        )))
        .await?,
    );
    trace.response(
        "banned sign in",
        &Box::pin(auth.handle_request(request(
            "/sign-in/email",
            Some(json!({"email": "impersonated@example.com", "password": PASSWORD})),
            "",
        )))
        .await?,
    );
    db.set_timestamp(
        "user",
        "banExpires",
        ("id", &member_id),
        chrono::Utc::now() - chrono::Duration::minutes(1),
    )
    .await?;
    trace.response(
        "expired ban sign in",
        &Box::pin(auth.handle_request(request(
            "/sign-in/email",
            Some(json!({"email": "impersonated@example.com", "password": PASSWORD})),
            "",
        )))
        .await?,
    );
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId": member_id, "banExpiresIn": 3600})),
            &admin,
        ),
        200,
    )
    .await;
    db.set_timestamp(
        "user",
        "banExpires",
        ("id", &member_id),
        chrono::Utc::now() - chrono::Duration::minutes(1),
    )
    .await?;
    trace.response(
        "impersonate expired ban",
        &Box::pin(auth.handle_request(request(
            "/admin/impersonate-user",
            Some(json!({"userId": member_id})),
            &admin,
        )))
        .await?,
    );
    trace.response(
        "remove self",
        &Box::pin(auth.handle_request(request(
            "/admin/remove-user",
            Some(json!({"userId": admin_id})),
            &admin,
        )))
        .await?,
    );
    trace.assert("admin/impersonation-and-bans");
    B::close(connection).await
}

// Compat owner: plugins/admin/ban-permission-create.test.ts.
async fn create_only_role_cannot_initialize_ban_properties<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut permissions = roles();
    _ = permissions.insert(
        "creator".into(),
        RolePermissions::new().allow("user", ["create"]),
    );
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(permissions))
        .build()
        .await?;
    let creator = signup(&auth, "creator@example.test").await;
    _ = promote(&auth, &creator, "creator").await;
    let cookie = cookies(&creator);
    let before = db.tables(&["user", "account", "session"]).await?;
    for data in [
        json!({"banned":false}),
        json!({"banReason":"reason"}),
        json!({"banExpires":"2100-01-01T00:00:00.000Z"}),
    ] {
        let denied = call(&auth, request("/admin/create-user", Some(json!({"email":"target@example.test","name":"Target","password":PASSWORD,"data":data})), &cookie), 403).await;
        assert_eq!(body(&denied)["code"], "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let created = call(
        &auth,
        request(
            "/admin/create-user",
            Some(json!({"email":"target@example.test","name":"Target","password":PASSWORD})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(db.count("user").await?, 2);
    assert_eq!(db.count("account").await?, 2);
    assert_eq!(db.count("session").await?, 1);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], body(&created)["user"]["id"]);
    B::close(connection).await
}

async fn update_only_role_cannot_mutate_any_ban_property<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let manager = signup(&auth, "manager@example.test").await;
    _ = promote(&auth, &manager, "support").await;
    let cookie = cookies(&manager);
    let owner = signup(&auth, "target@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for data in [
        json!({"banned":false,"name":"must-not-commit"}),
        json!({"banReason":"reason","name":"must-not-commit"}),
        json!({"banExpires":"2100-01-01T00:00:00.000Z","name":"must-not-commit"}),
    ] {
        let denied = call(
            &auth,
            request(
                "/admin/update-user",
                Some(json!({"userId":id,"data":data})),
                &cookie,
            ),
            403,
        )
        .await;
        assert_eq!(body(&denied)["code"], "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let accounts = db.table("account").await?;
    let sessions = db.table("session").await?;
    let accepted = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"name":"Allowed name"}})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["name"], "Allowed name");
    assert_eq!(
        db.text("SELECT \"name\" FROM \"user\" WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("Allowed name")
    );
    assert_eq!(db.table("account").await?, accounts);
    assert_eq!(db.table("session").await?, sessions);
    authenticated(&auth, &cookies(&owner), "target@example.test").await;
    B::close(connection).await
}

async fn update_only_role_cannot_change_email_verification<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let manager = signup(&auth, "manager@example.test").await;
    _ = promote(&auth, &manager, "support").await;
    let owner = signup(&auth, "target@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    let denied = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"emailVerified":true,"name":"must-not-commit"}})),
            &cookies(&manager),
        ),
        403,
    )
    .await;
    assert_eq!(
        body(&denied)["code"],
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL"
    );
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let accepted = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"name":"Allowed name"}})),
            &cookies(&manager),
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["name"], "Allowed name");
    assert_eq!(body(&accepted)["emailVerified"], false);
    authenticated(&auth, &cookies(&owner), "target@example.test").await;
    B::close(connection).await
}

async fn admin_password_bounds_preserve_credentials_until_valid_replacement<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let administrator = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &administrator, "admin").await;
    let owner = signup(&auth, "target@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for (length, code) in [(7, "PASSWORD_TOO_SHORT"), (129, "PASSWORD_TOO_LONG")] {
        let denied = call(
            &auth,
            request(
                "/admin/set-user-password",
                Some(json!({"userId":id,"newPassword":"x".repeat(length)})),
                &cookies(&administrator),
            ),
            400,
        )
        .await;
        assert_eq!(body(&denied)["code"], code);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    for password in [PASSWORD.to_owned(), "x".repeat(8), "x".repeat(128)] {
        if password != PASSWORD {
            let accepted = call(
                &auth,
                request(
                    "/admin/set-user-password",
                    Some(json!({"userId":id,"newPassword":password})),
                    &cookies(&administrator),
                ),
                200,
            )
            .await;
            assert_eq!(body(&accepted)["status"], true);
        }
        let login = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"target@example.test","password":password})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&login)["user"]["id"], id);
    }
    B::close(connection).await
}

async fn admin_email_replacement_moves_login_without_replacing_accounts_or_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let administrator = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &administrator, "admin").await;
    let owner = signup(&auth, "old@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let accounts = db.table("account").await?;
    let sessions = db.table("session").await?;
    let updated = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"email":"NEW@EXAMPLE.TEST","emailVerified":false}})),
            &cookies(&administrator),
        ),
        200,
    )
    .await;
    assert_eq!(body(&updated)["id"], id);
    assert_eq!(body(&updated)["email"], "new@example.test");
    assert_eq!(
        db.text("SELECT \"email\" FROM \"user\" WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("new@example.test")
    );
    assert_eq!(db.table("account").await?, accounts);
    assert_eq!(db.table("session").await?, sessions);
    let denied = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"old@example.test","password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INVALID_EMAIL_OR_PASSWORD");
    assert_eq!(db.table("session").await?, sessions);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"new@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(db.table("account").await?, accounts);
    authenticated(&auth, &cookies(&owner), "new@example.test").await;
    B::close(connection).await
}

async fn configured_role_validation_precedes_missing_target_lookup<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &admin, "admin").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    let denied = call(
        &auth,
        request(
            "/admin/set-role",
            Some(json!({"userId":"missing-target","role":"ghost"})),
            &cookies(&admin),
        ),
        400,
    )
    .await;
    assert_eq!(
        body(&denied)["code"],
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
    );
    let missing = call(
        &auth,
        request(
            "/admin/set-role",
            Some(json!({"userId":"missing-target","role":"user"})),
            &cookies(&admin),
        ),
        404,
    )
    .await;
    assert_eq!(body(&missing)["code"], "USER_NOT_FOUND");
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}

async fn admin_email_values_are_coerced_and_validated_before_any_update<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &admin, "admin").await;
    let owner = signup(&auth, "owner@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for email in [json!(null), json!(123), json!(false), json!([]), json!({})] {
        let denied = call(
            &auth,
            request(
                "/admin/update-user",
                Some(json!({"userId":id,"data":{"email":email,"name":"must-not-commit"}})),
                &cookies(&admin),
            ),
            400,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_EMAIL");
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let accepted = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"email":["REPLACEMENT@EXAMPLE.TEST"]}})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["email"], "replacement@example.test");
    assert_eq!(body(&accepted)["id"], id);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"replacement@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    B::close(connection).await
}

async fn demoted_admin_cannot_use_stale_cookie_cache_to_restore_grants<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthUser;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            strategy: alibi::CookieCacheStrategy::Compact,
            max_age: 300.0,
            version: None,
        });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            default_role: "admin".into(),
            ..Default::default()
        }))
        .build()
        .await?;
    let first = signup(&auth, "first@example.test").await;
    let second = signup(&auth, "second@example.test").await;
    let id = body(&first)["user"]["id"].as_str().unwrap().to_owned();
    let other_id = body(&second)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&first);
    assert!(cookie.contains("session_data"));
    _ = call(
        &auth,
        request(
            "/admin/set-role",
            Some(json!({"userId":id,"role":"user"})),
            &cookies(&second),
        ),
        200,
    )
    .await;
    let cached = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert_eq!(body(&cached)["user"]["role"], "admin");
    let before = db.tables(&["user", "account", "session"]).await?;
    for (path, input, code) in [
        (
            "/admin/set-role",
            json!({"userId":id,"role":"admin"}),
            "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
        ),
        (
            "/admin/impersonate-user",
            json!({"userId":other_id}),
            "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        ),
    ] {
        let denied = call(&auth, request(path, Some(input), &cookie), 403).await;
        assert_eq!(body(&denied)["code"], code);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let permission = call(
        &auth,
        request(
            "/admin/has-permission",
            Some(json!({"permissions":{"user":["set-role"]}})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&permission)["success"], false);
    assert_eq!(
        auth.store().get_user_by_id(&id).await?.unwrap().role(),
        Some("user")
    );
    authenticated(&auth, &cookies(&second), "second@example.test").await;
    B::close(connection).await
}

async fn explicit_empty_admin_roles_deny_builtin_grants_without_losing_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            roles: Some(HashMap::new()),
            default_role: "admin".into(),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    let mut get = request("/admin/get-user", None, &cookies(&owner));
    _ = get.query.insert("id".into(), id.clone());
    _ = call(&auth, get.clone(), 403).await;
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":id})),
            &cookies(&owner),
        ),
        403,
    )
    .await;
    let check = call(
        &auth,
        request(
            "/admin/has-permission",
            Some(json!({"permissions":{"user":["get"]},"role":"admin"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&check)["success"], false);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    let standard = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let allowed = call(&standard, get, 200).await;
    assert_eq!(body(&allowed)["id"], id);
    B::close(connection).await
}

async fn admin_role_tokens_with_whitespace_do_not_gain_privileges_or_admin_protection<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            default_role: "user, admin".into(),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let admin = signup(&auth, "admin@example.test").await;
    let admin_id = promote(&auth, &admin, "admin").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    let check = call(
        &auth,
        request(
            "/admin/has-permission",
            Some(json!({"permissions":{"user":["ban"]},"role":"admin","userId":admin_id})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&check)["success"], false);
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":admin_id})),
            &cookies(&owner),
        ),
        403,
    )
    .await;
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let impersonated = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId":owner_id})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert_eq!(body(&impersonated)["user"]["id"], owner_id);
    assert_eq!(body(&impersonated)["session"]["impersonatedBy"], admin_id);
    let stopped = call(
        &auth,
        request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &cookies(&impersonated),
        ),
        200,
    )
    .await;
    assert_eq!(body(&stopped)["user"]["id"], admin_id);
    B::close(connection).await
}

async fn blank_admin_role_falls_back_to_configured_user_permission<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let permissions =
        HashMap::from([("user".into(), RolePermissions::new().allow("user", ["get"]))]);
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            default_role: String::new(),
            roles: Some(permissions),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(body(&owner)["user"]["role"], "");
    let check = call(
        &auth,
        request(
            "/admin/has-permission",
            Some(json!({"permissions":{"user":["get"]}})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&check)["success"], true);
    let before = db.tables(&["user", "account", "session"]).await?;
    let mut get = request("/admin/get-user", None, &cookies(&owner));
    _ = get.query.insert("id".into(), id.clone());
    let visible = call(&auth, get, 200).await;
    assert_eq!(body(&visible)["id"], id);
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":id})),
            &cookies(&owner),
        ),
        403,
    )
    .await;
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}

async fn create_only_role_cannot_select_explicit_or_nested_roles<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut permissions = roles();
    _ = permissions.insert(
        "creator".into(),
        RolePermissions::new().allow("user", ["create"]),
    );
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::with_config(alibi::plugins::AdminConfig {
            default_role: "creator".into(),
            roles: Some(permissions),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "creator@example.test").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    for extra in [
        json!({"role":"support"}),
        json!({"role":""}),
        json!({"data":{"role":"support"}}),
        json!({"data":{"role":null}}),
        json!({"data":{"role":{"unexpected":"support"}}}),
        json!({"role":[],"data":{"role":"user"}}),
    ] {
        let mut input = json!({"email":"target@example.test","name":"Target","password":PASSWORD});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let denied = call(
            &auth,
            request("/admin/create-user", Some(input), &cookies(&owner)),
            403,
        )
        .await;
        assert_eq!(
            body(&denied)["code"],
            "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
        );
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let created = call(
        &auth,
        request(
            "/admin/create-user",
            Some(json!({"email":"target@example.test","name":"Target","password":PASSWORD})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&created)["user"]["role"], "creator");
    let after = db.tables(&["user", "account", "session"]).await?;
    let duplicate=call(&auth,request("/admin/create-user",Some(json!({"email":"target@example.test","name":"Target","password":PASSWORD,"data":{"role":"user"}})),&cookies(&owner)),403).await;
    assert_eq!(
        body(&duplicate)["code"],
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
    );
    assert_eq!(db.tables(&["user", "account", "session"]).await?, after);
    B::close(connection).await
}

async fn admin_password_field_rejects_accompanying_profile_mutations<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &admin, "admin").await;
    let target = signup(&auth, "target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    let denied=call(&auth,request("/admin/update-user",Some(json!({"userId":id,"data":{"password":"replacement-password-123","name":"must-not-commit"}})),&cookies(&admin)),400).await;
    assert_eq!(
        body(&denied)["code"],
        "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"
    );
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"target@example.test","password":"replacement-password-123"})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(body(&login)["user"]["name"], body(&target)["user"]["name"]);
    authenticated(&auth, &cookies(&target), "target@example.test").await;
    B::close(connection).await
}

async fn admin_colliding_email_rejects_accompanying_profile_mutations<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &admin, "admin").await;
    let left = signup(&auth, "left@example.test").await;
    let right = signup(&auth, "right@example.test").await;
    let id = body(&left)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for email in ["right@example.test", "RIGHT@EXAMPLE.TEST"] {
        let denied = call(
            &auth,
            request(
                "/admin/update-user",
                Some(json!({"userId":id,"data":{"email":email,"name":"must-not-commit"}})),
                &cookies(&admin),
            ),
            400,
        )
        .await;
        assert_eq!(
            body(&denied)["code"],
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
        );
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    for (email, owner) in [("left@example.test", &left), ("right@example.test", &right)] {
        let login = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&login)["user"]["id"], body(owner)["user"]["id"]);
        assert_eq!(body(&login)["user"]["name"], body(owner)["user"]["name"]);
        authenticated(&auth, &cookies(owner), email).await;
    }
    B::close(connection).await
}

async fn admin_update_ban_revokes_every_target_browser_and_preserves_foreign_sessions<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    _ = promote(&auth, &admin, "admin").await;
    let target = signup(&auth, "target@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let accounts = db.table("account").await?;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
            &[&id]
        )
        .await?,
        2
    );
    let updated = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"banned":true,"banReason":"Update route ban"}})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert_eq!(body(&updated)["id"], id);
    assert_eq!(body(&updated)["banned"], true);
    assert_eq!(body(&updated)["banReason"], "Update route ban");
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
            &[&id]
        )
        .await?,
        0
    );
    assert_eq!(db.count("session").await?, 2);
    assert_eq!(db.table("account").await?, accounts);
    for browser in [&target, &sibling] {
        let response = call(&auth, request("/get-session", None, &cookies(browser)), 200).await;
        assert!(body(&response).is_null());
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    authenticated(&auth, &cookies(&admin), "admin@example.test").await;
    B::close(connection).await
}

// Compat owner: tests/plugins/admin/self-ban-update.test.ts. The dedicated
// ban-user guard does not protect update-user or its accompanying profile writes.
async fn admin_self_ban_update_preserves_state_and_live_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "self-ban-admin@example.test").await;
    let id = promote(&auth, &admin, "admin").await;
    let cookie = cookies(&admin);
    let before = db.tables(&["user", "account", "session"]).await?;
    let mut read = request("/admin/get-user", None, &cookie);
    _ = read.query.insert("id".into(), id.clone());
    let visible_before = body(&call(&auth, read.clone(), 200).await);

    let denied = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({
                "userId": id,
                "data": {"banned": true, "banReason": "self", "name": "must-not-commit"}
            })),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "YOU_CANNOT_BAN_YOURSELF");
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    assert_eq!(body(&call(&auth, read, 200).await), visible_before);
    let session = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert_eq!(body(&session)["user"]["id"], id);
    assert_eq!(body(&session)["session"]["token"], body(&admin)["token"]);

    let accepted = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId": id, "data": {"name": "Still authorized"}})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["id"], id);
    assert_eq!(body(&accepted)["name"], "Still authorized");
    assert_eq!(
        db.text("SELECT \"name\" FROM \"user\" WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("Still authorized")
    );
    B::close(connection).await
}

async fn admin_empty_update_authority_order<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let administrator = signup(&auth, "empty-update-admin@example.test").await;
    _ = promote(&auth, &administrator, "admin").await;
    let target = signup(&auth, "empty-update-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for (cookie, status, code) in [
        (cookies(&target), 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS"),
        (cookies(&administrator), 400, "NO_DATA_TO_UPDATE"),
    ] {
        let response = call(
            &auth,
            request(
                "/admin/update-user",
                Some(json!({"userId":id,"data":{}})),
                &cookie,
            ),
            status,
        )
        .await;
        assert_eq!(body(&response)["code"], code);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let retry = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":id,"data":{"name":"Valid retry"}})),
            &cookies(&administrator),
        ),
        200,
    )
    .await;
    assert_eq!(body(&retry)["id"], id);
    assert_eq!(body(&retry)["name"], "Valid retry");
    assert_eq!(
        db.text("SELECT \"name\" FROM \"user\" WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("Valid retry")
    );
    authenticated(&auth, &cookies(&target), "empty-update-target@example.test").await;
    B::close(connection).await
}

async fn admin_literal_role_input_admission<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut configured = roles();
    _ = configured.insert(String::new(), RolePermissions::new());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(configured))
        .build()
        .await?;
    let administrator = signup(&auth, "literal-admin@example.test").await;
    _ = promote(&auth, &administrator, "admin").await;
    let target = signup(&auth, "literal-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    for role in [
        json!("admin,user"),
        json!(["admin,user"]),
        json!(" admin"),
        json!([" user"]),
    ] {
        for (path, input) in [
            ("/admin/set-role", json!({"userId":id,"role":role})),
            (
                "/admin/update-user",
                json!({"userId":id,"data":{"role":role,"name":"Must not commit"}}),
            ),
        ] {
            let response = call(
                &auth,
                request(path, Some(input), &cookies(&administrator)),
                400,
            )
            .await;
            assert_eq!(
                body(&response)["code"],
                "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
            );
            assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
        }
    }
    for (role, expected) in [
        (json!(["user", "admin"]), "user,admin"),
        (json!([]), ""),
        (json!(""), ""),
        (json!([""]), ""),
    ] {
        let response = call(
            &auth,
            request(
                "/admin/set-role",
                Some(json!({"userId":id,"role":role})),
                &cookies(&administrator),
            ),
            200,
        )
        .await;
        assert_eq!(body(&response)["user"]["role"], expected);
        assert_eq!(
            db.text("SELECT \"role\" FROM \"user\" WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some(expected)
        );
        assert_eq!(db.table("account").await?, before[1]);
        assert_eq!(db.table("session").await?, before[2]);
    }
    authenticated(
        &auth,
        &cookies(&administrator),
        "literal-admin@example.test",
    )
    .await;
    B::close(connection).await
}

async fn admin_create_role_selector_precedence<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut configured = roles();
    _ = configured.insert(String::new(), RolePermissions::new());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(configured).default_role("admin"))
        .build()
        .await?;
    let administrator = signup(&auth, "create-role-admin@example.test").await;
    _ = promote(&auth, &administrator, "admin").await;
    let initial = db.tables(&["user", "account", "session"]).await?;
    for (index, input) in [
        json!({"role":["user"],"data":{"role":"admin,user"}}),
        json!({"data":{"role":["user"]}}),
        json!({"role":"","data":{"role":["admin"]}}),
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("create-role-{index}@example.test");
        let mut input = input.as_object().unwrap().clone();
        input.extend([
            (String::from("email"), json!(email)),
            (String::from("name"), json!("Created owner")),
            (String::from("password"), json!(PASSWORD)),
        ]);
        let response = call(
            &auth,
            request(
                "/admin/create-user",
                Some(Value::Object(input)),
                &cookies(&administrator),
            ),
            200,
        )
        .await;
        let expected = if index == 2 { "" } else { "user" };
        assert_eq!(body(&response)["user"]["role"], expected);
        let id = body(&response)["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            db.text("SELECT \"role\" FROM \"user\" WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some(expected)
        );
        assert_eq!(db.count_where("SELECT COUNT(*) FROM \"account\" WHERE \"userId\"=$1 AND \"accountId\"=$1 AND \"providerId\"='credential'", &[&id]).await?, 1);
        let login = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&login)["user"]["id"], id);
        assert_eq!(body(&login)["user"]["role"], expected);
    }
    let before = db.tables(&["user", "account", "session"]).await?;
    for role in [Value::Null, json!({"unexpected":"admin"})] {
        let response = call(&auth, request("/admin/create-user", Some(json!({"email":"invalid-nested@example.test","name":"Invalid","data":{"role":role}})), &cookies(&administrator)), 400).await;
        assert_eq!(body(&response)["code"], "INVALID_ROLE_TYPE");
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let users: Vec<Value> = serde_json::from_str(&db.table("user").await?)?;
    assert!(
        serde_json::from_str::<Vec<Value>>(&initial[0])?
            .iter()
            .all(|row| users.contains(row))
    );
    authenticated(
        &auth,
        &cookies(&administrator),
        "create-role-admin@example.test",
    )
    .await;
    B::close(connection).await
}

async fn admin_array_filter_sql_operands<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let names = [
        "Array Owner",
        "Array Alpha",
        "Array Beta",
        "Array Alpha,Array Beta",
        "Array %_",
    ];
    let mut users = Vec::new();
    for (i, name) in names.iter().enumerate() {
        users.push(call(&auth,request("/sign-up/email",Some(json!({"email":format!("array-{i}@example.test"),"password":PASSWORD,"name":name})),""),200).await);
    }
    _ = promote(&auth, &users[0], "admin").await;
    let jar = cookies(&users[0]);
    let before = db.tables(&["user", "account", "session"]).await?;
    let make = |field: &str, operator: &str, values: Vec<String>, page: bool, cookie: &str| {
        let mut input = request("/admin/list-users", None, cookie);
        let mut query: Vec<(String, String)> = vec![
            ("sortBy".into(), "name".into()),
            ("sortDirection".into(), "asc".into()),
            ("filterField".into(), field.into()),
            ("filterOperator".into(), operator.into()),
        ];
        query.extend(values.into_iter().map(|v| ("filterValue".into(), v)));
        if page {
            query.extend([("limit".into(), "1".into()), ("offset".into(), "1".into())]);
        }
        input.set_query_pairs(query);
        input
    };
    for (op, values, expected, page) in [
        (
            "in",
            vec![names[1], names[2]],
            vec![names[1], names[2]],
            false,
        ),
        (
            "in",
            vec![names[2], names[1]],
            vec![names[1], names[2]],
            false,
        ),
        ("in", vec![names[1], names[1]], vec![names[1]], false),
        (
            "not_in",
            vec![names[1], names[2]],
            vec![names[4], names[3], names[0]],
            false,
        ),
        ("in", vec![names[1], names[2]], vec![names[2]], true),
    ] {
        let result = call(
            &auth,
            make(
                "name",
                op,
                values.into_iter().map(str::to_owned).collect(),
                page,
                &jar,
            ),
            200,
        )
        .await;
        assert_eq!(
            body(&result)["users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            body(&result)["total"],
            if page { 2 } else { expected.len() }
        );
        if page {
            assert_eq!(body(&result)["limit"], 1);
            assert_eq!(body(&result)["offset"], 1);
        }
    }
    for field in ["id", "email"] {
        let operands = [&users[2], &users[1]]
            .into_iter()
            .map(|r| body(r)["user"][field].as_str().unwrap().to_owned())
            .collect();
        let result = call(&auth, make(field, "in", operands, false, &jar), 200).await;
        assert_eq!(
            body(&result)["users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["id"].clone())
                .collect::<Vec<_>>(),
            [
                body(&users[1])["user"]["id"].clone(),
                body(&users[2])["user"]["id"].clone()
            ]
        );
    }
    for operator in ["contains", "starts_with", "ends_with"] {
        let result = call(
            &auth,
            make(
                "name",
                operator,
                vec!["array alpha".into(), "array beta".into()],
                false,
                &jar,
            ),
            200,
        )
        .await;
        assert_eq!(
            body(&result)["users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["name"].clone())
                .collect::<Vec<_>>(),
            [json!(names[3])]
        );
    }
    let wildcard = call(
        &auth,
        make(
            "name",
            "contains",
            vec!["%".into(), "Array Beta".into()],
            false,
            &jar,
        ),
        200,
    )
    .await;
    assert_eq!(
        body(&wildcard)["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["name"].clone())
            .collect::<Vec<_>>(),
        [json!(names[3])]
    );
    let boolean = call(
        &auth,
        make(
            "emailVerified",
            "in",
            vec!["0".into(), "0".into()],
            false,
            &jar,
        ),
        200,
    )
    .await;
    assert_eq!(body(&boolean)["total"], 5);
    for value in ["true", "false", "FALSE", "0"] {
        let result = call(
            &auth,
            make("emailVerified", "not_in", vec![value.into()], false, &jar),
            200,
        )
        .await;
        assert_eq!(body(&result)["total"], if value == "true" { 5 } else { 0 });
    }
    for operator in ["eq", "ne", "lt", "lte", "gt", "gte"] {
        let result = call(
            &auth,
            make(
                "name",
                operator,
                vec![names[1].into(), names[2].into()],
                true,
                &jar,
            ),
            200,
        )
        .await;
        assert_eq!(body(&result), json!({"users":[],"total":0}));
    }
    for (jar, status) in [(String::new(), 401), (cookies(&users[1]), 403)] {
        _ = call(
            &auth,
            make(
                "name",
                "in",
                vec![names[1].into(), names[2].into()],
                false,
                &jar,
            ),
            status,
        )
        .await;
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}

async fn admin_repeated_query_validation_before_auth<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let owner = signup(&auth, "repeat-owner@example.test").await;
    let regular = signup(&auth, "repeat-regular@example.test").await;
    _ = promote(&auth, &owner, "admin").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    for cookie in [String::new(), cookies(&regular), cookies(&owner)] {
        for (route, key, a, b, message) in [
            (
                "get-user",
                "id",
                body(&owner)["user"]["id"].as_str().unwrap(),
                body(&regular)["user"]["id"].as_str().unwrap(),
                "[query.id] Invalid input: expected string, received array",
            ),
            (
                "get-user",
                "id",
                "same",
                "same",
                "[query.id] Invalid input: expected string, received array",
            ),
            (
                "list-users",
                "searchValue",
                "A",
                "B",
                "[query.searchValue] Invalid input: expected string, received array",
            ),
            (
                "list-users",
                "searchField",
                "email",
                "name",
                "[query.searchField] Invalid option: expected one of \"email\"|\"name\"",
            ),
            (
                "list-users",
                "searchOperator",
                "contains",
                "starts_with",
                "[query.searchOperator] Invalid option: expected one of \"contains\"|\"starts_with\"|\"ends_with\"",
            ),
            (
                "list-users",
                "limit",
                "1",
                "2",
                "[query.limit] Invalid input",
            ),
            (
                "list-users",
                "offset",
                "0",
                "1",
                "[query.offset] Invalid input",
            ),
            (
                "list-users",
                "sortBy",
                "email",
                "name",
                "[query.sortBy] Invalid input: expected string, received array",
            ),
            (
                "list-users",
                "sortDirection",
                "asc",
                "desc",
                "[query.sortDirection] Invalid option: expected one of \"asc\"|\"desc\"",
            ),
            (
                "list-users",
                "filterField",
                "email",
                "name",
                "[query.filterField] Invalid input: expected string, received array",
            ),
            (
                "list-users",
                "filterOperator",
                "eq",
                "ne",
                "[query.filterOperator] Invalid option: expected one of \"eq\"|\"ne\"|\"lt\"|\"lte\"|\"gt\"|\"gte\"|\"in\"|\"not_in\"|\"contains\"|\"starts_with\"|\"ends_with\"",
            ),
        ] {
            let mut input = request(&format!("/admin/{route}"), None, &cookie);
            input.set_query_pairs([(key, a), (key, b)]);
            let denied = call(&auth, input, 400).await;
            assert_eq!(
                body(&denied),
                json!({"code":"VALIDATION_ERROR","message":message})
            );
            assert_eq!(
                denied.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert!(!denied.headers.contains_key("set-cookie"));
        }
    }
    let mut combined = request("/admin/list-users", None, "");
    combined.set_query_pairs([
        ("sortBy", "name"),
        ("sortBy", "email"),
        ("limit", "1"),
        ("limit", "2"),
        ("searchValue", "A"),
        ("searchValue", "B"),
    ]);
    let result = call(&auth, combined, 400).await;
    assert_eq!(
        body(&result),
        json!({"code":"VALIDATION_ERROR","message":"[query.searchValue] Invalid input: expected string, received array; [query.limit] Invalid input; [query.sortBy] Invalid input: expected string, received array"})
    );
    for (cookie, status) in [
        (String::new(), 401),
        (cookies(&regular), 403),
        (cookies(&owner), 200),
    ] {
        let mut input = request("/admin/get-user", None, &cookie);
        input.set_query_pairs([
            ("id", body(&regular)["user"]["id"].as_str().unwrap()),
            ("ignored", "first"),
            ("ignored", "second"),
        ]);
        let result = call(&auth, input, status).await;
        if status == 200 {
            assert_eq!(body(&result)["id"], body(&regular)["user"]["id"]);
        }
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}

// Compat owner: tests/plugins/admin/timestamp-precision.test.ts. Shared date
// serializer tests do not prove that admin read, mutation and list projections
// retain physical creation precision while exposing JavaScript milliseconds.
async fn admin_stored_timestamp_precision_survives_public_projections<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let admin = signup(&auth, "timestamp-admin@example.test").await;
    let admin_id = promote(&auth, &admin, "admin").await;
    let target_email = "timestamp-target@example.test";
    let target = signup(&auth, target_email).await;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let stable_authority = db.tables(&["account", "session"]).await?;
    let mut read = request("/admin/get-user", None, &cookies(&admin));
    _ = read.query.insert("id".into(), target_id.clone());
    let mut list = request("/admin/list-users", None, &cookies(&admin));
    list.set_query_pairs([
        ("searchField", "email"),
        ("searchOperator", "contains"),
        ("searchValue", target_email),
    ]);

    for fraction in ["145927", "145927123", "145000"] {
        let created_at = format!("2026-09-30T22:11:23.{fraction}Z");
        let updated_at = "2026-09-30T22:12:34.321456Z";
        assert_eq!(
            db.execute(
                "UPDATE \"user\" SET \"createdAt\"=$1, \"updatedAt\"=$2 WHERE id=$3",
                &[&created_at, updated_at, &target_id],
            )
            .await?,
            1
        );
        let physical_before = db.tables(&["user", "account", "session"]).await?;
        let user = body(&call(&auth, read.clone(), 200).await);
        assert_eq!(user["id"], target_id);
        assert_eq!(user["createdAt"], "2026-09-30T22:11:23.145Z");
        assert_eq!(user["updatedAt"], "2026-09-30T22:12:34.321Z");
        let denied = call(
            &auth,
            request(
                "/admin/set-role",
                Some(json!({"userId": admin_id, "role": "user"})),
                &cookies(&target),
            ),
            403,
        )
        .await;
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        assert_eq!(
            db.tables(&["user", "account", "session"]).await?,
            physical_before
        );

        let update = call(
            &auth,
            request(
                "/admin/set-role",
                Some(json!({"userId": target_id, "role": "user"})),
                &cookies(&admin),
            ),
            200,
        )
        .await;
        let updated_user = body(&update)["user"].clone();
        assert_eq!(updated_user["id"], target_id);
        assert_eq!(updated_user["role"], "user");
        assert_eq!(updated_user["createdAt"], "2026-09-30T22:11:23.145Z");
        let updated_wire = updated_user["updatedAt"].as_str().unwrap();
        assert_eq!(updated_wire.len(), 24);
        assert_eq!(updated_wire.as_bytes()[19], b'.');
        assert!(updated_wire.ends_with('Z'));
        let persisted = auth.store().get_user_by_id(&target_id).await?.unwrap();
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(updated_wire)?.timestamp_millis(),
            alibi::AuthUser::updated_at(&persisted).timestamp_millis()
        );
        let listed = body(&call(&auth, list.clone(), 200).await);
        assert_eq!(listed["users"].as_array().unwrap().len(), 1);
        assert_eq!(listed["users"][0], updated_user);
        let stored_created = db
            .text(
                "SELECT \"createdAt\" FROM \"user\" WHERE id=$1",
                &[&target_id],
            )
            .await?
            .unwrap();
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&stored_created)?,
            chrono::DateTime::parse_from_rfc3339(&created_at)?
        );
        assert_eq!(db.tables(&["account", "session"]).await?, stable_authority);
        for established in [&admin, &target] {
            let session = call(
                &auth,
                request("/get-session", None, &cookies(established)),
                200,
            )
            .await;
            assert_eq!(
                body(&session)["user"]["id"],
                body(established)["user"]["id"]
            );
            assert_eq!(
                body(&session)["session"]["token"],
                body(established)["token"]
            );
        }
        assert_eq!(db.tables(&["account", "session"]).await?, stable_authority);
    }
    B::close(connection).await
}

async fn admin_date_callback_error_identity<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use alibi::{AuthError, AuthResult, CreateSession};
    struct Hooks;
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Hooks {
        async fn before_update_user(
            &self,
            _: &str,
            u: &mut UpdateUser,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            if u.banned == Some(true) {
                return Err(AuthError::Api {
                    status: 403,
                    code: Some("APPLICATION_BAN_REFUSED".into()),
                    message: "Invalid Date".into(),
                });
            }
            Ok(HookControl::Continue)
        }
        async fn before_create_session(
            &self,
            s: &mut CreateSession,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            if s.impersonated_by.is_some() {
                return Err(AuthError::Api {
                    status: 500,
                    code: Some("APPLICATION_SESSION_REFUSED".into()),
                    message: "Invalid Date".into(),
                });
            }
            Ok(HookControl::Continue)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let owner = signup(&setup, "date-callback-admin@example.test").await;
    let target = signup(&setup, "date-callback-target@example.test").await;
    let foreign = signup(&setup, "date-callback-foreign@example.test").await;
    _ = promote(&setup, &owner, "admin").await;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(B::store(Arc::new(config), &connection), Hooks))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(roles()))
        .build()
        .await?;
    let before = db.tables(&["user", "account", "session"]).await?;
    for (route, data, status, code) in [
        (
            "/admin/ban-user",
            json!({"userId":body(&target)["user"]["id"],"banExpiresIn":300.5}),
            403,
            "APPLICATION_BAN_REFUSED",
        ),
        (
            "/admin/impersonate-user",
            json!({"userId":body(&target)["user"]["id"]}),
            500,
            "APPLICATION_SESSION_REFUSED",
        ),
    ] {
        let failed = call(&auth, request(route, Some(data), &cookies(&owner)), status).await;
        assert_eq!(body(&failed), json!({"code":code,"message":"Invalid Date"}));
        assert!(!failed.headers.contains_key("set-cookie"));
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    authenticated(&auth, &cookies(&owner), "date-callback-admin@example.test").await;
    authenticated(
        &auth,
        &cookies(&target),
        "date-callback-target@example.test",
    )
    .await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "date-callback-foreign@example.test",
    )
    .await;
    B::close(connection).await
}

async fn admin_impersonation_operator_metadata<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.advanced.ip_address.trusted_proxies = vec!["10.0.0.0/8".into()];
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let operator = signup(&auth, "operator@example.test").await;
    let operator_id = promote(&auth, &operator, "admin").await;
    let target = signup(&auth, "target@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let before = db.tables(&["user", "account", "session"]).await?;
    _ = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId":operator_id})),
            &cookies(&target),
        ),
        403,
    )
    .await;
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let mut input = request(
        "/admin/impersonate-user",
        Some(json!({"userId":target_id})),
        &cookies(&operator),
    );
    input.headers.extend([
        (
            "x-forwarded-for".into(),
            "203.0.113.99, 198.51.100.224, 10.2.3.4".into(),
        ),
        ("user-agent".into(), "admin-browser".into()),
    ]);
    let impersonated = call(&auth, input, 200).await;
    let jar = cookies(&impersonated);
    let current = body(&call(&auth, request("/get-session", None, &jar), 200).await);
    assert_eq!(current["user"]["id"], target_id);
    let token = current["session"]["token"].as_str().unwrap();
    assert_eq!(
        db.text(
            "SELECT \"userId\" FROM \"session\" WHERE \"token\"=$1",
            &[token]
        )
        .await?
        .as_deref(),
        Some(target_id.as_str())
    );
    assert_eq!(
        db.text(
            "SELECT \"impersonatedBy\" FROM \"session\" WHERE \"token\"=$1",
            &[token]
        )
        .await?
        .as_deref(),
        Some(operator_id.as_str())
    );
    assert_eq!(
        db.text(
            "SELECT \"ipAddress\" FROM \"session\" WHERE \"token\"=$1",
            &[token]
        )
        .await?
        .as_deref(),
        Some("198.51.100.224")
    );
    assert_eq!(
        db.text(
            "SELECT \"userAgent\" FROM \"session\" WHERE \"token\"=$1",
            &[token]
        )
        .await?
        .as_deref(),
        Some("admin-browser")
    );
    let after = db.tables(&["user", "account", "session"]).await?;
    for (before, now) in before.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|r| now.contains(r)));
    }
    let stopped = call(
        &auth,
        request("/admin/stop-impersonating", Some(json!({})), &jar),
        200,
    )
    .await;
    let restored = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&stopped)),
            200,
        )
        .await,
    );
    assert_eq!(restored["user"]["id"], operator_id);
    assert_eq!(restored["session"]["token"], body(&operator)["token"]);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    authenticated(&auth, &cookies(&target), "target@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

// Compat owner: admin/guest-wire.test.ts. Valid admin inputs must retain the
// bare unauthorized wire contract for absent, invalid and retired authority.
async fn admin_missing_tampered_and_revoked_sessions_reject_without_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "guest-wire-owner@example.test").await;
    let owner_id = promote(&auth, &owner, "admin").await;
    let target = signup(&auth, "guest-wire-target@example.test").await;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let target_token = body(&target)["token"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "guest-wire-foreign@example.test").await;
    let retired = signup(&auth, "guest-wire-retired@example.test").await;
    let retired_id = promote(&auth, &retired, "admin").await;
    let retired_cookie = cookies(&retired);
    let _ = call(
        &auth,
        request("/sign-out", Some(json!({})), &retired_cookie),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
            &[&retired_id]
        )
        .await?,
        0
    );
    let owner_cookie = cookies(&owner);
    let pair = owner_cookie
        .split("; ")
        .find(|pair| pair.starts_with("better-auth.session_token="))
        .unwrap();
    let (name, encoded) = pair.split_once('=').unwrap();
    let signed = url::form_urlencoded::parse(format!("v={encoded}").as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    let (token, signature) = signed.rsplit_once('.').unwrap();
    assert_eq!(token, body(&owner)["token"].as_str().unwrap());
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    let altered = format!("{token}.{replacement}{}", &signature[1..]);
    let tampered = format!(
        "{name}={}",
        url::form_urlencoded::byte_serialize(altered.as_bytes()).collect::<String>()
    );
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    let posts = [
        (
            "/admin/set-role",
            json!({"userId":target_id,"role":"admin"}),
        ),
        (
            "/admin/create-user",
            json!({"email":"guest-wire-denied-create@example.test","password":PASSWORD,"name":"Guest Creation"}),
        ),
        (
            "/admin/update-user",
            json!({"userId":target_id,"data":{"name":"Guest Mutation"}}),
        ),
        ("/admin/list-user-sessions", json!({"userId":target_id})),
        (
            "/admin/ban-user",
            json!({"userId":target_id,"banReason":"Guest Ban"}),
        ),
        ("/admin/unban-user", json!({"userId":target_id})),
        ("/admin/impersonate-user", json!({"userId":target_id})),
        ("/admin/stop-impersonating", json!({})),
        (
            "/admin/revoke-user-session",
            json!({"sessionToken":target_token}),
        ),
        ("/admin/revoke-user-sessions", json!({"userId":target_id})),
        ("/admin/remove-user", json!({"userId":target_id})),
        (
            "/admin/set-user-password",
            json!({"userId":target_id,"newPassword":"replacement-password-123"}),
        ),
        (
            "/admin/has-permission",
            json!({"permissions":{"user":["get"]},"userId":owner_id,"role":"admin"}),
        ),
    ];
    for cookie in ["", tampered.as_str(), retired_cookie.as_str()] {
        let mut requests: Vec<AuthRequest> = posts
            .iter()
            .map(|(path, value)| request(path, Some(value.clone()), cookie))
            .collect();
        for (path, query) in [
            ("/admin/get-user", vec![("id", target_id.as_str())]),
            ("/admin/list-users", vec![("limit", "10")]),
        ] {
            let mut get = request(path, None, cookie);
            get.set_query_pairs(query);
            requests.push(get);
        }
        for req in requests {
            let response = call(&auth, req, 401).await;
            assert!(response.body.is_empty());
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert!(cookies(&response).is_empty());
            assert_eq!(
                db.tables(&["user", "account", "session", "verification"])
                    .await?,
                before
            );
        }
    }
    let denied = body(
        &call(
            &auth,
            request(
                "/admin/ban-user",
                Some(json!({"userId":target_id})),
                &cookies(&foreign),
            ),
            403,
        )
        .await,
    );
    assert_eq!(denied["code"], "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS");
    assert_eq!(
        db.tables(&["user", "account", "session", "verification"])
            .await?,
        before
    );
    let mut get = request("/admin/get-user", None, &owner_cookie);
    get.set_query_pairs([("id", target_id.as_str())]);
    assert_eq!(body(&call(&auth, get, 200).await)["id"], target_id);
    authenticated(&auth, &owner_cookie, "guest-wire-owner@example.test").await;
    authenticated(&auth, &cookies(&target), "guest-wire-target@example.test").await;
    authenticated(&auth, &cookies(&foreign), "guest-wire-foreign@example.test").await;
    assert_eq!(
        db.tables(&["user", "account", "session", "verification"])
            .await?,
        before
    );
    B::close(connection).await
}
