//! Admin route input validation, role authority and moderation outcomes.
use super::*;
use crate::snapshot::Trace;
use alibi::UpdateUser;
use alibi::plugins::{AdminPlugin, RolePermissions};
use std::collections::HashMap;

backend_tests!(
    admin_route_matrix,
    admin_impersonation_and_bans,
    blank_admin_role_falls_back_to_configured_user_permission
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
        "users",
        "ban_expires",
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
        "users",
        "ban_expires",
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
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
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
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    B::close(connection).await
}
