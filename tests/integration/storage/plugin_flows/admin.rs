//! Admin authority comes from the acting session; target mutations stay scoped.
use super::*;
use better_auth::plugins::AdminPlugin;
use better_auth_core::{AuthUser, UpdateUser};

backend_tests!(admin_provisioning_permissions_passwords_and_session_moderation);
postgres_tests!(admin_provisioning_permissions_passwords_and_session_moderation);

async fn login<S: AuthSchema>(auth: &BetterAuth<S>, password: &str, status: u16) -> AuthResponse {
    call(
        auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"managed@example.test","password":password})),
            "",
        ),
        status,
    )
    .await
}

async fn admin_provisioning_permissions_passwords_and_session_moderation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let administrator = signup(&auth, "administrator@example.test").await;
    let admin_id = body(&administrator)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Initial administrator provisioning is an application operation. Every
    // subsequent grant and mutation below crosses the real admin route.
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
    let admin = cookies(&administrator);
    let foreign = signup(&auth, "foreign@example.test").await;
    let unprivileged = cookies(&foreign);
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    // Public profile updates must never grant administrative authority.
    for role in [json!("admin"), json!(["admin"]), json!({"role":"admin"})] {
        let denied = call(
            &auth,
            request(
                "/update-user",
                Some(json!({"name":"Updated profile","role":role})),
                &unprivileged,
            ),
            400,
        )
        .await;
        assert_eq!(body(&denied)["code"], "FIELD_NOT_ALLOWED");
        let stored = auth.store().get_user_by_id(&foreign_id).await?.unwrap();
        assert_eq!(stored.name(), body(&foreign)["user"]["name"].as_str());
        assert_eq!(
            stored.role(),
            Some("user"),
            "profile input must not change role"
        );
    }
    let _ = call(
        &auth,
        request("/update-user", Some(json!({"role":"admin"})), &unprivileged),
        400,
    )
    .await;
    let created = call(&auth, request("/admin/create-user", Some(json!({"email":"managed@example.test","name":"Managed","password":PASSWORD,"role":"user"})), &admin), 200).await;
    let target = body(&created)["user"]["id"].as_str().unwrap().to_owned();
    let first = login(&auth, PASSWORD, 200).await;
    let second = login(&auth, PASSWORD, 200).await;
    let first_token = body(&first)["token"].as_str().unwrap().to_owned();
    let second_token = body(&second)["token"].as_str().unwrap().to_owned();
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let _ = call(
        &auth,
        request("/admin/list-users", None, &unprivileged),
        403,
    )
    .await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    // Valid operation inputs make each rejection reach the permission guard.
    for (path, input) in [
        (
            "/admin/create-user",
            json!({"email":"forged@example.test","name":"Forged","password":PASSWORD}),
        ),
        ("/admin/set-role", json!({"userId":target,"role":"admin"})),
        (
            "/admin/update-user",
            json!({"userId":target,"data":{"name":"Forged"}}),
        ),
        (
            "/admin/ban-user",
            json!({"userId":target,"banReason":"Forged"}),
        ),
        ("/admin/unban-user", json!({"userId":target})),
        (
            "/admin/set-user-password",
            json!({"userId":target,"newPassword":"forged-password-123"}),
        ),
        ("/admin/list-user-sessions", json!({"userId":target})),
        (
            "/admin/revoke-user-session",
            json!({"sessionToken":first_token}),
        ),
        ("/admin/revoke-user-sessions", json!({"userId":target})),
    ] {
        let denied = call(&auth, request(path, Some(input), &unprivileged), 403).await;
        assert!(
            denied.headers.get_all("set-cookie").next().is_none(),
            "{path}"
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            before,
            "{path}"
        );
    }
    let mut get = request("/admin/get-user", None, &unprivileged);
    drop(get.query.insert("id".into(), target.clone()));
    let _ = call(&auth, get.clone(), 403).await;
    drop(get.headers.insert("cookie".into(), admin.clone()));
    let read = call(&auth, get, 200).await;
    assert_eq!(body(&read)["id"], target);
    assert_eq!(body(&read)["email"], "managed@example.test");
    assert!(body(&read).get("password").is_none());
    for (cookie, expected) in [(&admin, true), (&unprivileged, false)] {
        let permissions = call(
            &auth,
            request(
                "/admin/has-permission",
                Some(json!({"userId":admin_id,"role":"admin","permissions":{"user":["set-role"]}})),
                cookie,
            ),
            200,
        )
        .await;
        assert_eq!(
            body(&permissions)["success"],
            expected,
            "supplied userId/role must not replace session authority"
        );
    }
    let renamed = call(
        &auth,
        request(
            "/admin/update-user",
            Some(json!({"userId":target,"data":{"name":"Renamed"}})),
            &admin,
        ),
        200,
    )
    .await;
    assert_eq!(body(&renamed)["name"], "Renamed");
    assert_eq!(
        db.text("SELECT name FROM users WHERE id = $1", &[&target])
            .await?
            .as_deref(),
        Some("Renamed")
    );
    for role in ["admin", "user"] {
        let changed = call(
            &auth,
            request(
                "/admin/set-role",
                Some(json!({"userId":target,"role":role})),
                &admin,
            ),
            200,
        )
        .await;
        assert_eq!(body(&changed)["user"]["role"], role);
        assert_eq!(
            db.text("SELECT role FROM users WHERE id = $1", &[&target])
                .await?
                .as_deref(),
            Some(role)
        );
    }
    let listed = call(
        &auth,
        request(
            "/admin/list-user-sessions",
            Some(json!({"userId":target})),
            &admin,
        ),
        200,
    )
    .await;
    let listed_body = body(&listed);
    let sessions = listed_body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().all(|session| session["userId"] == target));
    assert!(
        sessions
            .iter()
            .any(|session| session["token"] == first_token)
    );
    let _ = call(
        &auth,
        request(
            "/admin/revoke-user-session",
            Some(json!({"sessionToken":first_token})),
            &admin,
        ),
        200,
    )
    .await;
    assert!(auth.store().get_session(&first_token).await?.is_none());
    assert!(auth.store().get_session(&second_token).await?.is_some());
    let _ = call(
        &auth,
        request(
            "/admin/revoke-user-sessions",
            Some(json!({"userId":target})),
            &admin,
        ),
        200,
    )
    .await;
    assert!(auth.store().get_user_sessions(&target).await?.is_empty());
    authenticated(&auth, &unprivileged, "foreign@example.test").await;

    let replacement = "replacement-password-123";
    let _ = call(
        &auth,
        request(
            "/admin/set-user-password",
            Some(json!({"userId":target,"newPassword":replacement})),
            &admin,
        ),
        200,
    )
    .await;
    let _ = login(&auth, PASSWORD, 401).await;
    let new_session = login(&auth, replacement, 200).await;
    authenticated(&auth, &cookies(&new_session), "managed@example.test").await;
    let _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":target,"banReason":"review","banExpiresIn":3600})),
            &admin,
        ),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id = $1 AND banned = true AND ban_reason = 'review'",
            &[&target]
        )
        .await?,
        1
    );
    assert!(auth.store().get_user_sessions(&target).await?.is_empty());
    let banned = login(&auth, replacement, 403).await;
    assert_eq!(body(&banned)["code"], "BANNED_USER");
    let _ = call(
        &auth,
        request("/admin/unban-user", Some(json!({"userId":target})), &admin),
        200,
    )
    .await;
    assert_eq!(db.count_where("SELECT COUNT(*) FROM users WHERE id = $1 AND banned = false AND ban_reason IS NULL AND ban_expires IS NULL", &[&target]).await?, 1);
    let _ = login(&auth, replacement, 200).await;

    let impersonated = call(
        &auth,
        request(
            "/admin/impersonate-user",
            Some(json!({"userId":target})),
            &admin,
        ),
        200,
    )
    .await;
    assert_eq!(body(&impersonated)["session"]["impersonatedBy"], admin_id);
    let impersonated_token = body(&impersonated)["session"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let restored = call(
        &auth,
        request(
            "/admin/stop-impersonating",
            Some(json!({})),
            &cookies(&impersonated),
        ),
        200,
    )
    .await;
    assert_eq!(
        body(&restored)["session"]["token"],
        body(&administrator)["token"]
    );
    assert!(
        auth.store()
            .get_session(&impersonated_token)
            .await?
            .is_none()
    );
    authenticated(&auth, &cookies(&restored), "administrator@example.test").await;
    authenticated(&auth, &unprivileged, "foreign@example.test").await;
    B::close(connection).await
}
