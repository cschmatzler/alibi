use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn token_signs_the_single_normally_refreshed_snapshot_and_honors_suppression() {
    for (case, deferred, disabled, query, preference, should_refresh) in [
        ("normal", false, false, None, None, true),
        ("empty-query", false, false, Some(""), None, true),
        ("false-query", false, false, Some("false"), None, false),
        (
            "remember-preference",
            false,
            false,
            None,
            Some("true"),
            false,
        ),
        ("empty-preference", false, false, None, Some(""), true),
        ("disabled", false, true, None, None, false),
        ("deferred", true, false, None, None, false),
        ("deferred-empty-query", true, false, Some(""), None, false),
        (
            "deferred-false-query",
            true,
            false,
            Some("false"),
            None,
            false,
        ),
        (
            "deferred-preference",
            true,
            false,
            None,
            Some("true"),
            false,
        ),
        ("deferred-disabled", true, true, None, None, false),
    ] {
        let (auth, db, jwt, observed) = fixture(deferred, disabled).await;
        let (user_id, token, mut cookie) =
            issued(&auth, &format!("{case}@jwt-session.fixture.test")).await;
        let before = age(&auth, &db, &token, false).await;
        if let Some(value) = preference {
            cookie.push_str("; better-auth.dont_remember=");
            cookie.push_str(&better_auth_core::utils::cookie_utils::sign_cookie_value(
                value,
                &auth.config().secret,
            ));
        }
        let mut req = request("/token", &cookie);
        if let Some(query) = query {
            drop(req.query.insert("disableRefresh".into(), query.into()));
        }
        let response = auth.handle_request(req).await.unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, 200, "{case}: {body}");
        let claims = verified(
            &jwt,
            &auth,
            (*(body).get("token").unwrap_or(&Value::Null))
                .as_str()
                .unwrap(),
        )
        .await;
        let stored = auth.store().get_session(&token).await.unwrap().unwrap();
        assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), user_id);
        assert_eq!(
            (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("user")
                .unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
            user_id
        );
        assert_eq!(
            (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null)),
            json!(auth.context().session_view(&stored)),
            "{case}"
        );
        assert_eq!(
            stored.id().as_ref(),
            (*(before).get("id").unwrap_or(&Value::Null))
                .as_str()
                .unwrap()
        );
        assert_eq!(stored.token(), token);
        assert_eq!(stored.user_id().as_ref(), user_id);
        if deferred && query.is_none_or(str::is_empty) && preference != Some("true") {
            assert_eq!(
                (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("needsRefresh")
                    .unwrap_or(&Value::Null)),
                !disabled,
                "{case}"
            );
        } else {
            assert!(
                (*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("needsRefresh")
                    .is_none(),
                "{case}"
            );
        }
        assert_eq!(
            observed.0.lock().unwrap().len(),
            1,
            "{case}: one payload callback"
        );
        assert_eq!(
            *observed.0.lock().unwrap(),
            *observed.1.lock().unwrap(),
            "{case}: payload and subject callbacks receive the same authenticated snapshot"
        );
        assert_eq!(
            writes(&db).await,
            i64::from(should_refresh),
            "{case}: one refresh write"
        );
        assert_eq!(
            response.headers.get_all("set-cookie").count(),
            usize::from(should_refresh),
            "{case}"
        );
        if should_refresh {
            assert!(stored.expires_at() > Utc::now() + Duration::days(6));
            assert!(
                response
                    .headers
                    .get_all("set-cookie")
                    .next()
                    .unwrap()
                    .contains("Max-Age=604800")
            );
        } else {
            assert_eq!(
                json!(auth.context().session_view(&stored)),
                before,
                "{case}: no state changes"
            );
        }
    }
}

#[tokio::test]
async fn session_jwt_header_uses_the_original_snapshot_and_exact_exposed_header_set() {
    for deferred in [false, true] {
        let (auth, db, jwt, observed) = fixture(deferred, false).await;
        let (user_id, token, cookie) = issued(&auth, "header@jwt-session.fixture.test").await;
        let before = age(&auth, &db, &token, false).await;
        let mut suppressed = request("/get-session", &cookie);
        drop(
            suppressed
                .query
                .insert("disableRefresh".into(), "false".into()),
        );
        let response = auth.handle_request(suppressed).await.unwrap();
        let claims = verified(&jwt, &auth, response.headers.get("set-auth-jwt").unwrap()).await;
        assert_eq!(
            (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("expiresAt")
            .unwrap_or(&Value::Null)),
            (*(before).get("expiresAt").unwrap_or(&Value::Null))
        );
        assert_eq!(
            response
                .headers
                .get("access-control-expose-headers")
                .unwrap(),
            "existing, set-auth-jwt, Existing"
        );
        assert_eq!(writes(&db).await, 0);
        observed.0.lock().unwrap().clear();
        let response_2 = auth
            .handle_request(request("/get-session", &cookie))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response_2.body).unwrap();
        assert_eq!(response_2.status, 200, "{body}");
        let claims_2 = verified(&jwt, &auth, response_2.headers.get("set-auth-jwt").unwrap()).await;
        assert_eq!((*(claims_2).get("sub").unwrap_or(&Value::Null)), user_id);
        assert_eq!(
            (*(*(*(claims_2).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("expiresAt")
            .unwrap_or(&Value::Null)),
            (*(before).get("expiresAt").unwrap_or(&Value::Null))
        );
        assert_eq!(
            (*(*(body).get("session").unwrap_or(&Value::Null))
                .get("token")
                .unwrap_or(&Value::Null)),
            token
        );
        let stored = auth.store().get_session(&token).await.unwrap().unwrap();
        assert_eq!(
            (*(body).get("session").unwrap_or(&Value::Null)),
            json!(auth.context().session_view(&stored))
        );
        assert_eq!(
            response_2
                .headers
                .get("access-control-expose-headers")
                .unwrap(),
            "existing, set-auth-jwt, Existing"
        );
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        assert_eq!(writes(&db).await, i64::from(!deferred));
        observed.0.lock().unwrap().clear();
        let expired = age(&auth, &db, &token, true).await;
        let response_3 = auth
            .handle_request(request("/get-session", &cookie))
            .await
            .unwrap();
        let body_2: Value = serde_json::from_slice(&response_3.body).unwrap();
        assert_eq!(response_3.status, 200);
        assert_eq!(body_2, Value::Null);
        let claims_3 = verified(&jwt, &auth, response_3.headers.get("set-auth-jwt").unwrap()).await;
        assert_eq!(
            (*(*(*(claims_3).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("expiresAt")
            .unwrap_or(&Value::Null)),
            (*(expired)
                .get("expiresAt")
                .expect("fixture contains the requested index"))
        );
        assert_eq!((*(claims_3).get("sub").unwrap_or(&Value::Null)), user_id);
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        assert_eq!(response_3.headers.get_all("set-cookie").count(), 3);
        assert_eq!(
            auth.store().get_session(&token).await.unwrap().is_some(),
            deferred
        );
        // The endpoint's normal middleware still rejects the same expired proof.
        let response_4 = auth
            .handle_request(request("/token", &cookie))
            .await
            .unwrap();
        assert_eq!(response_4.status, 401);
        assert_eq!(observed.0.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn api_key_virtual_owner_overrides_another_cookie_without_creating_a_session() {
    let (auth, db, jwt, observed) = fixture(false, false).await;
    let (key_owner, owner_token, owner_cookie) =
        issued(&auth, "key-owner@jwt-session.fixture.test").await;
    let (cookie_owner, cookie_token, cookie) =
        issued(&auth, "cookie-owner@jwt-session.fixture.test").await;
    let mut create = request("/api-key/create", &owner_cookie);
    create.method = HttpMethod::Post;
    drop(
        create
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    create.body = Some(serde_json::to_vec(&json!({"name":"JWT virtual principal"})).unwrap());
    let created = auth.handle_request(create).await.unwrap();
    assert_eq!(created.status, 200);
    let created: Value = serde_json::from_slice(&created.body).unwrap();
    let raw_key = (*(created).get("key").unwrap_or(&Value::Null))
        .as_str()
        .unwrap();
    let before = auth.store().get_user_sessions(&key_owner).await.unwrap();
    let foreign_before = age(&auth, &db, &cookie_token, false).await;
    let mut req = request("/token", &cookie);
    drop(req.headers.insert("x-api-key".into(), raw_key.into()));
    let response = auth.handle_request(req).await.unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.status, 200, "{body}");
    let claims = verified(
        &jwt,
        &auth,
        (*(body).get("token").unwrap_or(&Value::Null))
            .as_str()
            .unwrap(),
    )
    .await;
    assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), key_owner);
    assert_ne!((*(claims).get("sub").unwrap_or(&Value::Null)), cookie_owner);
    assert_eq!(
        (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
            .get("session")
            .unwrap_or(&Value::Null))
        .get("id")
        .unwrap_or(&Value::Null)),
        (*(created).get("id").unwrap_or(&Value::Null))
    );
    assert_eq!(
        (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
            .get("session")
            .unwrap_or(&Value::Null))
        .get("token")
        .unwrap_or(&Value::Null)),
        raw_key
    );
    assert_eq!(
        (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
            .get("session")
            .unwrap_or(&Value::Null))
        .get("userId")
        .unwrap_or(&Value::Null)),
        key_owner
    );
    assert_eq!(
        serde_json::to_value(auth.store().get_user_sessions(&key_owner).await.unwrap()).unwrap(),
        json!(before)
    );
    assert_eq!(
        json!(
            auth.context().session_view(
                &auth
                    .store()
                    .get_session(&cookie_token)
                    .await
                    .unwrap()
                    .unwrap()
            )
        ),
        foreign_before
    );
    assert_eq!(response.headers.get_all("set-cookie").count(), 0);
    assert_eq!(writes(&db).await, 0);
    assert_eq!(observed.0.lock().unwrap().len(), 1);
    let mut req_2 = request("/get-session", "");
    drop(req_2.headers.insert("x-api-key".into(), raw_key.into()));
    let response_2 = auth.handle_request(req_2).await.unwrap();
    let body_2: Value = serde_json::from_slice(&response_2.body).unwrap();
    assert_eq!(
        (*(*(body_2).get("user").unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
        key_owner
    );
    assert_eq!(
        (*(*(body_2).get("session").unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
        (*(created).get("id").unwrap_or(&Value::Null))
    );
    assert!(response_2.headers.get("set-auth-jwt").is_none());
    assert!(
        response_2
            .headers
            .get("access-control-expose-headers")
            .is_none()
    );
    assert_eq!(observed.0.lock().unwrap().len(), 1);
    let mut bad = request("/token", &cookie);
    drop(bad.headers.insert(
        "x-api-key".into(),
        "invalid-api-key-proof-with-adequate-length".into(),
    ));
    let rejected = auth.handle_request(bad).await.unwrap();
    assert_eq!(rejected.status, 403);
    assert_eq!(observed.0.lock().unwrap().len(), 1);
    assert_eq!(
        auth.store()
            .get_user_sessions(&key_owner)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        auth.store()
            .get_session(&owner_token)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn failed_refresh_retains_the_direct_hook_snapshot_but_never_authorizes_token_issuance() {
    for (action, status, cookie_count) in [
        ("IGNORE", 401, 3),
        ("ABORT, 'fixture refresh failure'", 500, 0),
    ] {
        let (auth, db, jwt, observed) = fixture(false, false).await;
        let (user_id, token, cookie) =
            issued(&auth, "failed-refresh@jwt-session.fixture.test").await;
        let before = age(&auth, &db, &token, false).await;
        _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
            format!("CREATE TRIGGER reject_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN SELECT RAISE({action}); END")))
            .await.unwrap();
        let response = auth
            .handle_request(request("/get-session", &cookie))
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, status, "{action}: {error}");
        assert_eq!(
            (*(error).get("code").unwrap_or(&Value::Null)),
            "FAILED_TO_GET_SESSION"
        );
        let claims = verified(&jwt, &auth, response.headers.get("set-auth-jwt").unwrap()).await;
        assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), user_id);
        assert_eq!(
            (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null)),
            before
        );
        assert_eq!(response.headers.get_all("set-cookie").count(), cookie_count);
        assert_eq!(writes(&db).await, 0);
        assert_eq!(
            json!(
                auth.context()
                    .session_view(&auth.store().get_session(&token).await.unwrap().unwrap())
            ),
            before
        );
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        let response_2 = auth
            .handle_request(request("/token", &cookie))
            .await
            .unwrap();
        let error_2: Value = serde_json::from_slice(&response_2.body).unwrap();
        assert_eq!(response_2.status, 401);
        assert_eq!(
            error_2,
            json!({"code":"UNAUTHORIZED","message":"Unauthorized"})
        );
        assert!(response_2.headers.get("set-auth-jwt").is_none());
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        assert_eq!(writes(&db).await, 0);
    }
}

#[tokio::test]
async fn caller_supplied_hook_snapshot_cannot_set_a_jwt_or_authorize_the_token_endpoint() {
    let (auth, db, _, observed) = fixture(false, false).await;
    let (user_id, token, _) = issued(&auth, "forged-context@jwt-session.fixture.test").await;
    let before = age(&auth, &db, &token, false).await;
    let user = auth
        .store()
        .get_user_by_id(&user_id)
        .await
        .unwrap()
        .unwrap();
    let session = auth.store().get_session(&token).await.unwrap().unwrap();
    for path in ["/get-session", "/token"] {
        let req = request(path, "");
        req.set_session_hook_snapshot(
            auth.context().user_view(&user),
            auth.context().session_view(&session),
        );
        let response = auth.handle_request(req).await.unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        if path == "/get-session" {
            assert_eq!(response.status, 200);
            assert_eq!(body, Value::Null);
        } else {
            assert_eq!(response.status, 401);
            assert_eq!(
                body,
                json!({"code":"UNAUTHORIZED","message":"Unauthorized"})
            );
        }
        assert!(response.headers.get("set-auth-jwt").is_none());
        assert_eq!(observed.0.lock().unwrap().len(), 0);
        assert_eq!(writes(&db).await, 0);
        assert!(auth.store().list_jwks().await.unwrap().is_empty());
        assert_eq!(
            json!(
                auth.context()
                    .session_view(&auth.store().get_session(&token).await.unwrap().unwrap())
            ),
            before
        );
    }
}
