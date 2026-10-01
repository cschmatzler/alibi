use super::*;
use std::io::Write;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn production_exchange_preserves_rows_then_preview_consumes_state_and_issues_only_the_actual_owner()
 {
    let fixture = Fixture::new().await;
    let foreign = request(
        &fixture.preview,
        "/api/auth/sign-up/email",
        Some(
            json!({"email":"foreign-proxy@fixture.test","name":"Foreign","password":"password123"}),
        ),
        None,
    )
    .await;
    assert_eq!(foreign.status, 200);
    let foreign_body: Value = serde_json::from_slice(&foreign.body).unwrap();
    let foreign_id = foreign_body
        .get("user")
        .unwrap()
        .get("id")
        .unwrap()
        .as_str()
        .unwrap();
    let before = rows(&fixture.preview_db).await;
    let prod_before = rows(&fixture.production_db).await;
    let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
    let original_state = state
        .get("oauthState")
        .expect("provider fixture contains this parameter")
        .as_str()
        .unwrap();
    let issued = rows(&fixture.preview_db).await;
    let (_, bridge) = fixture.forward(&authorization).await;
    assert_eq!(rows(&fixture.production_db).await, prod_before);
    assert_eq!(rows(&fixture.preview_db).await, issued);
    let completed = request(&fixture.preview, &target(&bridge), None, None).await;
    assert_eq!(completed.status, 302);
    assert_eq!(
        location(&completed).as_str(),
        &format!("{PREVIEW}/new-owner")
    );
    assert!(
        fixture
            .preview
            .store()
            .get_verification_by_identifier(&format!("oauth:{original_state}"))
            .await
            .unwrap()
            .is_none()
    );
    let owner = fixture
        .preview
        .store()
        .get_user_by_email("proxy-owner@fixture.test")
        .await
        .unwrap()
        .unwrap();
    let sessions = fixture
        .preview
        .store()
        .get_user_sessions(&owner.id())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    let current = request(
        &fixture.preview,
        "/api/auth/get-session",
        None,
        Some(&cookies(&completed)),
    )
    .await;
    let current: Value = serde_json::from_slice(&current.body).unwrap();
    assert_eq!(
        current
            .get("user")
            .expect("provider fixture contains this parameter")
            .get("id")
            .expect("provider fixture contains this parameter"),
        owner.id().as_ref()
    );
    assert_eq!(
        current
            .get("session")
            .expect("provider fixture contains this parameter")
            .get("token")
            .expect("provider fixture contains this parameter"),
        sessions.first().unwrap().token()
    );
    assert_eq!(
        fixture
            .preview
            .store()
            .get_user_sessions(foreign_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let accounts = fixture
        .preview
        .store()
        .get_user_accounts(&owner.id())
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    let after = rows(&fixture.preview_db).await;
    let replay = request(&fixture.preview, &target(&bridge), None, None).await;
    assert!(location(&replay).as_str().contains("error=state_mismatch"));
    assert_eq!(rows(&fixture.preview_db).await, after);
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    let mut callback = url::Url::parse(
        query
            .get("redirect_uri")
            .expect("provider fixture contains this parameter"),
    )
    .unwrap();
    _ = callback
        .query_pairs_mut()
        .append_pair(
            "state",
            query
                .get("state")
                .expect("provider fixture contains this parameter"),
        )
        .append_pair("code", "real-code-1");
    let retry = request(&fixture.production, &target(&callback), None, None).await;
    assert!(location(&retry).as_str().contains("error=invalid_code"));
    assert_eq!(rows(&fixture.preview_db).await, after);
    assert_eq!(rows(&fixture.production_db).await, prod_before);
    writeln!(std::io::stderr(),
        "PROXY_NATIVE_LIFECYCLE {}",
        json!({"before":before,"issued":issued,"authorization":authorization.as_str(),"bridge":bridge.as_str(),"completed":{"status":completed.status,"headers":completed.headers.iter().collect::<Vec<_>>()},"current":current,"after":after,"production":prod_before,"receipts":fixture.provider.lock().unwrap().receipts})
    ).expect("write native lifecycle observation");
}

#[tokio::test]
async fn completion_rejects_foreign_origin_provider_tampering_and_expired_state_before_any_principal_write()
 {
    let fixture = Fixture::new().await;
    let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let issued = rows(&fixture.preview_db).await;
    let mut foreign = bridge.clone();
    let profile = foreign
        .query_pairs()
        .find(|(key, _)| key == "profile")
        .unwrap()
        .1
        .into_owned();
    foreign.set_query(None);
    _ = foreign
        .query_pairs_mut()
        .append_pair("callbackURL", "https://foreign.fixture.test/leak")
        .append_pair("profile", &profile);
    let denied = request(&fixture.preview, &target(&foreign), None, None).await;
    assert_eq!(denied.status, 403);
    assert_eq!(rows(&fixture.preview_db).await, issued);
    let mut provider = bridge.clone();
    provider.set_path("/api/auth/callback/google/oauth-proxy");
    let denied_2 = request(&fixture.preview, &target(&provider), None, None).await;
    assert!(
        location(&denied_2)
            .as_str()
            .contains("error=provider_mismatch")
    );
    assert_eq!(rows(&fixture.preview_db).await, issued);
    let mut invalid = bridge.clone();
    invalid.set_query(None);
    _ = invalid
        .query_pairs_mut()
        .append_pair("callbackURL", PREVIEW)
        .append_pair("profile", &format!("{profile}00"));
    let denied_3 = request(&fixture.preview, &target(&invalid), None, None).await;
    assert!(
        location(&denied_3)
            .as_str()
            .contains("error=invalid_profile")
    );
    assert_eq!(rows(&fixture.preview_db).await, issued);
    let mut expired = state.clone();
    *expired.get_mut("expiresAt").unwrap() = json!(chrono::Utc::now().timestamp_millis() - 1);
    _ = fixture
        .preview_db
        .execute_raw(Statement::from_sql_and_values(
            fixture.preview_db.get_database_backend(),
            "UPDATE verifications SET value=?",
            [expired.to_string().into()],
        ))
        .await
        .unwrap();
    let denied_4 = request(&fixture.preview, &target(&bridge), None, None).await;
    assert!(
        location(&denied_4)
            .as_str()
            .contains("error=state_mismatch")
    );
    let after = rows(&fixture.preview_db).await;
    assert_eq!(
        after
            .get("users")
            .expect("provider fixture contains this parameter"),
        issued
            .get("users")
            .expect("provider fixture contains this parameter")
    );
    assert_eq!(
        after
            .get("accounts")
            .expect("provider fixture contains this parameter"),
        issued
            .get("accounts")
            .expect("provider fixture contains this parameter")
    );
    assert_eq!(
        after
            .get("sessions")
            .expect("provider fixture contains this parameter"),
        issued
            .get("sessions")
            .expect("provider fixture contains this parameter")
    );
    assert_eq!(
        after
            .get("verifications")
            .expect("provider fixture contains this parameter"),
        &json!([])
    );
}
