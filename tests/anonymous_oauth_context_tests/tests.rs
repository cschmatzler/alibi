use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn consumed_oauth_context_requires_actual_capture_and_a_proof_bound_to_the_issued_state() {
    for mode in [
        "captured",
        "modified-owner",
        "copied-proof",
        "legacy-object",
        "legacy-string",
        "legacy-array",
        "legacy-null",
        "wrong-cookie",
        "expired",
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let token_calls = Arc::clone(&calls);
        let user_calls = Arc::clone(&calls);
        let provider = Router::new()
            .route("/oauth/token", post(move || { let calls_2=Arc::clone(&token_calls); async move {
                _ = calls_2.fetch_add(1, Ordering::SeqCst);
                Json(json!({"access_token":"local-actual-access","token_type":"Bearer","scope":"read_user","expires_in":3600}))
            }}))
            .route("/api/v4/user", get(move || { let calls_3=Arc::clone(&user_calls); async move {
                _ = calls_3.fetch_add(1, Ordering::SeqCst);
                Json(json!({"id":42,"name":"Real Provider Owner","email":"oauth-owner@fixture.test","email_verified":true,"state":"active","locked":false}))
            }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, provider).await.unwrap();
        });
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let config = AuthConfig::new("native-anonymous-context-authentication-secret-32")
            .base_url("http://localhost:42615");
        let events = Arc::new(Mutex::new(Vec::new()));
        let auth = AuthBuilder::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(OAuthPlugin::new().add_provider(
                "gitlab",
                OAuthProvider::gitlab_with_issuer("local-client", "local-secret", &issuer),
            ))
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                on_link_account: Some(Arc::new(Linker(Arc::clone(&events)))),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap();
        let anonymous = auth
            .handle_request(request(
                "/api/auth/sign-in/anonymous",
                Some(json!({})),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(anonymous.status, 200, "{mode}");
        let old: Value = serde_json::from_slice(&anonymous.body).unwrap();
        let old_id = old
            .get("user")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();
        let foreign = auth
            .handle_request(request(
                "/api/auth/sign-in/anonymous",
                Some(json!({})),
                None,
            ))
            .await
            .unwrap();
        let foreign_body: Value = serde_json::from_slice(&foreign.body).unwrap();
        let foreign_id = foreign_body
            .get("user")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();
        let foreign_user_before = auth
            .store()
            .get_user_by_id(foreign_id)
            .await
            .unwrap()
            .unwrap();
        let foreign_sessions_before = auth.store().get_user_sessions(foreign_id).await.unwrap();
        let (state, state_cookie, mut payload) =
            initiate(&auth, &cookies(&anonymous), foreign_id).await;
        assert_eq!(
            payload
                .get("serverContext")
                .unwrap()
                .get("anonymousUserId")
                .unwrap(),
            old_id,
            "client authority must be stripped"
        );
        assert_eq!(payload.get("application").unwrap(), &json!({"kept":true}));
        assert_eq!(
            payload
                .get("_serverContextProof")
                .unwrap()
                .as_str()
                .unwrap()
                .len(),
            43
        );
        let row = auth
            .store()
            .get_verification_by_identifier(&state)
            .await
            .unwrap()
            .unwrap();
        let mut selected_cookie = state_cookie.clone();
        match mode {
            "modified-owner" => {
                *payload
                    .get_mut("serverContext")
                    .unwrap()
                    .get_mut("anonymousUserId")
                    .unwrap() = json!(foreign_id);
            }
            "copied-proof" => {
                let (_other_state, _other_cookie, other) =
                    initiate(&auth, &cookies(&anonymous), foreign_id).await;
                assert_ne!(
                    other.get("_serverContextProof").unwrap(),
                    payload.get("_serverContextProof").unwrap()
                );
                *payload.get_mut("_serverContextProof").unwrap() =
                    other.get("_serverContextProof").unwrap().clone();
            }
            "legacy-object" => {
                *payload.get_mut("serverContext").unwrap() = json!({"anonymousUserId":foreign_id});
                drop(
                    payload
                        .as_object_mut()
                        .unwrap()
                        .remove("_serverContextProof"),
                );
            }
            "legacy-string" => {
                *payload.get_mut("serverContext").unwrap() = json!("arbitrary old client data");
                *payload.get_mut("_serverContextProof").unwrap() = json!({"private":true});
            }
            "legacy-array" => {
                *payload.get_mut("serverContext").unwrap() = json!([foreign_id]);
                *payload.get_mut("_serverContextProof").unwrap() = json!(false);
            }
            "legacy-null" => {
                *payload.get_mut("serverContext").unwrap() = Value::Null;
                *payload.get_mut("_serverContextProof").unwrap() = json!(99);
            }
            "wrong-cookie" => {
                let (_, cookie, _) = initiate(&auth, &cookies(&anonymous), foreign_id).await;
                selected_cookie = cookie;
            }
            "expired" => {
                *payload.get_mut("expiresAt").unwrap() =
                    json!((Utc::now() - Duration::minutes(1)).timestamp_millis());
            }
            _ => {}
        }
        let edited = database
            .execute_raw(Statement::from_sql_and_values(
                database.get_database_backend(),
                "UPDATE verifications SET value=? WHERE id=?",
                [payload.to_string().into(), row.id().into_owned().into()],
            ))
            .await
            .unwrap();
        assert_eq!(edited.rows_affected(), 1);
        let response = callback(&auth, &state, &selected_cookie).await;
        assert_eq!(response.status, 302, "{mode}");
        let denied = matches!(mode, "wrong-cookie" | "expired");
        if denied {
            assert!(
                response
                    .headers
                    .get("location")
                    .unwrap()
                    .contains(if mode == "wrong-cookie" {
                        "state_mismatch"
                    } else {
                        "please_restart_the_process"
                    }),
                "{mode}: {:?}",
                response.headers
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(
                auth.store()
                    .get_user_by_email("oauth-owner@fixture.test")
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            assert_eq!(
                response.headers.get("location").unwrap(),
                "/completed",
                "{mode}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let new = auth
                .store()
                .get_user_by_email("oauth-owner@fixture.test")
                .await
                .unwrap()
                .unwrap();
            assert_ne!(new.id().as_ref(), old_id);
            assert_ne!(new.id().as_ref(), foreign_id);
            let sessions = auth
                .store()
                .get_user_sessions(new.id().as_ref())
                .await
                .unwrap();
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions.first().unwrap().user_id(), new.id());
            assert_eq!(
                auth.store()
                    .get_user_accounts(new.id().as_ref())
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        let transferred = mode == "captured";
        assert_eq!(
            events.lock().unwrap().len(),
            usize::from(transferred),
            "{mode}"
        );
        assert_eq!(
            auth.store().get_user_by_id(old_id).await.unwrap().is_none(),
            transferred,
            "{mode}"
        );
        assert_eq!(
            auth.store()
                .get_user_sessions(old_id)
                .await
                .unwrap()
                .is_empty(),
            transferred,
            "{mode}"
        );
        assert_eq!(
            auth.store()
                .get_user_by_id(foreign_id)
                .await
                .unwrap()
                .unwrap(),
            foreign_user_before,
            "{mode}"
        );
        assert_eq!(
            auth.store().get_user_sessions(foreign_id).await.unwrap(),
            foreign_sessions_before,
            "{mode}"
        );
        assert!(
            auth.store()
                .get_user_accounts(foreign_id)
                .await
                .unwrap()
                .is_empty(),
            "{mode}"
        );
        assert_eq!(
            auth.store()
                .get_verification_by_identifier(&state)
                .await
                .unwrap()
                .is_some(),
            mode == "wrong-cookie"
        );
        if !denied {
            let replay = callback(&auth, &state, &state_cookie).await;
            assert!(
                replay
                    .headers
                    .get("location")
                    .unwrap()
                    .contains("state_mismatch")
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(events.lock().unwrap().len(), usize::from(transferred));
        }
        server.abort();
    }
}
