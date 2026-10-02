use super::*;

#[test]
fn router_construction_is_lazy_and_completed_router_can_move_between_runtimes() {
    struct DatabaseFile(std::path::PathBuf);

    impl Drop for DatabaseFile {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.0));
        }
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    // SQLite memory databases can vanish when runtime shutdown closes the
    // final pooled connection. Keep this transport owner independent of that
    // database lifetime by using an isolated, persisted file.

    let database_file = DatabaseFile(std::env::temp_dir().join(format!(
        "better-auth-router-runtime-{}.sqlite",
        uuid::Uuid::new_v4()
    )));
    let (auth, evaluated_store) = runtime.block_on(async {
        let database =
            Database::connect(format!("sqlite://{}?mode=rwc", database_file.0.display()))
                .await
                .unwrap();
        auth_with_database(Arc::default(), database).await
    });
    assert!(tokio::runtime::Handle::try_current().is_err());
    let router = Router::new()
        .nest("/auth", Arc::clone(&auth).axum_router())
        .with_state(auth);
    let first = runtime
        .block_on(router.clone().oneshot(request(
            "/auth/transport",
            "first-runtime@transport.fixture.test",
        )))
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    drop(runtime);
    let next_runtime = tokio::runtime::Runtime::new().unwrap();
    let second = next_runtime
        .block_on(router.oneshot(request(
            "/auth/transport",
            "second-runtime@transport.fixture.test",
        )))
        .unwrap();
    let second_status = second.status();
    let second_body = next_runtime
        .block_on(axum::body::to_bytes(second.into_body(), 4096))
        .unwrap();
    assert_eq!(
        second_status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&second_body)
    );
    assert_eq!(
        next_runtime
            .block_on(evaluated_store.get_user_by_email("second-runtime@transport.fixture.test"))
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
}

#[tokio::test]
async fn accepted_dispatch_survives_real_disconnect_and_router_drop_then_releases_ownership() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(Arc::clone(&observations)).await;
    let weak = Arc::downgrade(&auth);
    let router = Arc::clone(&auth)
        .axum_router()
        .with_state(Arc::clone(&auth));
    drop(auth);
    let router = Router::new()
        .nest("/auth", router)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&observations),
            observe,
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                _ = stop.await;
            })
            .await
            .unwrap();
    });
    let mut socket = TcpStream::connect(address).await.unwrap();
    let body = r#"{"email":"disconnected@transport.fixture.test"}"#;
    socket.write_all(format!("POST /auth/transport?pause=yes HTTP/1.1\r\nHost: {address}\r\nUser-Agent: actual-native-agent\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    bounded(&observations.entered).await;
    assert_eq!(
        store
            .get_user_by_email("disconnected@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("started")
    );
    drop(socket);
    bounded(&observations.dropped).await;
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        weak.upgrade().is_some(),
        "accepted worker must retain auth after server/router drop"
    );
    observations.release.notify_one();
    bounded(&observations.finished).await;
    assert_eq!(
        store
            .get_user_by_email("disconnected@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observations.contexts.lock().unwrap().first().unwrap().0,
        "/transport"
    );
    assert_eq!(
        observations.contexts.lock().unwrap().first().unwrap().1,
        "actual-native-agent"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed dispatch retained an auth ownership cycle");
}

#[tokio::test]
async fn live_dispatch_keeps_repeated_headers_context_and_tracing_and_isolates_application_panic() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(Arc::clone(&observations)).await;
    let router = Router::new()
        .nest("/auth", Arc::clone(&auth).axum_router())
        .with_state(auth);
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry());
    let span =
        tracing::dispatcher::with_default(&dispatch, || tracing::info_span!("native-dispatch"));
    let response = router
        .clone()
        .oneshot(request(
            "/auth/transport?original=yes",
            "live@transport.fixture.test",
        ))
        .instrument(span)
        .with_subscriber(dispatch)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-application"], "actual");
    assert_eq!(response.headers()["x-after-hook"], "complete");
    assert_eq!(
        response
            .headers()
            .get_all("x-middleware")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["second-after", "first-after"]
    );
    assert_eq!(
        *observations.phases.lock().unwrap(),
        vec![
            "first-before",
            "second-before",
            "handler",
            "plugin-after",
            "second-after",
            "first-after"
        ]
    );
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "first=one; Path=/; HttpOnly",
            "second=two; Path=/; HttpOnly"
        ]
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(response.into_body(), 256)
                .await
                .unwrap()
        )
        .unwrap(),
        serde_json::json!({"email":"live@transport.fixture.test","name":"completed"})
    );
    assert_eq!(
        *observations.contexts.lock().unwrap().first().unwrap(),
        (
            "/transport".into(),
            "actual-native-agent".into(),
            "native-dispatch".into()
        )
    );
    let panic = router
        .clone()
        .oneshot(request("/auth/panic", "panic@transport.fixture.test"))
        .await
        .unwrap();
    assert_eq!(panic.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(panic.into_body(), 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("private application panic detail"));
    assert!(
        store
            .get_user_by_email("panic@transport.fixture.test")
            .await
            .unwrap()
            .is_none()
    );
    let next = router
        .oneshot(request("/auth/transport", "next@transport.fixture.test"))
        .await
        .unwrap();
    assert_eq!(next.status(), StatusCode::CREATED);
    assert_eq!(
        store
            .get_user_by_email("next@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
}

#[tokio::test]
async fn incomplete_and_over_limit_bodies_never_enter_supervised_dispatch() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(Arc::clone(&observations)).await;
    let router = Router::new()
        .nest("/auth", Arc::clone(&auth).axum_router())
        .with_state(auth)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&observations),
            observe,
        ));
    let over = Request::builder()
        .method("POST")
        .uri("/auth/transport")
        .body(Body::from(vec![b'x'; 257]))
        .unwrap();
    let response = router.clone().oneshot(over).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let control = router.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                _ = stop.await;
            })
            .await
            .unwrap();
    });
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!(
                "POST /auth/transport HTTP/1.1\r\nHost: {address}\r\nContent-Length: 100\r\n\r\n{{",
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    socket.shutdown().await.unwrap();
    let mut result = Vec::new();
    let _read = tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observations.calls.load(Ordering::SeqCst), 0);
    let valid = control
        .oneshot(request(
            "/auth/transport",
            "body-control@transport.fixture.test",
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::CREATED);
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .get_user_by_email("body-control@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn native_request_cancellation_and_detached_observer_preserve_actual_ownership() {
    use better_auth_core::HttpMethod;

    for mode in ["cancel", "detach", "connected"] {
        let observations = Arc::new(Observations::default());
        let (auth, store) = auth(Arc::clone(&observations)).await;
        let email = format!("{mode}@example.test");
        let input = AuthRequest::from_parts(
            HttpMethod::Post,
            "/auth/transport".into(),
            std::collections::HashMap::from([
                ("content-type".into(), "application/json".into()),
                ("user-agent".into(), "actual-native-agent".into()),
            ]),
            Some(serde_json::json!({"email": email}).to_string().into_bytes()),
            std::collections::HashMap::from([("pause".into(), "yes".into())]),
        );
        let task = tokio::spawn(async move { auth.handle_request(input).await.unwrap() });
        bounded(&observations.entered).await;
        assert_eq!(
            store
                .get_user_by_email(&email)
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("started")
        );
        if mode == "cancel" {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            observations.release.notify_one();
            assert_eq!(
                store
                    .get_user_by_email(&email)
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("started")
            );
            assert_eq!(observations.completions.load(Ordering::SeqCst), 0);
            assert!(observations.contexts.lock().unwrap().is_empty());
            assert_eq!(
                *observations.phases.lock().unwrap(),
                vec!["first-before", "second-before", "handler"]
            );
        } else {
            if mode == "detach" {
                // Dropping a real JoinHandle loses the observer, but retains the owned task.
                drop(task);
                observations.release.notify_one();
            } else {
                observations.release.notify_one();
                let response = task.await.unwrap();
                assert_eq!(response.status, 201);
                assert_eq!(
                    response.headers.get("x-after-hook").map(String::as_str),
                    Some("complete")
                );
                assert_eq!(
                    response.headers.get_all("set-cookie").collect::<Vec<_>>(),
                    vec![
                        "first=one; Path=/; HttpOnly",
                        "second=two; Path=/; HttpOnly"
                    ]
                );
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                    serde_json::json!({"email": email, "name":"completed"})
                );
                assert_eq!(
                    *observations.phases.lock().unwrap(),
                    vec![
                        "first-before",
                        "second-before",
                        "handler",
                        "plugin-after",
                        "second-after",
                        "first-after"
                    ]
                );
            }
            bounded(&observations.finished).await;
            assert_eq!(
                store
                    .get_user_by_email(&email)
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("completed")
            );
            assert_eq!(observations.completions.load(Ordering::SeqCst), 1);
            let context = observations.contexts.lock().unwrap();
            assert_eq!(context.first().unwrap().0, "/auth/transport");
            assert_eq!(context.first().unwrap().1, "actual-native-agent");
        }
    }
}
