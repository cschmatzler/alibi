use super::*;

// Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
#[tokio::test]
async fn plugin_database_hooks_run_before_builder_hooks() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = test_config();
    let store = test_store(&config)
        .await
        .hook(OrderingHook {
            label: "plugin",
            events: Arc::clone(&events),
        })
        .hook(OrderingHook {
            label: "builder",
            events: Arc::clone(&events),
        });
    let auth = AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .build()
        .await
        .expect("auth should build");

    drop(
        auth.store()
            .create_user(
                CreateUser::new()
                    .with_email("ordering@example.com")
                    .with_name("Ordering"),
            )
            .await
            .expect("user should be created"),
    );

    assert_eq!(
        *events.lock().expect("events mutex should lock"),
        vec!["plugin", "builder"]
    );
}

// Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
#[tokio::test]
async fn request_context_is_present_for_requests_and_absent_for_direct_store_calls() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let config = test_config();
    let store = test_store(&config).await.hook(RequestContextHook {
        seen: Arc::clone(&seen),
    });
    let auth = AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await
        .expect("auth should build");

    let response = auth
        .handle_request(signup_request("request-context@example.com"))
        .await
        .expect("sign-up request should succeed");
    assert_eq!(response.status, 200);

    drop(
        auth.store()
            .create_user(
                CreateUser::new()
                    .with_email("direct-store@example.com")
                    .with_name("Direct Store"),
            )
            .await
            .expect("direct store call should succeed"),
    );

    assert_eq!(
        *seen.lock().expect("request context mutex should lock"),
        vec![
            (true, "/sign-up/email".to_owned()),
            (false, "<none>".to_owned()),
        ]
    );
}

// Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
#[tokio::test]
async fn onboarding_hook_provisions_app_data_after_the_auth_transaction_commits() {
    let database = test_database().await;
    create_app_workspace_table(&database).await;

    let tx_seen = Arc::new(AtomicBool::new(false));
    let config = test_config();
    let store =
        SeaOrmStore::<TestSchema>::new(config.clone(), database.clone()).hook(OnboardingHook {
            service: ProvisioningService {
                db: database.clone(),
                tx_seen: Arc::clone(&tx_seen),
            },
        });
    let auth = AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await
        .expect("auth should build");

    let response = auth
        .handle_request(signup_request("onboarding@example.com"))
        .await
        .expect("sign-up request should succeed");
    assert_eq!(response.status, 200);

    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response body should be valid JSON");
    let user_id = body["user"]["id"]
        .as_str()
        .expect("user id should be present");

    assert_eq!(app_workspace_rows_for_user(&database, user_id).await, 1);
    assert!(!tx_seen.load(Ordering::SeqCst));
}

// Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
#[tokio::test]
async fn delete_hooks_receive_the_loaded_user_entity() {
    let emails = Arc::new(Mutex::new(Vec::new()));
    let config = test_config();
    let store = test_store(&config).await.hook(DeleteCaptureHook {
        emails: Arc::clone(&emails),
    });
    let auth = AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .build()
        .await
        .expect("auth should build");

    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("delete-capture@example.com")
                .with_name("Delete Capture"),
        )
        .await
        .expect("user should be created");

    auth.store()
        .delete_user(&user.id())
        .await
        .expect("user should be deleted");

    assert_eq!(
        *emails.lock().expect("delete capture mutex should lock"),
        vec![Some("delete-capture@example.com".to_owned())]
    );
}
