use super::*;

#[tokio::test]
async fn admin_supplied_ids_use_string_defaults_and_actual_sqlite_parameters() {
    use alibi_core::AuthUser;
    let (ctx, _, _, _, _) = create_admin_context().await;
    for (index, (raw, expected)) in [
        (serde_json::json!("admin-provided-id"), "admin-provided-id"),
        (serde_json::json!(2), "2"),
        (serde_json::json!(1.9), "1.9"),
        (serde_json::json!(true), "1"),
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("supplied-id-{index}@fixture.test");
        let mut input = types::CreateUserRequest::new(&email, "Supplied identifier");
        input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
        let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        assert_eq!(created.user.id, expected);
        assert_eq!(
            ctx.database
                .get_user_by_id(expected)
                .await
                .unwrap()
                .unwrap()
                .email(),
            Some(email.as_str())
        );
        assert_eq!(
            ctx.database
                .get_user_by_email(&email.into())
                .await
                .unwrap()
                .unwrap()
                .id(),
            expected
        );
    }
    for (index, data) in [serde_json::json!({}), serde_json::json!({"id":null})]
        .into_iter()
        .enumerate()
    {
        let email = format!("default-id-{index}@fixture.test");
        let mut input = types::CreateUserRequest::new(&email, "Generated identifier");
        input.data = Some(data.as_object().unwrap().clone());
        let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        assert!(!created.user.id.is_empty());
        assert_eq!(
            ctx.database
                .get_user_by_id(&created.user.id)
                .await
                .unwrap()
                .unwrap()
                .email(),
            Some(email.as_str())
        );
    }
    for (index, raw) in [
        serde_json::json!(false),
        serde_json::json!(0),
        serde_json::json!(""),
        serde_json::json!({}),
        serde_json::json!([]),
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("invalid-id-{index}@fixture.test");
        let mut input = types::CreateUserRequest::new(&email, "Must not persist");
        input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
        let error = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 500, "{raw:?}: {error:?}");
        assert!(
            ctx.database
                .get_user_by_email(&email.into())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn supplied_native_ids_do_not_invoke_the_application_generator() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut config = test_helpers::create_test_config();
    config.advanced.database.generate_id = Some(alibi_core::config::DatabaseIdStrategy::Custom(
        Arc::new(move |model: &str, _: Option<usize>| {
            assert_eq!(model, "user");
            Ok(Some(format!(
                "generated-{}",
                observed.fetch_add(1, Ordering::SeqCst)
            )))
        }),
    ));
    let config = Arc::new(config);
    let database = alibi_seaorm::sea_orm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
        config.clone(),
        database,
    ));
    let ctx = AuthContext::new(config, store);
    for (index, raw) in [
        serde_json::json!("provided"),
        serde_json::json!(71),
        serde_json::json!(true),
        serde_json::json!(false),
        serde_json::json!(0),
        serde_json::json!(""),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input =
            types::CreateUserRequest::new(format!("counter-id-{index}@fixture.test"), "Counter");
        input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
        let result = handlers::create_user_core(&input, &AdminConfig::default(), &ctx).await;
        assert_eq!(result.is_ok(), index < 3);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    for (index, data) in [serde_json::json!({"id":null}), serde_json::json!({})]
        .into_iter()
        .enumerate()
    {
        let mut input = types::CreateUserRequest::new(
            format!("counter-default-{index}@fixture.test"),
            "Counter",
        );
        input.data = Some(data.as_object().unwrap().clone());
        let user = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        assert_eq!(user.user.id, format!("generated-{index}"));
        assert_eq!(calls.load(Ordering::SeqCst), index + 1);
    }
}
