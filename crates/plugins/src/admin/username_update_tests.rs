use super::*;

fn update_request(id: &str, data: serde_json::Value) -> types::AdminUpdateUserRequest {
    types::AdminUpdateUserRequest::new(id, data.as_object().unwrap().clone())
}

fn update_call(
    user: UserView,
    session: SessionView,
    path: &str,
) -> alibi_core::endpoint::EndpointCall {
    let definition = alibi_core::endpoint::EndpointDefinition {
        name: "update-user",
        operation_id: "updateUser",
        path: Some(path.into()),
        method: HttpMethod::Post,
    };
    let call = alibi_core::endpoint::EndpointCall::new(&definition, None, None, Default::default());
    call.record_authenticated_session(user, session);
    call
}

#[tokio::test]
async fn admin_username_updates_use_actual_actor_and_keep_falsy_display_without_create_fallback() {
    let ctx = username_context(UsernameConfig::default(), None).await;
    let admin = ctx
        .database
        .get_user_by_email_record(&"admin@example.com".into())
        .await
        .unwrap()
        .unwrap();
    let acting = UserView::from(&admin);
    let created = handlers::create_user_core(
        &provision(
            "updated-username@fixture.test",
            serde_json::json!({"username":"EXISTING"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap()
    .user;
    let input = update_request(&created.id, serde_json::json!({"username":"existing"}));
    let error = handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::Upstream {
            code: "USERNAME_IS_ALREADY_TAKEN",
            ..
        }
    ));
    let session = test_helpers::create_session(&ctx, created.id.clone(), Duration::hours(1)).await;
    let self_call = update_call(created.clone(), session.clone(), "/admin/update-user");
    let result = alibi_core::endpoint::with_endpoint_call_context(
        self_call,
        handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx),
    )
    .await
    .unwrap();
    assert_eq!(
        result
            .values()
            .get("username")
            .and_then(alibi_core::utils::json::JsValue::as_str),
        Some("existing")
    );
    let other_call = update_call(acting.clone(), session.clone(), "/admin/update-user");
    assert!(
        alibi_core::endpoint::with_endpoint_call_context(
            other_call,
            handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx)
        )
        .await
        .is_err()
    );
    let changed = handlers::update_user_core(
        &update_request(
            &created.id,
            serde_json::json!({"username":"NEW_NAME","displayUsername":false}),
        ),
        &acting,
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(
        changed
            .values()
            .get("username")
            .and_then(alibi_core::utils::json::JsValue::as_str),
        Some("new_name")
    );
    assert_eq!(
        changed
            .values()
            .get("displayUsername")
            .and_then(alibi_core::utils::json::JsValue::as_str),
        Some("0")
    );
    let nulled = handlers::update_user_core(
        &update_request(
            &created.id,
            serde_json::json!({"username":null,"displayUsername":null}),
        ),
        &acting,
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert!(nulled.values()["username"].is_null());
    assert!(nulled.values()["displayUsername"].is_null());
    let default_numeric = handlers::update_user_core(
        &update_request(&created.id, serde_json::json!({"username":42})),
        &acting,
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(default_numeric.status_code(), 500);
    assert!(
        ctx.database
            .get_user_by_id(&created.id)
            .await
            .unwrap()
            .unwrap()
            .username()
            .is_none()
    );
    let skip = update_call(acting.clone(), session, "/update-user");
    let skipped = alibi_core::endpoint::with_endpoint_call_context(
        skip,
        handlers::update_user_core(
            &update_request(&created.id, serde_json::json!({"username":"X"})),
            &acting,
            &AdminConfig::default(),
            &ctx,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        skipped
            .values()
            .get("username")
            .and_then(alibi_core::utils::json::JsValue::as_str),
        Some("x")
    );
}

#[tokio::test]
async fn admin_username_updates_await_ordered_validation_and_stop_later_hooks() {
    for admit in [true, false] {
        let (mut ctx, _, _, target, _) = create_admin_context().await;
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
        let log = events.clone();
        init.register_user_update_transform(move |_, input| {
            log.lock().unwrap().push("before".to_owned());
            Ok(input)
        });
        let log = events.clone();
        let policy = UsernameConfig {
            validator: Some(Arc::new(move |username: String| {
                let log = log.clone();
                async move {
                    tokio::task::yield_now().await;
                    log.lock().unwrap().push(format!("validator:{username}"));
                    Ok(admit)
                }
            })),
            ..Default::default()
        };
        let plugin = EmailPasswordPlugin::new()
            .enable_username(true)
            .username_config(policy.clone());
        <EmailPasswordPlugin as AuthPlugin<TestSchema>>::on_init(&plugin, &mut init)
            .await
            .unwrap();
        init.extensions
            .insert(UserFields(SessionFields(policy.fields())));
        init.extensions
            .insert(alibi_core::field_policy::AdapterFieldPolicies {
                user: alibi_core::field_policy::SessionAdapterFields(Arc::new(policy.fields())),
                ..Default::default()
            });
        let log = events.clone();
        init.register_user_update_transform(move |_, input| {
            log.lock().unwrap().push("after".to_owned());
            assert_eq!(input.username.as_deref(), Some("ORDERED"));
            Ok(input)
        });
        ctx.metadata = init.metadata.clone();
        ctx.extensions = init.extensions.clone();
        ctx.database = init.database_with_registered_transforms();
        let result = ctx
            .database
            .update_user(
                &target.id,
                alibi_core::UpdateUser {
                    username: Some("ORDERED".into()),
                    name: Some("Changed".into()),
                    ..Default::default()
                },
            )
            .await;
        let stored = ctx
            .database
            .get_user_by_id(&target.id)
            .await
            .unwrap()
            .unwrap();
        if admit {
            result.unwrap();
            assert_eq!(
                *events.lock().unwrap(),
                ["before", "validator:ORDERED", "after"]
            );
            assert_eq!(stored.username(), Some("ordered"));
            assert_eq!(stored.name(), Some("Changed"));
        } else {
            assert_eq!(result.unwrap_err().status_code(), 400);
            assert_eq!(*events.lock().unwrap(), ["before", "validator:ORDERED"]);
            assert_eq!(stored.username(), None);
            assert_eq!(stored.name(), target.name.as_deref());
        }
    }
}

#[tokio::test]
async fn admin_username_updates_preserve_scalars_and_observe_current_transaction() {
    let policy = UsernameConfig {
        normalization: UsernameNormalization::Preserve,
        ..Default::default()
    };
    let ctx = username_context(policy, None).await;
    let acting = UserView::from(
        &ctx.database
            .get_user_by_email_record(&"admin@example.com".into())
            .await
            .unwrap()
            .unwrap(),
    );
    let target = handlers::create_user_core(
        &provision("preserved-update@fixture.test", serde_json::json!({})),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap()
    .user;
    for raw in [
        serde_json::json!("KeEpCaSe"),
        serde_json::json!(42),
        serde_json::json!(false),
        serde_json::json!(""),
    ] {
        let changed = handlers::update_user_core(
            &update_request(
                &target.id,
                serde_json::json!({"username":raw,"displayUsername":false}),
            ),
            &acting,
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap();
        let expected = match raw {
            serde_json::Value::String(text) => text,
            serde_json::Value::Bool(_) => "0".into(),
            _ => "42".into(),
        };
        assert_eq!(
            changed
                .values()
                .get("username")
                .and_then(alibi_core::utils::json::JsValue::as_str),
            Some(expected.as_str())
        );
        assert_eq!(
            changed
                .values()
                .get("displayUsername")
                .and_then(alibi_core::utils::json::JsValue::as_str),
            Some("0")
        );
    }
    alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
        Box::pin(async move {
            let first = tx
                .create_user(CreateUser::new().with_email("update-tx-a@fixture.test"))
                .await?;
            let second = tx
                .create_user(CreateUser::new().with_email("update-tx-b@fixture.test"))
                .await?;
            let updated = tx
                .update_user(
                    first.id().as_ref(),
                    alibi_core::UpdateUser {
                        username: Some("InTransaction".into()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(updated.username(), Some("InTransaction"));
            let error = tx
                .update_user(
                    second.id().as_ref(),
                    alibi_core::UpdateUser {
                        username: Some("InTransaction".into()),
                        name: Some("Never".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                AuthError::Upstream {
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    ..
                }
            ));
            assert_ne!(
                tx.get_user_by_id(second.id().as_ref())
                    .await?
                    .unwrap()
                    .name(),
                Some("Never")
            );
            Ok(())
        })
    })
    .await
    .unwrap();
}
