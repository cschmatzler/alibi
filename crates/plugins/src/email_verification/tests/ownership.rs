use super::*;

#[tokio::test]
async fn mailbox_change_requires_a_bound_user_and_never_verifies_an_unverified_owner() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = EmailVerificationPlugin::new();
    let owner = ctx
        .database
        .create_user(CreateUser::new().with_email("owner@binding.test"))
        .await
        .unwrap();
    for bound in [false, true] {
        let token = create_email_verification_token(
            ctx.config.current_secret(),
            "owner@binding.test",
            Some("changed@binding.test"),
            Duration::hours(1),
            Some("change-email-verification"),
            bound.then_some(owner.id().as_ref()),
        )
        .unwrap();
        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/verify-email",
            None,
            None,
            HashMap::from([("token".into(), token)]),
        );
        let response = plugin.handle_verify_email(&req, &ctx).await;
        if bound {
            let response = response.unwrap();
            assert_eq!(response.status, 200);
            assert!(response.headers.get("set-cookie").is_none());
            let user = ctx
                .database
                .get_user_by_id(&owner.id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(user.email(), Some("changed@binding.test"));
            assert!(!user.email_verified());
            assert_eq!(
                ctx.database.get_user_sessions(&owner.id()).await.unwrap(),
                []
            );
        } else {
            assert_eq!(
                response.unwrap_err().error_payload().1.as_deref(),
                Some("INVALID_TOKEN")
            );
            assert_eq!(
                ctx.database
                    .get_user_by_id(&owner.id())
                    .await
                    .unwrap()
                    .unwrap()
                    .email(),
                Some("owner@binding.test")
            );
        }
    }
}

#[tokio::test]
async fn released_mailbox_cannot_transfer_a_verification_link_to_its_next_owner() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = EmailVerificationPlugin::new();
    let owner = ctx
        .database
        .create_user(CreateUser::new().with_email("reused@binding.test"))
        .await
        .unwrap();
    let token = create_email_verification_token(
        ctx.config.current_secret(),
        "reused@binding.test",
        None,
        Duration::hours(1),
        None,
        Some(&owner.id()),
    )
    .unwrap();
    _ = ctx
        .database
        .update_user(
            &owner.id(),
            UpdateUser {
                email: Some("released@binding.test".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let replacement = ctx
        .database
        .create_user(CreateUser::new().with_email("reused@binding.test"))
        .await
        .unwrap();
    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/verify-email",
        None,
        None,
        HashMap::from([("token".into(), token)]),
    );
    assert_eq!(
        plugin
            .handle_verify_email(&req, &ctx)
            .await
            .unwrap_err()
            .error_payload()
            .1
            .as_deref(),
        Some("INVALID_TOKEN")
    );
    assert!(
        !ctx.database
            .get_user_by_id(&replacement.id())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
}
