//! Slug lookup allows trusted headerless calls and still authenticates request-backed callers.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::types::CheckSlugRequest;

backend_tests!(server_slug_checks_admit_headerless_calls_and_authenticate_attached_credentials);
async fn server_slug_checks_admit_headerless_calls_and_authenticate_attached_credentials<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "slug-owner@example.test").await;
    let _created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Stored slug","slug":"stored-slug"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let before = db
        .tables(&["users", "organization", "member", "sessions"])
        .await?;
    for slug in ["available-slug", "", "UPPER/slash space"] {
        let output = auth
            .dispatch_endpoint(
                OrganizationPlugin::check_slug_endpoint(&CheckSlugRequest { slug: slug.into() })?
                    .with_query(&json!({"slug":"stored-slug"}))?,
                EndpointOptions::default(),
            )
            .await?;
        assert!(output.decode()?.status);
    }
    let endpoint = |slug: &str| {
        OrganizationPlugin::check_slug_endpoint(&CheckSlugRequest { slug: slug.into() })
    };
    let taken = auth
        .dispatch_endpoint(endpoint("stored-slug")?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(taken.error.status_code(), 400);
    assert_eq!(
        body(&taken.error.to_auth_response())["code"],
        "ORGANIZATION_SLUG_ALREADY_TAKEN"
    );
    let authenticated = auth
        .dispatch_endpoint(
            endpoint("authenticated-free")?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?;
    assert!(authenticated.decode()?.status);
    for options in [
        EndpointOptions {
            headers: Some(Default::default()),
            ..Default::default()
        },
        EndpointOptions {
            request: Some(request(
                "/organization/check-slug",
                Some(json!({"slug":"stored-slug"})),
                "",
            )),
            ..Default::default()
        },
    ] {
        let denied = auth
            .dispatch_endpoint(endpoint("stored-slug")?, options)
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 401);
        assert_eq!(
            body(&denied.error.to_auth_response())["code"],
            "UNAUTHORIZED"
        );
    }
    assert_eq!(
        db.tables(&["users", "organization", "member", "sessions"])
            .await?,
        before
    );
    B::close(connection).await
}
