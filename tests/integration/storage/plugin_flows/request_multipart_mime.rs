use super::*;

backend_tests!(malformed_multipart_mime_cannot_repair_itself_into_credentials);
postgres_tests!(malformed_multipart_mime_cannot_repair_itself_into_credentials);

async fn malformed_multipart_mime_cannot_repair_itself_into_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&auth, "multipart-owner@example.test").await;
    let raw = format!(
        "--fixture-boundary\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nmultipart-owner@example.test\r\n--fixture-boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{PASSWORD}\r\n--fixture-boundary--\r\n"
    );
    let original = db.tables(&["user", "account", "session"]).await?;
    for content_type in [
        "multipart/form-dataapplication/json; boundary=fixture-boundary",
        "multipart/form-dataapplication/json; boundary=fixture-boundary; charset=utf-8",
    ] {
        let mut input = request("/sign-in/email", Some(json!({})), &cookies(&owner));
        _ = input
            .headers
            .insert("content-type".into(), content_type.into());
        input.body = Some(raw.as_bytes().to_vec());
        let response = call(&auth, input, 500).await;
        assert!(response.body.is_empty());
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(db.tables(&["user", "account", "session"]).await?, original);
    }
    let valid = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({
                "email":"multipart-owner@example.test","password":PASSWORD,
            })),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&valid)["user"]["id"], body(&owner)["user"]["id"]);
    Ok(())
}
