use super::*;

struct FormProbe;

#[async_trait::async_trait]
impl<S: alibi::AuthSchema> alibi::AuthPlugin<S> for FormProbe {
    fn name(&self) -> &'static str {
        "form-probe"
    }
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        vec![alibi::AuthRoute::post("/form-probe", "formProbe")]
    }
    fn allowed_media_types(&self, _: &alibi::AuthRoute) -> Vec<&'static str> {
        vec!["multipart/form-data", "application/x-www-form-urlencoded"]
    }
    async fn on_request(
        &self,
        req: &alibi::AuthRequest,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<alibi::AuthResponse>> {
        Ok(Some(alibi::AuthResponse::json(
            200,
            &json!({"payload":req.body_as_json::<Value>()?}),
        )?))
    }
}

backend_tests!(malformed_form_mime_cannot_repair_itself_into_credentials);
postgres_tests!(malformed_form_mime_cannot_repair_itself_into_credentials);

async fn malformed_form_mime_cannot_repair_itself_into_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(FormProbe)
        .build()
        .await?;
    let owner = signup(&auth, "multipart-owner@example.test").await;
    let raw = format!(
        "--fixture-boundary\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nmultipart-owner@example.test\r\n--fixture-boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{PASSWORD}\r\n--fixture-boundary--\r\n"
    );
    let form = format!("email=multipart-owner%40example.test&password={PASSWORD}");
    let original = db.tables(&["user", "account", "session"]).await?;
    for (content_type, raw) in [
        (
            "multipart/form-dataapplication/json; boundary=fixture-boundary",
            raw.as_str(),
        ),
        (
            "multipart/form-dataapplication/json; boundary=fixture-boundary; charset=utf-8",
            raw.as_str(),
        ),
        (
            "application/x-www-form-urlencodedapplication/json",
            form.as_str(),
        ),
        ("text/application/x-www-form-urlencoded", form.as_str()),
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
    let mut input = request("/sign-in/email", Some(json!({})), &cookies(&owner));
    _ = input.headers.insert(
        "content-type".into(),
        "Application/X-WWW-Form-Urlencoded; charset=utf-8".into(),
    );
    input.body = Some(form.into_bytes());
    let valid = call(&auth, input, 200).await;
    assert_eq!(body(&valid)["user"]["id"], body(&owner)["user"]["id"]);
    let mut input = request("/form-probe", Some(json!({})), &cookies(&owner));
    _=input.headers.insert("content-type".into(),r#"multipart/form-data; boundary=fixture-boundary; mode="application/x-www-form-urlencoded""#.into());
    input.body=Some(b"--fixture-boundary\r\nContent-Disposition: form-data; name=\"literal\"\r\n\r\nform-text\r\n--fixture-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"probe.txt\"\r\nContent-Type: text/plain\r\n\r\nsecret-contents\r\n--fixture-boundary--\r\n".to_vec());
    let mixed = call(&auth, input, 200).await;
    assert_eq!(
        body(&mixed),
        json!({"payload":{"literal":"form-text","file":"[object File]"}})
    );
    Ok(())
}
