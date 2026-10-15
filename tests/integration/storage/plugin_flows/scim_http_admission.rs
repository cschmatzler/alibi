//! SCIM request preparation precedes generic body parsing and endpoint admission.
use super::*;
use alibi::plugins::ScimPlugin;
backend_tests!(scim_http_admission_preserves_protocol_errors_and_ignores_delete_bodies);
postgres_tests!(scim_http_admission_preserves_protocol_errors_and_ignores_delete_bodies);
pub(super) async fn http<S: AuthSchema>(
    auth: &Alibi<S>,
    method: HttpMethod,
    path: &str,
    media: Option<&str>,
    payload: Option<&str>,
    token: Option<&str>,
) -> AuthResponse {
    let mut request = AuthRequest::new(method, format!("/api/auth/scim/v2/{path}"));
    request.body = payload.map(|value| value.as_bytes().to_vec());
    if let Some(media) = media {
        _ = request.headers.insert("content-type".into(), media.into());
    }
    if let Some(token) = token {
        _ = request
            .headers
            .insert("authorization".into(), format!("Bearer {token}"));
    }
    Box::pin(auth.handle_request(request)).await.unwrap()
}
async fn scim_http_admission_preserves_protocol_errors_and_ignores_delete_bodies<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    for (method, path, media, payload, token, status, expected) in [
        (
            HttpMethod::Post,
            "Users",
            Some("text/plain"),
            "bad",
            None,
            415,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"415","detail":"SCIM requests must use application/scim+json or application/json"}),
        ),
        (
            HttpMethod::Put,
            "Users/missing",
            Some("application/json"),
            "{",
            None,
            400,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","detail":"SCIM request body must contain valid JSON","scimType":"invalidSyntax"}),
        ),
        (
            HttpMethod::Patch,
            "Groups/missing",
            Some("application/scim+json"),
            "",
            None,
            400,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","detail":"SCIM request body must contain valid JSON","scimType":"invalidSyntax"}),
        ),
        (
            HttpMethod::Post,
            "Groups",
            None,
            "{}",
            None,
            415,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"415","detail":"SCIM requests must use application/scim+json or application/json"}),
        ),
        (
            HttpMethod::Post,
            "Groups",
            Some("application/json; charset=utf-8"),
            "{",
            None,
            400,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"400","detail":"SCIM request body must contain valid JSON","scimType":"invalidSyntax"}),
        ),
        (
            HttpMethod::Delete,
            "Users/missing",
            Some("application/json"),
            "{",
            None,
            401,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"SCIM bearer token is required"}),
        ),
        (
            HttpMethod::Delete,
            "Groups/missing",
            Some("text/plain"),
            "{",
            Some("group-reader"),
            404,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"SCIM Group not found"}),
        ),
        (
            HttpMethod::Post,
            "unknown",
            Some("text/plain"),
            "bad",
            None,
            415,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"415","detail":"SCIM requests must use application/scim+json or application/json"}),
        ),
    ] {
        let response = http(&auth, method, path, media, Some(payload), token).await;
        assert_eq!(
            response.status,
            status,
            "{path}: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(body(&response), expected);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/scim+json")
        );
    }
    for kind in ["Users", "Groups"] {
        let created = if kind == "Users" {
            super::scim_user_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"delete-body@example.com"}),Some("group-reader")).await?
        } else {
            super::scim_group_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Delete body"}),&json!({}),Some("group-reader")).await?
        };
        assert_eq!(created.status, 201);
        let resource = body(&created);
        let path = format!("{kind}/{}", resource["id"].as_str().unwrap());
        let removed = http(
            &auth,
            HttpMethod::Delete,
            &path,
            Some("text/plain"),
            Some("{"),
            Some("group-reader"),
        )
        .await;
        assert_eq!(removed.status, 204);
        assert!(removed.body.is_empty());
        let missing = http(
            &auth,
            HttpMethod::Get,
            &path,
            None,
            None,
            Some("group-reader"),
        )
        .await;
        assert_eq!(missing.status, 404);
    }
    Ok(())
}
