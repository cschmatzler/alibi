use super::*;
use alibi::AuthUser as _;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[path = "../../../fixtures/oauth/extension-claims.rs"]
mod extension_claims;

backend_tests!(oauth_extension_claims_receive_live_trusted_issuance_context);
postgres_tests!(oauth_extension_claims_receive_live_trusted_issuance_context);

async fn oauth_extension_claims_receive_live_trusted_issuance_context<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        extensions: extension_claims::extensions(),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "extension-claims@example.test").await;
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
            "client_name":"Claims","redirect_uris":["https://app.fixture.test/callback"],
            "scope":"openid profile email","token_endpoint_auth_method":"none",
            "metadata":{"tenant":"application"}
        }))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 201);
    let client = provider
        .get_client(
            auth.context(),
            body(&created)["client_id"].as_str().unwrap(),
        )
        .await?
        .unwrap();
    let user = auth
        .store()
        .get_user_by_id(body(&owner)["user"]["id"].as_str().unwrap())
        .await?
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(
        client,
        vec!["openid".into(), "profile".into(), "email".into()],
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.reference_id = Some("native-reference".into());
    params.access_token_claims = Some(json!({"per_request":"native"}));
    params.id_token_claims = Some(json!({"per_request":"native"}));
    params.resources = Some(vec![format!("{ORIGIN}/api/auth/oauth2/userinfo")]);
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "nativeClaims",
            operation_id: "nativeClaims",
            path: Some("/native/claims".into()),
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions {
            headers: Some(
                [("x-claims-caller".into(), "native-caller".into())]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        },
    );
    let tokens = provider
        .issue_tokens(auth.context(), &call, Some("urn:native:claims"), &params)
        .await?;
    for key in ["access_token", "id_token"] {
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(tokens[key].as_str().unwrap().split('.').nth(1).unwrap())?,
        )?;
        assert_eq!(claims["extension_owner"], "first");
        assert_eq!(claims["per_request"], "native");
        assert_eq!(claims["extension_first"]["caller"], "native-caller");
        assert_eq!(claims["extension_second"]["caller"], "native-caller");
        assert_eq!(claims["extension_first"]["userId"], user.id().as_ref());
        assert_eq!(claims["extension_first"]["grant"], "urn:native:claims");
        assert_eq!(
            claims["extension_first"]["metadata"],
            json!({"tenant":"application"})
        );
        assert_eq!(claims["sub"], user.id().as_ref());
        assert!(claims.get("constructor").is_none());
    }
    Ok(())
}
