//! Extension grant dispatch and provider-bound capabilities use real token authority.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderApi, OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use std::sync::Arc;
backend_tests!(oauth_extension_grants_dispatch_bound_authority);
postgres_tests!(oauth_extension_grants_dispatch_bound_authority);
const GRANT: &str = "urn:fixture:extension";
#[derive(Debug)]
struct ExtensionGrant;
#[async_trait::async_trait]
impl alibi::plugins::OAuthExtensionGrantHandler for ExtensionGrant {
    async fn handle(
        &self,
        input: alibi::plugins::OAuthExtensionGrantInput<'_>,
    ) -> Result<serde_json::Value, alibi::endpoint::EndpointError> {
        let body = input.call.body().unwrap().to_json_value()?;
        if body["marker"] == "deny" {
            return Err(alibi::endpoint::EndpointError {
                error: alibi::AuthError::bad_request("extension rejected request"),
                headers: None,
                body: Some(Box::new(alibi::utils::json::JsValue::from(
                    serde_json::json!({"error":"invalid_grant","error_description":"extension rejected request"}),
                ))),
                body_absent: false,
            });
        }
        let scopes = body["scope"]
            .as_str()
            .unwrap_or("email")
            .split(' ')
            .map(str::to_owned)
            .collect();
        let authenticated = input
            .provider
            .authenticate_client(&alibi::plugins::OAuthClientAuthenticationOptions {
                require_credentials: true,
                scopes: Some(scopes),
            })
            .await?;
        let mut params = alibi::plugins::OAuthTokenIssueParams::new(
            authenticated.client,
            body["scope"]
                .as_str()
                .unwrap_or("email")
                .split(' ')
                .map(str::to_owned)
                .collect(),
        );
        params.reference_id = Some("grant-reference".into());
        params.token_response = Some(
            serde_json::json!({"custom":body["marker"],"boundGrant":input.grant_type,"observedGrant":body["grant_type"]}),
        );
        input.provider.issue_tokens(&params).await
    }
}

async fn oauth_extension_grants_dispatch_bound_authority<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = OAuthProviderConfig::default();
    config.grant_types.push("urn:fixture:orphan".into());
    config
        .extensions
        .push(Arc::new(alibi::plugins::OAuthProviderExtension {
            grants: [(
                GRANT.into(),
                Arc::new(ExtensionGrant) as Arc<dyn alibi::plugins::OAuthExtensionGrantHandler>,
            )]
            .into_iter()
            .collect(),
        }));
    let provider = OAuthProviderPlugin::with_config(config);
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(
            &json!({"grant_type":"urn:fixture:orphan","client_id":"not-an-authority"}),
        )?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?["error"],
        "unsupported_grant_type"
    );
    let rejected = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":GRANT,"marker":"deny"}))?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(
        rejected.body.unwrap().to_json_value()?["error"],
        "invalid_grant"
    );
    let owner = signup(&auth, "extension-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Extension client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","grant_types":[GRANT],"token_endpoint_auth_method":"client_secret_post"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    let issued=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":format!(" {GRANT} "),"client_id":client["client_id"],"client_secret":client["client_secret"],"scope":"email","marker":"delivered","grantType":"urn:forged"}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(issued.status, 200);
    let output = body(&issued);
    assert_eq!(output["boundGrant"], GRANT);
    assert_eq!(output["observedGrant"], GRANT);
    assert_eq!(output["custom"], "delivered");
    let call = alibi::endpoint::EndpointCall::new(
        &alibi::endpoint::EndpointDefinition {
            name: "validateFixture",
            operation_id: "validateFixture",
            path: Some("/fixture/validate".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let api = provider.get_oauth_provider_api(auth.context(), &call, None);
    let access = output["access_token"].as_str().unwrap();
    let active = api.require_active_access_token(access, None).await?;
    assert_eq!(active["client_id"], client["client_id"]);
    let hashed = api.hash_token(access, "access_token").await?;
    let row = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hashed)
        .await?
        .unwrap();
    assert_eq!(row.client_id, client["client_id"].as_str().unwrap());
    assert_eq!(
        api.get_client(&row.client_id).await?.unwrap().client_id,
        row.client_id
    );
    assert_eq!(
        api.validate_access_token(access, None).await?["scope"],
        "email"
    );
    let missing = api
        .issue_tokens(&alibi::plugins::OAuthTokenIssueParams::new(
            provider
                .get_client(auth.context(), &row.client_id)
                .await?
                .unwrap(),
            vec!["email".into()],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        missing.body.unwrap().to_json_value()?["error"],
        "server_error"
    );
    Ok(())
}
