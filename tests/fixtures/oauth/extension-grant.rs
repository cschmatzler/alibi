//! A companion grant fixture uses only live, grant-bound provider capabilities.
#[derive(Debug)]
pub struct ExtensionGrant;
#[async_trait::async_trait]
impl alibi::plugins::OAuthExtensionGrantHandler for ExtensionGrant {
    async fn handle(
        &self,
        input: alibi::plugins::OAuthExtensionGrantInput<'_>,
    ) -> Result<serde_json::Value, alibi::endpoint::EndpointError> {
        let body = input
            .call
            .body()
            .unwrap()
            .to_json_value()
            .map_err(alibi::AuthError::from)?;
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
        let scopes: Vec<String> = body["scope"]
            .as_str()
            .unwrap_or("email")
            .split(' ')
            .map(str::to_owned)
            .collect();
        let authenticated = input
            .provider
            .authenticate_client(&alibi::plugins::OAuthClientAuthenticationOptions {
                require_credentials: true,
                scopes: Some(scopes.clone()),
            })
            .await?;
        let mut params = alibi::plugins::OAuthTokenIssueParams::new(authenticated.client, scopes);
        params.reference_id = Some("grant-reference".into());
        params.token_response = Some(
            serde_json::json!({"custom":body["marker"],"boundGrant":input.grant_type,"observedGrant":body["grant_type"]}),
        );
        input.provider.issue_tokens(&params).await
    }
}
