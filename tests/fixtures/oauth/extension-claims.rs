use alibi::plugins::{OAuthTokenClaimsInput, OAuthUserInfoClaimsInput};
use serde_json::{Map, Value, json};

#[derive(Debug)]
pub(super) struct ExtensionClaims {
    pub id: &'static str,
    pub target: &'static str,
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenClaimsContributor for ExtensionClaims {
    async fn contribute(
        &self,
        input: OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        if input
            .context
            .endpoint
            .as_ref()
            .and_then(|call| call.headers())
            .and_then(|headers| headers.get("x-claims-error"))
            .map(String::as_str)
            == Some(self.target)
        {
            return Err(alibi::AuthError::Api {
                status: 400,
                code: Some("CLAIM_REJECTED".into()),
                message: format!("rejected {}", self.target),
            });
        }
        Ok(json!({
            "extension_owner": self.id,
            format!("extension_{}", self.id): {
                "grant": input.grant_type,
                "scopes": input.params.scopes,
                "userId": input.params.user.as_ref().map(|user| &user.id),
                "clientId": input.params.client.client_id,
                "referenceId": input.params.reference_id,
                "sessionId": input.params.session_id,
                "metadata": input.metadata,
                "caller": input.context.endpoint.as_ref().and_then(|call|call.headers()).and_then(|headers|headers.get("x-claims-caller")),
            },
            "per_request": self.id,
            "resource_wins": self.id,
            "sub": "forged", "iss": "https://forged.fixture.test", "aud": "forged",
            "email": "forged@example.test", "scope": "forged", "exp": 1, "sid": "forged",
            "constructor": "forged", "nullable_claim": null,
        }).as_object().unwrap().clone())
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthUserInfoClaimsContributor for ExtensionClaims {
    async fn contribute(
        &self,
        input: OAuthUserInfoClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        Ok(json!({
            "extension_owner": self.id,
            format!("extension_{}", self.id): {
                "scopes": input.scopes,
                "userId": input.user.id,
                "clientId": input.client.map(|client| &client.client_id),
                "requestedClaims": input.requested_claims,
                "payloadSub": input.payload.get("sub"),
                "caller": input.context.endpoint.as_ref().and_then(|call|call.headers()).and_then(|headers|headers.get("x-claims-caller")),
            },
            "sub": "forged", "name": "Forged name", "email_verified": true,
            "constructor": "forged", "nullable_claim": null,
        }).as_object().unwrap().clone())
    }
}
pub(super) fn extensions() -> Vec<std::sync::Arc<alibi::plugins::OAuthProviderExtension>> {
    ["first", "second"]
        .into_iter()
        .map(|id| {
            std::sync::Arc::new(alibi::plugins::OAuthProviderExtension {
                claims: alibi::plugins::OAuthExtensionClaims {
                    access_token: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "access",
                    })),
                    id_token: Some(std::sync::Arc::new(ExtensionClaims { id, target: "id" })),
                    user_info: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "userinfo",
                    })),
                },
                ..Default::default()
            })
        })
        .collect()
}
