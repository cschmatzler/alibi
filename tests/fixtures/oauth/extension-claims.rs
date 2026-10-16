use alibi::plugins::{OAuthTokenClaimsInput, OAuthUserInfoClaimsInput};
use serde_json::{Map, Value, json};

#[derive(Debug)]
pub(super) struct ExtensionClaims {
    pub id: &'static str,
    pub target: &'static str,
    pub live: Option<std::sync::Arc<LiveAccessClaims>>,
}

#[derive(Debug, Default)]
pub(super) struct LiveAccessClaims {
    pub value: std::sync::Mutex<String>,
    pub calls: std::sync::Mutex<Vec<Value>>,
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
        let mut claims = json!({
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
        }).as_object().unwrap().clone();
        // JavaScript omits undefined issuance context in the recorded claim.
        if serde_json::to_value(input.grant_type)?.is_null() {
            let _ = claims[&format!("extension_{}", self.id)]
                .as_object_mut()
                .unwrap()
                .remove("grant");
        }
        if let Some(live) = &self.live {
            live.calls.lock().unwrap().push(json!({
                "extension": self.id,
                "grant": input.grant_type,
                "sessionId": input.params.session_id,
                "userId": input.params.user.as_ref().map(|user| &user.id),
                "clientId": input.params.client.client_id,
                "referenceId": input.params.reference_id,
                "scopes": input.params.scopes,
                "resources": input.params.resources,
                "metadata": input.metadata,
            }));
            claims.extend(
                json!({
                    "live_value": *live.value.lock().unwrap(),
                    "active": false, "azp": "forged", "client_id": "forged",
                    "token_type": "forged", "iat": 1, "jti": "forged",
                    "cnf": {"jkt":"forged"}, "auth_time": 1, "acr": "forged", "amr": ["forged"],
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        Ok(claims)
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
    extensions_with_live(None)
}

pub(super) fn extensions_with_live(
    live: Option<std::sync::Arc<LiveAccessClaims>>,
) -> Vec<std::sync::Arc<alibi::plugins::OAuthProviderExtension>> {
    ["first", "second"]
        .into_iter()
        .map(|id| {
            std::sync::Arc::new(alibi::plugins::OAuthProviderExtension {
                claims: alibi::plugins::OAuthExtensionClaims {
                    access_token: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "access",
                        live: live.clone(),
                    })),
                    id_token: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "id",
                        live: None,
                    })),
                    user_info: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "userinfo",
                        live: None,
                    })),
                },
                ..Default::default()
            })
        })
        .collect()
}
