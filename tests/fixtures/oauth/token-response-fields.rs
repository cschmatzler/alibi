use alibi::plugins::OAuthTokenClaimsInput;
use serde_json::{Map, Value, json};

#[derive(Debug, Default)]
pub(crate) struct TokenResponseFields {
    pub mode: std::sync::Mutex<String>,
    pub calls: std::sync::Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenClaimsContributor for TokenResponseFields {
    async fn contribute(
        &self,
        input: OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        self.calls.lock().unwrap().push(json!({
            "grant":input.grant_type,
            "userId":input.params.user.as_ref().map(|user| &user.id),
            "email":input.params.user.as_ref().map(|user| &user.email),
            "scopes":input.params.scopes,
            "metadata":input.metadata,
            "verification":input.params.verification_value.as_ref().map(|value|json!({
                "type":value["type"],"userId":value["userId"],"sessionId":value["sessionId"],
                "scope":value["query"]["scope"],"state":value["query"]["state"],
                "clientId":value["query"]["client_id"],"challenge":value["query"]["code_challenge"],
            })),
        }));
        match self.mode.lock().unwrap().as_str() {
            "ordinary" => return Err(alibi::AuthError::internal("private response failure")),
            "api" => {
                return Err(alibi::AuthError::Api {
                    status: 422,
                    code: Some("RESPONSE_REJECTED".into()),
                    message: "Operator response denied".into(),
                });
            }
            _ => {}
        }
        Ok(json!({
            "application_metadata":{"service":"billing","plan":"pro"},
            "per_request":"global", "nullable":null,
            "toString":"application-toString", "__proto__":{"applicationPrototype":true},
            "access_token":"forged", "refresh_token":"forged", "id_token":"forged",
            "expires_in":1,"expires_at":1,"token_type":"forged","scope":"forged",
        })
        .as_object()
        .unwrap()
        .clone())
    }
}
