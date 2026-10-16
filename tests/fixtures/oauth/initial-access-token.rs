use alibi::endpoint::EndpointError;
use alibi::plugins::{
    OAuthInitialAccessTokenAuthorization, OAuthInitialAccessTokenError,
    OAuthInitialAccessTokenInput, OAuthInitialAccessTokenValidator,
};
use serde_json::{Value, json};

#[derive(Debug, Default)]
pub(super) struct RegistrationPolicy {
    pub calls: std::sync::Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthInitialAccessTokenValidator for RegistrationPolicy {
    async fn validate(
        &self,
        input: OAuthInitialAccessTokenInput<'_>,
    ) -> Result<Option<OAuthInitialAccessTokenAuthorization>, OAuthInitialAccessTokenError> {
        self.calls.lock().unwrap().push(json!({
            "token": input.initial_access_token,
            "authorization": input.headers.get("authorization"),
            "caller": input.headers.get("x-registration-caller"),
            "clientMetadata": input.client_metadata,
        }));
        tokio::task::yield_now().await;
        match input.initial_access_token {
            "forbidden" => {
                Err::<(), _>(alibi::AuthError::forbidden("Operator forbids registration"))?;
                Ok(None)
            }
            "ordinary-error" => Err(alibi::AuthError::internal("private validator failure").into()),
            "api-error" => Err(EndpointError {
                error: alibi::AuthError::Api {
                    status: 429,
                    code: None,
                    message: String::new(),
                },
                headers: Some({
                    let mut headers = alibi::Headers::new();
                    _ = headers.insert("retry-after", "17");
                    _ = headers.insert("x-registration-policy", "limited");
                    headers
                }),
                body: Some(Box::new(alibi::utils::json::JsValue::from(
                    json!({"error":"slow_down","error_description":"Operator registration limit"}),
                ))),
                body_absent: false,
            }
            .into()),
            "api-empty" => Err(EndpointError {
                error: alibi::AuthError::Api {
                    status: 307,
                    code: None,
                    message: String::new(),
                },
                headers: Some({
                    let mut headers = alibi::Headers::new();
                    _ = headers.insert("location", "https://operator.fixture.test/register");
                    _ = headers.insert("content-type", "application/json");
                    headers
                }),
                body: None,
                body_absent: true,
            }
            .into()),
            token @ ("accepted" | "reference")
                if input
                    .headers
                    .get("x-registration-caller")
                    .map(String::as_str)
                    == Some("fixture")
                    && input
                        .client_metadata
                        .get("client_name")
                        .and_then(Value::as_str)
                        == Some("Token client") =>
            {
                Ok(Some(OAuthInitialAccessTokenAuthorization {
                    reference_id: (token == "reference").then(|| "registration-reference".into()),
                }))
            }
            _ => Ok(None),
        }
    }
}
