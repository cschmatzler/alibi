//! A real application-owned request registry shared by native and HTTP fixtures.
use alibi::plugins::{OAuthRequestUriInput, OAuthRequestUriResolver};
use alibi::utils::json::JsValue;
use std::sync::Mutex;

#[derive(Debug)]
pub(crate) struct RequestRegistry {
    pub parameters: Mutex<JsValue>,
    pub calls: Mutex<Vec<serde_json::Value>>,
    pub redirect_calls: Mutex<Vec<serde_json::Value>>,
}
impl Default for RequestRegistry {
    fn default() -> Self {
        Self {
            parameters: Mutex::new(JsValue::Null),
            calls: Mutex::default(),
            redirect_calls: Mutex::default(),
        }
    }
}

#[async_trait::async_trait]
impl OAuthRequestUriResolver for RequestRegistry {
    async fn resolve(
        &self,
        input: OAuthRequestUriInput<'_>,
    ) -> alibi::AuthResult<Option<alibi::plugins::OAuthAuthorizationQuery>> {
        let endpoint = input.context.endpoint.as_ref().unwrap();
        let request = input.context.request.as_ref().unwrap();
        self.calls.lock().unwrap().push(serde_json::json!({
            "stage":"resolver",
            "requestUri":input.request_uri,"clientId":input.client_id,
            "path":endpoint.path(),"query":endpoint.query(),
            "requestURL":request.url(),"requestHeader":request.headers.get("x-request-uri"),
        }));
        match input.request_uri {
            "urn:fixture:valid" | "urn:fixture:nonfinite" | "urn:fixture:invalid-max-age" => {
                match self.parameters.lock().unwrap().clone() {
                    JsValue::Object(mut parameters) => {
                        if input.request_uri == "urn:fixture:nonfinite" {
                            _ = parameters
                                .insert("extension_scalar".into(), JsValue::Number(f64::INFINITY));
                            _ = parameters.insert(
                                "extension_array".into(),
                                JsValue::Array(vec![JsValue::Number(f64::NEG_INFINITY)]),
                            );
                        }
                        if input.request_uri == "urn:fixture:invalid-max-age" {
                            _ = parameters.insert("max_age".into(), JsValue::Number(f64::INFINITY));
                        }
                        Ok(Some(parameters))
                    }
                    _ => Ok(None),
                }
            }
            "urn:fixture:throw" => Err(alibi::AuthError::internal("private resolver failure")),
            "urn:fixture:api-error" => Err(alibi::AuthError::Api {
                status: 429,
                code: Some("REQUEST_LOOKUP_LIMIT".into()),
                message: "Request lookup limited".into(),
            }),
            _ => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthRedirectUriValidator for RequestRegistry {
    async fn validate(
        &self,
        uri: &str,
        registered: &[String],
        default_result: bool,
    ) -> alibi::AuthResult<bool> {
        self.redirect_calls.lock().unwrap().push(serde_json::json!({
            "uri":uri,"registered":registered,"defaultResult":default_result,
        }));
        Ok(default_result)
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for RequestRegistry {
    fn id(&self) -> &str {
        "request-registry"
    }
    fn matches(&self, client_id: &str) -> bool {
        client_id == "resolver-unknown"
    }
    async fn resolve(
        &self,
        context: &alibi::CallbackContext,
        client_id: &str,
        _: Option<alibi::store::OAuthClient>,
    ) -> alibi::AuthResult<Option<alibi::store::OAuthClient>> {
        let endpoint = context.endpoint.as_ref().unwrap();
        let request = context.request.as_ref().unwrap();
        self.calls.lock().unwrap().push(serde_json::json!({
            "stage":"discovery","clientId":client_id,"path":endpoint.path(),"query":endpoint.query(),
            "requestURL":request.url(),"requestHeader":request.headers.get("x-request-uri"),
        }));
        Ok(None)
    }
}
