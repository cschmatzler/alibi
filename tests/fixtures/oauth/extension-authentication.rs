use alibi::endpoint::EndpointError;
use alibi::plugins::{OAuthClientAssertionInput, OAuthVerifiedClientAssertion};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;

pub(super) const METHOD: &str = "application_assertion";
pub(super) const ASSERTION: &str = "urn:fixture:client-assertion";
pub(super) const KEY: &str = "fixture-application-assertion-key";

#[derive(Debug)]
pub(super) struct ApplicationAssertion;
fn denied() -> EndpointError {
    EndpointError {
        error: alibi::AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        },
        headers: None,
        body: Some(Box::new(alibi::utils::json::JsValue::from(json!({
            "error":"invalid_client","error_description":"application assertion rejected"
        })))),
        body_absent: false,
    }
}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientAuthenticationStrategy for ApplicationAssertion {
    async fn authenticate(
        &self,
        input: OAuthClientAssertionInput<'_>,
    ) -> Result<OAuthVerifiedClientAssertion, EndpointError> {
        let (payload, signature) = input.assertion.split_once('.').ok_or_else(denied)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        let value: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| denied())?)
                .map_err(|_| denied())?;
        if value["audience"] != input.expected_audience
            || value.get("suppliedClientId").and_then(Value::as_str) != input.client_id
        {
            return Err(denied());
        }
        Ok(OAuthVerifiedClientAssertion {
            client_id: value["clientId"].as_str().ok_or_else(denied)?.into(),
            confirmation: value.get("confirmation").cloned(),
        })
    }
}
pub(super) fn extension(
    method: &str,
    assertion_types: Option<Vec<String>>,
) -> Arc<alibi::plugins::OAuthProviderExtension> {
    Arc::new(alibi::plugins::OAuthProviderExtension {
        client_authentication: [(
            method.into(),
            alibi::plugins::OAuthExtensionClientAuthentication {
                assertion_types,
                strategy: Arc::new(ApplicationAssertion),
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    })
}
pub(super) fn extensions() -> Vec<Arc<alibi::plugins::OAuthProviderExtension>> {
    vec![extension(
        METHOD,
        Some(vec![ASSERTION.into(), "urn:fixture:client-alias".into()]),
    )]
}
pub(super) fn proof(client_id: &str, audience: &str) -> String {
    let payload=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "clientId":client_id,"audience":audience,"confirmation":{"x5t#S256":"application-certificate"}
    })).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
