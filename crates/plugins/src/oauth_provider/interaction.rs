use super::OAuthProviderPlugin;
use alibi_core::endpoint::{BeforeEndpointAction, EndpointCall, EndpointHook, EndpointResponse};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use async_trait::async_trait;

fn query_text(input: &JsValue) -> AuthResult<String> {
    let ordinary =
        |message: &str| AuthError::CallbackFailure(Box::new(AuthError::internal(message)));
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    match input {
        JsValue::Object(fields) => {
            for (name, value) in fields {
                _ = query.append_pair(name, &value.coerce_string().map_err(ordinary)?);
            }
        }
        JsValue::Array(entries) => {
            for entry in entries {
                let JsValue::Array(pair) = entry else {
                    return Err(ordinary(
                        "Each query pair must be an iterable [name, value] tuple",
                    ));
                };
                let [name, value] = pair.as_slice() else {
                    return Err(ordinary(
                        "Each query pair must be an iterable [name, value] tuple",
                    ));
                };
                _ = query.append_pair(
                    &name.coerce_string().map_err(ordinary)?,
                    &value.coerce_string().map_err(ordinary)?,
                );
            }
        }
        value => return value.coerce_string().map_err(ordinary),
    }
    Ok(query.finish())
}

pub(super) fn admit(input: Option<&JsValue>, secret: &str) -> AuthResult<Option<EndpointResponse>> {
    let Some(input) = input.filter(|value| value.is_truthy()) else {
        return Ok(None);
    };
    let query = query_text(input)?;
    if super::authorization::verify_authorization_query(&query, secret)? {
        return Ok(None);
    }
    Ok(Some(
        EndpointResponse::error(AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        })
        .with_error_body(alibi_core::utils::json::parse_value(
            r#"{"error":"invalid_signature"}"#,
        )?),
    ))
}

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for OAuthProviderPlugin {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call
            .body()
            .and_then(|body| body.get("oauth_query"))
            .is_some_and(JsValue::is_truthy))
    }
    async fn before(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        Ok(admit(
            call.body().and_then(|body| body.get("oauth_query")),
            ctx.config.current_secret(),
        )?
        .map(BeforeEndpointAction::Reject))
    }
}
