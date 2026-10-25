//! Resume provider-issued authorization state after an authenticated interaction.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use serde_json::{Value, json};
#[derive(serde::Deserialize)]
pub(super) struct ContinuationInput {
    selected: Option<bool>,
    created: Option<bool>,
    #[serde(rename = "postLogin")]
    post_login: Option<bool>,
    oauth_query: Option<String>,
}
pub(super) fn validate(input: Option<&JsValue>) -> AuthResult<JsValue> {
    use crate::authentication_helpers::{JsonField, JsonFieldKind};
    crate::endpoint::validate_fields(
        input,
        "body",
        &[
            JsonField {
                name: "selected",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
            JsonField {
                name: "created",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
            JsonField {
                name: "postLogin",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
            JsonField::string("oauth_query", false),
        ],
    )
}
pub(super) fn interaction_query(supplied: &str) -> serde_json::Map<String, Value> {
    let mut query = serde_json::Map::new();
    for (key, value) in url::form_urlencoded::parse(supplied.as_bytes()) {
        if ["sig", "exp", "ba_iat", "ba_pl"].contains(&key.as_ref()) {
            continue;
        }
        match query.entry(key.into_owned()) {
            serde_json::map::Entry::Vacant(entry) => {
                _ = entry.insert(json!(value));
            }
            serde_json::map::Entry::Occupied(mut entry) => {
                let previous = entry.get().clone();
                if let Some(values) = entry.get_mut().as_array_mut() {
                    values.push(json!(value));
                } else {
                    _ = entry.insert(json!([previous, value]));
                }
            }
        }
    }
    query
}
// Read only after signature admission. Never accept a clearance flag from the
// ordinary authorization query or from selected/created continuation branches.
pub(super) fn post_login_clearance(supplied: &str) -> Option<String> {
    url::form_urlencoded::parse(supplied.as_bytes())
        .find(|(key, _)| key == "ba_pl")
        .map(|(_, value)| value.into_owned())
}
impl OAuthProviderPlugin {
    /// Resume a signed OAuth request after account selection, registration or post-login interaction.
    pub fn oauth2_continue_endpoint(
        input: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Continue").with_body(input)
    }
    pub(super) async fn continue_authorization<S: AuthSchema>(
        &self,
        input: ContinuationInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let supplied = input.oauth_query.as_deref().unwrap_or("");
        if !supplied.is_empty()
            && !super::authorization::verify_authorization_query(
                supplied,
                ctx.config.current_secret(),
            )?
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 400,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"invalid_signature"}"#,
            )?));
        }
        _ = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        let remove = if input.selected == Some(true) {
            Some("select_account")
        } else if input.created == Some(true) {
            Some("create")
        } else if input.post_login == Some(true) {
            None
        } else {
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                "Missing parameters",
            );
        };
        if supplied.is_empty() {
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                "missing oauth query",
            );
        }
        let mut query = interaction_query(supplied);
        let clearance = if remove.is_none() {
            post_login_clearance(supplied)
        } else {
            None
        };
        if let Some(remove) = remove
            && let Some(prompt) = query.get("prompt").and_then(Value::as_str)
        {
            let mut prompts = prompt.split(' ').collect::<Vec<_>>();
            if let Some(index) = prompts.iter().position(|prompt| *prompt == remove) {
                _ = prompts.remove(index);
                if prompts.is_empty() {
                    _ = query.remove("prompt");
                } else {
                    _ = query.insert("prompt".into(), json!(prompts.join(" ")));
                }
            }
        }
        Box::pin(self.resume_authorization(query, req, ctx, clearance, remove.is_none())).await
    }
}
