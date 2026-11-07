//! Public server operations over the shared passkey engines.
use super::{
    PasskeyHandlerOutcome, PasskeyPlugin, delete_passkey_core, list_user_passkeys_core,
    update_passkey_core,
};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde_json::Value;

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        crate::endpoint::definition(
            "verifyPasskeyAuthentication",
            "passkeyVerifyAuthentication",
            Some("/passkey/verify-authentication"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "verifyPasskeyRegistration",
            "passkeyVerifyRegistration",
            Some("/passkey/verify-registration"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "generatePasskeyAuthenticationOptions",
            "passkeyGenerateAuthenticateOptions",
            Some("/passkey/generate-authenticate-options"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "generatePasskeyRegistrationOptions",
            "generatePasskeyRegistrationOptions",
            Some("/passkey/generate-register-options"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "updatePasskey",
            "updatePasskey",
            Some("/passkey/update-passkey"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "listPasskeys",
            "listPasskeys",
            Some("/passkey/list-user-passkeys"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "deletePasskey",
            "deletePasskey",
            Some("/passkey/delete-passkey"),
            HttpMethod::Post,
        ),
    ]
}

/// The caller's registered credential was deleted.
#[derive(Debug, serde::Deserialize)]
pub struct PasskeyDeleted {
    pub status: bool,
}

/// A credential after its owner changed its display name.
#[derive(Debug, serde::Deserialize)]
pub struct PasskeyUpdated {
    pub passkey: alibi_core::utils::json::JsValue,
}

/// Authenticator response and optional registration preferences.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationInput {
    pub response: alibi_core::utils::json::JsValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<alibi_core::utils::json::JsString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_session: Option<bool>,
}

fn registration_input(call: &EndpointCall) -> AuthResult<alibi_core::utils::json::JsValue> {
    use crate::authentication_helpers::{JsonField, JsonFieldKind, field_issue, json_type};
    use alibi_core::utils::json::JsValue;
    let Some(object) = call.body().and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[body] Invalid input: expected object, received {}",
            json_type(call.body())
        )));
    };
    let mut issues = Vec::new();
    if !object.contains_key("response") {
        issues.push(
            "[body.response] Invalid input: expected nonoptional, received undefined".to_owned(),
        );
    }
    for field in [
        JsonField::string("name", false),
        JsonField {
            name: "createSession",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ] {
        if let Some(value) = object.get(field.name)
            && !value.is_undefined()
            && let Some(issue) = field_issue(field.kind, Some(value), json_type(Some(value)))
        {
            issues.push(format!("[body.{}] {issue}", field.name));
        }
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    Ok(JsValue::Object(
        ["response", "name", "createSession"]
            .into_iter()
            .filter_map(|name| {
                object.get(name).map(|value| {
                    let value = if name == "name" {
                        trim_name_value(value)
                    } else {
                        value.clone()
                    };
                    (name.into(), value)
                })
            })
            .collect(),
    ))
}

fn trim_name_value(value: &alibi_core::utils::json::JsValue) -> alibi_core::utils::json::JsValue {
    use alibi_core::utils::json::JsValue;
    match value {
        JsValue::String(name) => {
            JsValue::String(name.trim_matches(super::registration::is_name_whitespace))
        }
        value => value.clone(),
    }
}

/// The issued session and credential owner's public user projection.
#[derive(Debug, serde::Deserialize)]
pub struct PasskeyAuthenticated {
    pub session: Value,
    pub user: Value,
}

fn verification_response(output: alibi_core::AuthResponse) -> AuthResult<EndpointResponse> {
    let body =
        alibi_core::utils::json::from_slice::<alibi_core::utils::json::JsValue>(&output.body).ok();
    let mut response = if output.status >= 400 {
        let response = EndpointResponse::error(crate::endpoint::error_response(output.clone()));
        if let Some(body) = body {
            response.with_error_body(body)
        } else {
            response.without_error_body()
        }
    } else {
        EndpointResponse::json(&body)?
    };
    response.merge_headers(output.headers);
    Ok(response)
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: if call.operation_id() == "passkeyVerifyAuthentication" {
            Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[crate::authentication_helpers::JsonField {
                    name: "response",
                    kind: crate::authentication_helpers::JsonFieldKind::Record,
                    required: true,
                }],
            )?)
        } else if call.operation_id() == "passkeyVerifyRegistration" {
            Some(registration_input(call)?)
        } else if call.operation_id() == "deletePasskey" {
            Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[crate::authentication_helpers::JsonField::string("id", true)],
            )?)
        } else if call.operation_id() == "updatePasskey" {
            let body = crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[
                    crate::authentication_helpers::JsonField::string("id", true),
                    crate::authentication_helpers::JsonField::string("name", true),
                ],
            )?;
            let name = trim_name_value(&body["name"]);
            if name
                .as_js_string()
                .is_some_and(alibi_core::utils::json::JsString::is_empty)
            {
                return Err(crate::endpoint::validation(
                    "[body.name] Too small: expected string to have >=1 characters",
                ));
            }
            Some(alibi_core::utils::json::JsValue::Object(
                [("id".into(), body["id"].clone()), ("name".into(), name)].into(),
            ))
        } else {
            call.body().cloned()
        },
        query: if call.operation_id() == "generatePasskeyRegistrationOptions" {
            call.query()
                .map(|query| {
                    crate::endpoint::validate_fields(
                        Some(query),
                        "query",
                        &[
                            crate::authentication_helpers::JsonField {
                                name: "authenticatorAttachment",
                                kind: crate::authentication_helpers::JsonFieldKind::OneOf(&[
                                    "platform",
                                    "cross-platform",
                                ]),
                                required: false,
                            },
                            crate::authentication_helpers::JsonField::string("name", false),
                            crate::authentication_helpers::JsonField::string("context", false),
                        ],
                    )
                })
                .transpose()?
        } else {
            call.query().cloned()
        },
    })
}

impl PasskeyPlugin {
    /// Verify a signed authentication response and issue its credential owner's session.
    #[must_use]
    pub fn verify_passkey_authentication_endpoint(
        response: alibi_core::utils::json::JsValue,
    ) -> ServerEndpoint<PasskeyAuthenticated> {
        ServerEndpoint::new("passkey", "verifyPasskeyAuthentication").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [("response".into(), response)].into_iter().collect(),
            ),
        )
    }

    pub(super) async fn verify_authentication_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        verification_response(
            self.verify_authentication(&call.body_as()?, call, ctx)
                .await?,
        )
    }

    /// Verify a real registration response against the issued challenge and owner.
    #[must_use]
    pub fn verify_passkey_registration_endpoint(
        input: PasskeyRegistrationInput,
    ) -> ServerEndpoint<alibi_core::utils::json::JsValue> {
        use alibi_core::utils::json::JsValue;
        let mut body = [("response".into(), input.response)]
            .into_iter()
            .collect::<indexmap::IndexMap<_, _>>();
        if let Some(name) = input.name {
            _ = body.insert("name".into(), JsValue::String(name.into()));
        }
        if let Some(create_session) = input.create_session {
            _ = body.insert("createSession".into(), JsValue::Bool(create_session));
        }
        ServerEndpoint::new("passkey", "verifyPasskeyRegistration")
            .with_body_value(JsValue::Object(body))
    }

    pub(super) async fn verify_registration_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let output = self
            .verify_registration(&call.body_as()?, call, ctx)
            .await
            .map_err(crate::helpers::unauthorized_if_unauthenticated)?;
        verification_response(output)
    }

    /// Issue an authentication challenge, optionally limiting browser hints to the signed owner.
    #[must_use]
    pub fn generate_passkey_authentication_options_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("passkey", "generatePasskeyAuthenticationOptions")
    }

    pub(super) async fn authentication_options_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let output = self.generate_authentication_options(call, ctx).await?;
        let mut response = EndpointResponse::json(&alibi_core::utils::json::from_slice::<
            alibi_core::utils::json::JsValue,
        >(&output.body)?)?;
        response.merge_headers(output.headers);
        Ok(response)
    }

    /// Generate a challenge for registering a credential under the current owner.
    #[must_use]
    pub fn generate_passkey_registration_options_endpoint()
    -> ServerEndpoint<alibi_core::utils::json::JsValue> {
        ServerEndpoint::new("passkey", "generatePasskeyRegistrationOptions")
    }

    pub(super) async fn registration_options_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let query = call
            .query()
            .and_then(alibi_core::utils::json::JsValue::as_object)
            .cloned()
            .unwrap_or_default();
        let output = self
            .generate_register_options(call, &query, ctx)
            .await
            .map_err(crate::helpers::unauthorized_if_unauthenticated)?;
        if output.status >= 400 {
            let headers = output.headers.clone();
            let mut response = EndpointResponse::error(crate::endpoint::error_response(output));
            response.merge_headers(headers);
            Ok(response)
        } else {
            let mut response = EndpointResponse::json(&alibi_core::utils::json::from_slice::<
                alibi_core::utils::json::JsValue,
            >(&output.body)?)?;
            response.merge_headers(output.headers);
            Ok(response)
        }
    }

    /// Rename a registered credential under its owner's signed session.
    #[must_use]
    pub fn update_passkey_endpoint(
        id: impl Into<String>,
        name: impl Into<alibi_core::utils::json::JsString>,
    ) -> ServerEndpoint<PasskeyUpdated> {
        ServerEndpoint::new("passkey", "updatePasskey").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [
                    (
                        "id".into(),
                        alibi_core::utils::json::JsValue::String(id.into().into()),
                    ),
                    (
                        "name".into(),
                        alibi_core::utils::json::JsValue::String(name.into()),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        )
    }

    pub(super) async fn update_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = crate::helpers::ordinary_session(call, ctx).await?;
        match update_passkey_core(&call.body_as()?, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(value) => EndpointResponse::json(&value),
            PasskeyHandlerOutcome::Response(output) => {
                let headers = output.headers.clone();
                let mut response = EndpointResponse::error(crate::endpoint::error_response(output));
                response.merge_headers(headers);
                Ok(response)
            }
        }
    }

    /// Delete a registered credential under its owner's signed session.
    #[must_use]
    pub fn delete_passkey_endpoint(id: impl Into<String>) -> ServerEndpoint<PasskeyDeleted> {
        ServerEndpoint::new("passkey", "deletePasskey").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [(
                    "id".into(),
                    alibi_core::utils::json::JsValue::String(id.into().into()),
                )]
                .into_iter()
                .collect(),
            ),
        )
    }

    pub(super) async fn delete_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = crate::helpers::ordinary_session(call, ctx).await?;
        match delete_passkey_core(&call.body_as()?, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(value) => EndpointResponse::json(&value),
            PasskeyHandlerOutcome::Response(output) => {
                let mut response = EndpointResponse::error(alibi_core::AuthError::Api {
                    status: output.status,
                    code: None,
                    message: String::new(),
                })
                .without_error_body();
                response.merge_headers(output.headers);
                Ok(response)
            }
        }
    }

    /// List the caller's registered credentials under its signed session.
    #[must_use]
    pub fn list_passkeys_endpoint() -> ServerEndpoint<Vec<alibi_core::utils::json::JsValue>> {
        ServerEndpoint::new("passkey", "listPasskeys")
    }

    pub(super) async fn list_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = crate::helpers::ordinary_session(call, ctx).await?;
        EndpointResponse::json(&list_user_passkeys_core(&user, ctx).await?)
    }
}
