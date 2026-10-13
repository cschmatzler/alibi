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
    pub passkey: Value,
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: if call.operation_id() == "deletePasskey" {
            Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[crate::authentication_helpers::JsonField::string("id", true)],
            )?)
        } else if call.operation_id() == "updatePasskey" {
            let mut body = crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[
                    crate::authentication_helpers::JsonField::string("id", true),
                    crate::authentication_helpers::JsonField::string("name", true),
                ],
            )?;
            let name = super::registration::trim_name(
                body.get("name")
                    .and_then(alibi_core::utils::json::JsValue::as_str)
                    .unwrap_or_default(),
            );
            if name.is_empty() {
                return Err(crate::endpoint::validation(
                    "[body.name] Too small: expected string to have >=1 characters",
                ));
            }
            let name = name.to_owned();
            if let alibi_core::utils::json::JsValue::Object(object) = &mut body {
                _ = object.insert(
                    "name".into(),
                    alibi_core::utils::json::JsValue::String(name),
                );
            }
            Some(body)
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
    pub fn generate_passkey_registration_options_endpoint() -> ServerEndpoint<Value> {
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
            .map(|object| {
                object
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|value| (name.clone(), value.to_owned()))
                    })
                    .collect()
            })
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
        name: impl Into<String>,
    ) -> ServerEndpoint<PasskeyUpdated> {
        ServerEndpoint::new("passkey", "updatePasskey").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [
                    (
                        "id".into(),
                        alibi_core::utils::json::JsValue::String(id.into()),
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
                    alibi_core::utils::json::JsValue::String(id.into()),
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
    pub fn list_passkeys_endpoint() -> ServerEndpoint<Vec<Value>> {
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
