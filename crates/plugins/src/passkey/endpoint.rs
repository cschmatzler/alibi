//! Public server operations over the shared passkey engines.
use super::{PasskeyHandlerOutcome, PasskeyPlugin, delete_passkey_core, list_user_passkeys_core};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde_json::Value;

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
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

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: if call.operation_id() == "deletePasskey" {
            Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[crate::authentication_helpers::JsonField::string("id", true)],
            )?)
        } else {
            call.body().cloned()
        },
        query: call.query().cloned(),
    })
}

impl PasskeyPlugin {
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
