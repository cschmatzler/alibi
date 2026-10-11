//! Server-only phone proof consumption through installed logical endpoint dispatch.
use super::PhoneNumberPlugin;
use crate::authentication_helpers::JsonField;
use crate::endpoint::{definition, validate_fields};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::{Deserialize, Serialize};

/// Successful proof consumption does not create an identity or session.
#[derive(Debug, Deserialize, Serialize)]
pub struct PhoneOtpConsumption {
    pub status: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumeInput {
    phone_number: String,
    code: String,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![definition(
        "consumePhoneNumberOTP",
        "consumePhoneNumberOTP",
        None,
        HttpMethod::Post,
    )]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: Some(validate_fields(
            call.body(),
            "body",
            &[
                JsonField::string("phoneNumber", true),
                JsonField::string("code", true),
            ],
        )?),
        query: call.query().cloned(),
    })
}

impl PhoneNumberPlugin {
    /// Consume an issued proof through installed endpoint hooks, without an HTTP request.
    #[must_use]
    pub fn consume_otp_endpoint(
        phone_number: impl Into<String>,
        code: impl Into<String>,
    ) -> ServerEndpoint<PhoneOtpConsumption> {
        ServerEndpoint::new("phone-number", "consumePhoneNumberOTP").with_body_value(
            JsValue::Object(
                [
                    ("phoneNumber".into(), JsValue::String(phone_number.into())),
                    ("code".into(), JsValue::String(code.into())),
                ]
                .into_iter()
                .collect(),
            ),
        )
    }

    pub(super) async fn call_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let body: ConsumeInput = call.body_as()?;
        self.verify_and_consume(ctx, call.request(), &body.phone_number, &body.code)
            .await?;
        EndpointResponse::json(&PhoneOtpConsumption { status: true })
    }
}
