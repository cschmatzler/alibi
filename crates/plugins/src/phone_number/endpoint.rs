//! Phone challenge delivery and consumption through installed logical endpoint dispatch.
use super::{PhoneNumberPlugin, types::SendRequest};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PhoneOtpSent {
    pub message: String,
}

/// A reset challenge was issued without publishing browser authority.
#[derive(Debug, Deserialize, Serialize)]
pub struct PhonePasswordResetRequested {
    pub status: bool,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "requestPasswordResetPhoneNumber",
            "requestPasswordResetPhoneNumber",
            Some("/phone-number/request-password-reset"),
            HttpMethod::Post,
        ),
        definition(
            "sendPhoneNumberOTP",
            "sendPhoneNumberOTP",
            Some("/phone-number/send-otp"),
            HttpMethod::Post,
        ),
        definition(
            "consumePhoneNumberOTP",
            "consumePhoneNumberOTP",
            None,
            HttpMethod::Post,
        ),
    ]
}

const SEND_FIELDS: &[JsonField] = &[JsonField::string("phoneNumber", true)];
const CONSUME_FIELDS: &[JsonField] = &[
    JsonField::string("phoneNumber", true),
    JsonField::string("code", true),
];

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: Some(validate_fields(
            call.body(),
            "body",
            if call.operation_id() == "consumePhoneNumberOTP" {
                CONSUME_FIELDS
            } else {
                SEND_FIELDS
            },
        )?),
        query: call.query().cloned(),
    })
}

impl PhoneNumberPlugin {
    /// Issue a password reset challenge without requiring a browser session.
    #[must_use]
    pub fn request_password_reset_endpoint(
        phone_number: impl Into<String>,
    ) -> ServerEndpoint<PhonePasswordResetRequested> {
        ServerEndpoint::new("phone-number", "requestPasswordResetPhoneNumber").with_body_value(
            JsValue::Object(
                [("phoneNumber".into(), JsValue::String(phone_number.into()))]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    /// Send a phone challenge without requiring a browser request or session.
    #[must_use]
    pub fn send_otp_endpoint(phone_number: impl Into<String>) -> ServerEndpoint<PhoneOtpSent> {
        ServerEndpoint::new("phone-number", "sendPhoneNumberOTP").with_body_value(JsValue::Object(
            [("phoneNumber".into(), JsValue::String(phone_number.into()))]
                .into_iter()
                .collect(),
        ))
    }

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
        if call.operation_id() != "consumePhoneNumberOTP" {
            let body: SendRequest = call.body_as()?;
            let output = if call.operation_id() == "sendPhoneNumberOTP" {
                self.send_otp_core(ctx, call.request(), body).await?
            } else {
                self.request_password_reset_core(ctx, call.request(), body)
                    .await?
            };
            let mut response = if output.status >= 400 {
                EndpointResponse::error(crate::endpoint::error_response(output.clone()))
                    .without_error_body()
            } else {
                EndpointResponse::value(alibi_core::utils::json::from_slice(&output.body)?)
            };
            response.set_status(Some(output.status));
            response.merge_headers(output.headers);
            return Ok(response);
        }
        let body: ConsumeInput = call.body_as()?;
        self.verify_and_consume(ctx, call.request(), &body.phone_number, &body.code)
            .await?;
        EndpointResponse::json(&PhoneOtpConsumption { status: true })
    }
}
