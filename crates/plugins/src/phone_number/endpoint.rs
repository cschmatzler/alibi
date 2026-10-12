//! Phone challenge delivery and consumption through installed logical endpoint dispatch.
use super::{
    PhoneNumberPlugin,
    types::{ResetRequest, SendRequest, SignInRequest},
};
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

/// The reset proof was consumed and the replacement credential was committed.
#[derive(Debug, Deserialize, Serialize)]
pub struct PhonePasswordResetResult {
    pub status: bool,
}

/// A credential session or the installed second-factor challenge.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PhoneSignInResponse {
    Session {
        token: String,
        user: Box<alibi_core::UserView>,
    },
    TwoFactor {
        #[serde(rename = "twoFactorRedirect")]
        two_factor_redirect: bool,
        #[serde(rename = "twoFactorMethods")]
        two_factor_methods: Vec<String>,
    },
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "signInPhoneNumber",
            "signInPhoneNumber",
            Some("/sign-in/phone-number"),
            HttpMethod::Post,
        ),
        definition(
            "resetPasswordPhoneNumber",
            "resetPasswordPhoneNumber",
            Some("/phone-number/reset-password"),
            HttpMethod::Post,
        ),
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
            match call.operation_id() {
                "consumePhoneNumberOTP" => CONSUME_FIELDS,
                "signInPhoneNumber" => {
                    <SignInRequest as crate::authentication_helpers::RequestBody>::FIELDS
                }
                "resetPasswordPhoneNumber" => {
                    <ResetRequest as crate::authentication_helpers::RequestBody>::FIELDS
                }
                _ => SEND_FIELDS,
            },
        )?),
        query: call.query().cloned(),
    })
}

impl PhoneNumberPlugin {
    /// Admit phone credentials and publish an owned session or second-factor challenge.
    ///
    /// # Errors
    /// Returns an error if the credential input cannot be serialized.
    pub fn sign_in_endpoint(
        input: &SignInRequest,
    ) -> AuthResult<ServerEndpoint<PhoneSignInResponse>> {
        ServerEndpoint::new("phone-number", "signInPhoneNumber").with_body(input)
    }

    /// Consume a reset challenge and commit a replacement password.
    ///
    /// # Errors
    /// Returns an error if the supplied request cannot be serialized.
    pub fn reset_password_endpoint(
        input: &ResetRequest,
    ) -> AuthResult<ServerEndpoint<PhonePasswordResetResult>> {
        ServerEndpoint::new("phone-number", "resetPasswordPhoneNumber").with_body(input)
    }

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
            let output = match call.operation_id() {
                "signInPhoneNumber" => self.sign_in_core(call, ctx, call.body_as()?).await?,
                "sendPhoneNumberOTP" => {
                    self.send_otp_core(ctx, call.request(), call.body_as::<SendRequest>()?)
                        .await?
                }
                "resetPasswordPhoneNumber" => {
                    self.reset_password_core(ctx, call.body_as()?).await?
                }
                _ => {
                    self.request_password_reset_core(
                        ctx,
                        call.request(),
                        call.body_as::<SendRequest>()?,
                    )
                    .await?
                }
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
