use super::{EmailOtpPlugin, EmailOtpType};
use crate::authentication_helpers::{JsonField, JsonFieldKind};
use crate::endpoint::{definition, validate_fields};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct EmailOtpRead {
    pub otp: Option<String>,
}

/// The sending operation acknowledges both delivery and concealed unknown mailboxes.
#[derive(Debug, Deserialize)]
pub struct EmailOtpSent {
    pub success: bool,
}

/// A successful check retains the proof and its current attempt count.
#[derive(Debug, Deserialize)]
pub struct EmailOtpCheck {
    pub success: bool,
}

/// A verified mailbox with optional newly issued browser authority.
#[derive(Debug, Deserialize)]
pub struct EmailOtpVerification {
    pub status: bool,
    pub token: Option<String>,
    pub user: Box<alibi_core::UserView>,
}

/// Sign-in credentials with schema-defined fields retained for new identities.
#[derive(Debug, Deserialize, serde::Serialize)]
pub struct EmailOtpSignInInput {
    pub email: String,
    pub otp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Authority published after consuming a sign-in proof.
#[derive(Debug, Deserialize)]
pub struct EmailOtpSignInResult {
    pub token: String,
    pub user: Box<alibi_core::UserView>,
}

/// Reset request aliases acknowledge delivered or concealed mailbox requests.
#[derive(Debug, Deserialize)]
pub struct EmailOtpResetRequested {
    pub success: bool,
}

const FIELDS: &[JsonField] = &[
    JsonField::string("email", true),
    JsonField {
        name: "type",
        kind: JsonFieldKind::OneOf(&[
            "email-verification",
            "sign-in",
            "forget-password",
            "change-email",
        ]),
        required: true,
    },
];

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "requestPasswordResetEmailOTP",
            "requestPasswordResetWithEmailOTP",
            Some("/email-otp/request-password-reset"),
            HttpMethod::Post,
        ),
        definition(
            "forgetPasswordEmailOTP",
            "forgetPasswordWithEmailOTP",
            Some("/forget-password/email-otp"),
            HttpMethod::Post,
        ),
        definition(
            "signInEmailOTP",
            "signInWithEmailOTP",
            Some("/sign-in/email-otp"),
            HttpMethod::Post,
        ),
        definition(
            "verifyEmailOTP",
            "verifyEmailOTP",
            Some("/email-otp/verify-email"),
            HttpMethod::Post,
        ),
        definition(
            "checkVerificationOTP",
            "verifyEmailWithOTP",
            Some("/email-otp/check-verification-otp"),
            HttpMethod::Post,
        ),
        definition(
            "sendVerificationOTP",
            "sendEmailVerificationOTP",
            Some("/email-otp/send-verification-otp"),
            HttpMethod::Post,
        ),
        definition(
            "createVerificationOTP",
            "createEmailVerificationOTP",
            None,
            HttpMethod::Post,
        ),
        definition(
            "getVerificationOTP",
            "getEmailVerificationOTP",
            None,
            HttpMethod::Get,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if matches!(
        call.operation_id(),
        "requestPasswordResetWithEmailOTP" | "forgetPasswordWithEmailOTP"
    ) {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                <super::types::EmailRequest as crate::authentication_helpers::RequestBody>::FIELDS,
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "signInWithEmailOTP" {
        let _ = validate_fields(
            call.body(),
            "body",
            <super::types::SignInRequest as crate::authentication_helpers::RequestBody>::FIELDS,
        )?;
        return Ok(EndpointInput {
            body: call.body().cloned(),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "verifyEmailOTP" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                <super::types::VerifyRequest as crate::authentication_helpers::RequestBody>::FIELDS,
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "verifyEmailWithOTP" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                <super::types::CheckRequest as crate::authentication_helpers::RequestBody>::FIELDS,
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "getEmailVerificationOTP" {
        Ok(EndpointInput {
            body: call.body().cloned(),
            query: Some(validate_fields(call.query(), "query", FIELDS)?),
        })
    } else {
        Ok(EndpointInput {
            body: Some(validate_fields(call.body(), "body", FIELDS)?),
            query: call.query().cloned(),
        })
    }
}

impl EmailOtpPlugin {
    /// Request a scoped reset proof without exposing whether the mailbox exists.
    #[must_use]
    pub fn request_password_reset_email_otp_endpoint(
        email: impl Into<String>,
    ) -> ServerEndpoint<EmailOtpResetRequested> {
        reset_request("requestPasswordResetEmailOTP", email.into())
    }
    /// Call the published deprecated reset-request alias.
    #[must_use]
    pub fn forget_password_email_otp_endpoint(
        email: impl Into<String>,
    ) -> ServerEndpoint<EmailOtpResetRequested> {
        reset_request("forgetPasswordEmailOTP", email.into())
    }

    /// Consume a sign-in proof and apply returning-user or signup policy.
    ///
    /// # Errors
    /// Returns an error if the supplied sign-in input cannot be serialized.
    pub fn sign_in_email_otp_endpoint(
        input: &EmailOtpSignInInput,
    ) -> AuthResult<ServerEndpoint<EmailOtpSignInResult>> {
        ServerEndpoint::new("email-otp", "signInEmailOTP").with_body(input)
    }

    /// Consume a mailbox proof and apply verification/session policy.
    #[must_use]
    pub fn verify_email_otp_endpoint(
        email: impl Into<String>,
        otp: impl Into<String>,
    ) -> ServerEndpoint<EmailOtpVerification> {
        ServerEndpoint::new("email-otp", "verifyEmailOTP").with_body_value(JsValue::Object(
            [
                ("email".into(), JsValue::String(email.into())),
                ("otp".into(), JsValue::String(otp.into())),
            ]
            .into_iter()
            .collect(),
        ))
    }

    /// Check a scoped proof without consuming a successful validation.
    #[must_use]
    pub fn check_verification_otp_endpoint(
        email: impl Into<String>,
        otp_type: EmailOtpType,
        otp: impl Into<String>,
    ) -> ServerEndpoint<EmailOtpCheck> {
        let mut body = input(email.into(), otp_type);
        if let JsValue::Object(fields) = &mut body {
            let _ = fields.insert("otp".into(), JsValue::String(otp.into()));
        }
        ServerEndpoint::new("email-otp", "checkVerificationOTP").with_body_value(body)
    }

    /// Send a scoped OTP through the installed delivery and storage policies.
    #[must_use]
    pub fn send_verification_otp_endpoint(
        email: impl Into<String>,
        otp_type: EmailOtpType,
    ) -> ServerEndpoint<EmailOtpSent> {
        ServerEndpoint::new("email-otp", "sendVerificationOTP")
            .with_body_value(input(email.into(), otp_type))
    }

    /// Create a code through the installed endpoint hooks and post-hook validation.
    #[must_use]
    pub fn create_verification_otp_endpoint(
        email: impl Into<String>,
        otp_type: EmailOtpType,
    ) -> ServerEndpoint<String> {
        ServerEndpoint::new("email-otp", "createVerificationOTP")
            .with_body_value(input(email.into(), otp_type))
    }

    /// Retrieve a code through the installed endpoint hooks.
    #[must_use]
    pub fn get_verification_otp_endpoint(
        email: impl Into<String>,
        otp_type: EmailOtpType,
    ) -> ServerEndpoint<EmailOtpRead> {
        ServerEndpoint::new("email-otp", "getVerificationOTP")
            .with_query_value(input(email.into(), otp_type))
    }

    pub(super) async fn call_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "verifyEmailWithOTP" {
            let output = self.check_verification_core(ctx, call.body_as()?).await?;
            return EndpointResponse::json(&alibi_core::utils::json::from_slice::<JsValue>(
                &output.body,
            )?);
        }
        if matches!(
            call.operation_id(),
            "sendEmailVerificationOTP"
                | "verifyEmailOTP"
                | "signInWithEmailOTP"
                | "requestPasswordResetWithEmailOTP"
                | "forgetPasswordWithEmailOTP"
        ) {
            if call.operation_id() == "sendEmailVerificationOTP"
                && let Some(request) = call.request()
            {
                alibi_core::middleware::CsrfMiddleware::new(
                    alibi_core::middleware::CsrfConfig::new(),
                    ctx.config.clone(),
                )
                .check_login_origin(request)?;
            }
            let output = match call.operation_id() {
                "sendEmailVerificationOTP" => {
                    self.send_verification_core(call.request(), ctx, call.body_as()?)
                        .await?
                }
                "signInWithEmailOTP" => {
                    let raw = call.body().cloned().unwrap_or(JsValue::Null);
                    let mut parsed = raw.clone();
                    if let JsValue::Object(fields) = &mut parsed {
                        let _ = fields.shift_remove("username");
                        let _ = fields.shift_remove("displayUsername");
                    }
                    let body = alibi_core::utils::json::from_value(parsed)?;
                    self.sign_in_core(call, ctx, body, raw).await?
                }
                "requestPasswordResetWithEmailOTP" | "forgetPasswordWithEmailOTP" => {
                    self.request_password_reset_core(call.request(), ctx, call.body_as()?)
                        .await?
                }
                _ => self.verify_email_core(call, ctx, call.body_as()?).await?,
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
        let (email, otp_type) = if call.operation_id() == "createEmailVerificationOTP" {
            let body: super::types::SendRequest = call.body_as()?;
            (body.email, body.otp_type)
        } else {
            let query: super::types::SendRequest = call.query_as()?;
            (query.email, query.otp_type)
        };
        if call.operation_id() == "createEmailVerificationOTP" {
            EndpointResponse::json(&self.create_verification_otp(ctx, &email, otp_type).await?)
        } else {
            EndpointResponse::json(
                &serde_json::json!({"otp": self.get_verification_otp(ctx, &email, otp_type).await?}),
            )
        }
    }
}

fn input(email: String, otp_type: EmailOtpType) -> JsValue {
    JsValue::Object(
        [
            ("email".into(), JsValue::String(email)),
            ("type".into(), JsValue::String(otp_type.as_str().into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn reset_request(name: &'static str, email: String) -> ServerEndpoint<EmailOtpResetRequested> {
    ServerEndpoint::new("email-otp", name).with_body_value(JsValue::Object(
        [("email".into(), JsValue::String(email))]
            .into_iter()
            .collect(),
    ))
}
