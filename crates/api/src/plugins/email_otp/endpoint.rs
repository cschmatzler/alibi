use super::{EmailOtpPlugin, EmailOtpType};
use crate::plugins::authentication_helpers::{JsonField, JsonFieldKind};
use crate::plugins::endpoint::{definition, validate_fields};
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
    if call.operation_id() == "createEmailVerificationOTP" {
        Ok(EndpointInput {
            body: Some(validate_fields(call.body(), "body", FIELDS)?),
            query: call.query().cloned(),
        })
    } else {
        Ok(EndpointInput {
            body: call.body().cloned(),
            query: Some(validate_fields(call.query(), "query", FIELDS)?),
        })
    }
}

impl EmailOtpPlugin {
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
