use super::{
    BackupOperationError, EnableTwoFactorInput, TwoFactorEnabled, TwoFactorMethod, TwoFactorPlugin,
    enable_core,
};
use crate::authentication_helpers::JsonField;
use crate::endpoint::{definition, validate_fields};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCodesOutput {
    pub status: bool,
    pub backup_codes: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct TotpOutput {
    pub code: String,
}

/// The caller's factor was disabled and its current session replaced.
#[derive(Debug, Deserialize)]
pub struct TwoFactorDisabled {
    pub status: bool,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "disableTwoFactor",
            "disableTwoFactor",
            Some("/two-factor/disable"),
            HttpMethod::Post,
        ),
        definition(
            "enableTwoFactor",
            "enableTwoFactor",
            Some("/two-factor/enable"),
            HttpMethod::Post,
        ),
        definition("viewBackupCodes", "viewBackupCodes", None, HttpMethod::Post),
        definition("generateTOTP", "generateTOTP", None, HttpMethod::Post),
    ]
}

pub(super) fn validate(call: &EndpointCall, allow_passwordless: bool) -> AuthResult<EndpointInput> {
    if call.operation_id() == "disableTwoFactor" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[JsonField::string("password", !allow_passwordless)],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "enableTwoFactor" {
        let mut body = validate_fields(
            call.body(),
            "body",
            &[
                JsonField::string("password", !allow_passwordless),
                JsonField {
                    name: "method",
                    kind: crate::authentication_helpers::JsonFieldKind::OneOf(&["otp", "totp"]),
                    required: false,
                },
                JsonField::string("issuer", false),
            ],
        )?;
        if let JsValue::Object(object) = &mut body {
            _ = object
                .entry("method".into())
                .or_insert_with(|| JsValue::String("totp".into()));
        }
        return Ok(EndpointInput {
            body: Some(body),
            query: call.query().cloned(),
        });
    }
    let field = if call.operation_id() == "viewBackupCodes" {
        "userId"
    } else {
        "secret"
    };
    let mut body = call.body().cloned();
    if field == "userId"
        && let Some(JsValue::Object(body)) = &mut body
    {
        let user_id = body
            .get(field)
            .map_or_else(|| Ok("undefined".into()), JsValue::coerce_string)
            .map_err(crate::endpoint::validation)?;
        _ = body.insert(field.into(), JsValue::String(user_id));
    }
    Ok(EndpointInput {
        body: Some(validate_fields(
            body.as_ref(),
            "body",
            &[JsonField::string(field, true)],
        )?),
        query: call.query().cloned(),
    })
}

impl TwoFactorPlugin {
    /// Disable the persistent session owner's factor and rotate that session.
    #[must_use]
    pub fn disable_two_factor_endpoint(
        input: super::DisableTwoFactorInput,
    ) -> ServerEndpoint<TwoFactorDisabled> {
        let body = input
            .password
            .map(|password| ("password".into(), JsValue::String(password)))
            .into_iter()
            .collect();
        ServerEndpoint::new("two-factor", "disableTwoFactor").with_body_value(JsValue::Object(body))
    }

    async fn disable_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let output = self.disable_factor(&call.body_as()?, call, ctx).await?;
        let mut response = EndpointResponse::json(
            &alibi_core::utils::json::from_slice::<JsValue>(&output.body)?,
        )?;
        response.merge_headers(output.headers);
        Ok(response)
    }

    /// Enroll the signed-in owner using the configured factor and backup-code policies.
    #[must_use]
    pub fn enable_two_factor_endpoint(
        input: EnableTwoFactorInput,
    ) -> ServerEndpoint<TwoFactorEnabled> {
        let mut body = [(
            "method".into(),
            JsValue::String(
                match input.method {
                    TwoFactorMethod::Otp => "otp",
                    TwoFactorMethod::Totp => "totp",
                }
                .into(),
            ),
        )]
        .into_iter()
        .collect::<indexmap::IndexMap<_, _>>();
        if let Some(password) = input.password {
            _ = body.insert("password".into(), JsValue::String(password));
        }
        if let Some(issuer) = input.issuer {
            _ = body.insert("issuer".into(), JsValue::String(issuer));
        }
        ServerEndpoint::new("two-factor", "enableTwoFactor").with_body_value(JsValue::Object(body))
    }

    async fn enable_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let (user, session) = crate::helpers::ordinary_session(call, ctx).await?;
        match enable_core(&call.body_as()?, &user, &session, &self.config, ctx).await {
            Ok((value, cookies)) => {
                let mut response = EndpointResponse::json(&value)?;
                for cookie in cookies {
                    response = response.with_header("set-cookie", cookie);
                }
                Ok(response)
            }
            Err(
                BackupOperationError::Auth(alibi_core::AuthError::SessionCreationCancelled)
                | BackupOperationError::InvalidGeneration,
            ) => Ok(EndpointResponse::error(alibi_core::AuthError::Api {
                status: 500,
                code: None,
                message: String::new(),
            })
            .without_error_body()),
            Err(BackupOperationError::Auth(error)) => Err(error),
        }
    }

    /// Read trusted server-only backup codes through installed endpoint hooks.
    #[must_use]
    pub fn view_backup_codes_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<BackupCodesOutput> {
        ServerEndpoint::new("two-factor", "viewBackupCodes")
            .with_body_value(single_input("userId", user_id.into()))
    }

    /// Generate a TOTP through installed endpoint hooks and current configured policy.
    #[must_use]
    pub fn generate_totp_endpoint(secret: impl Into<String>) -> ServerEndpoint<TotpOutput> {
        ServerEndpoint::new("two-factor", "generateTOTP")
            .with_body_value(single_input("secret", secret.into()))
    }

    pub(super) async fn call_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "disableTwoFactor" {
            self.disable_endpoint(call, ctx).await
        } else if call.operation_id() == "enableTwoFactor" {
            self.enable_endpoint(call, ctx).await
        } else if call.operation_id() == "viewBackupCodes" {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Body {
                user_id: String,
            }
            let body: Body = call.body_as()?;
            EndpointResponse::json(
                &serde_json::json!({"status":true,"backupCodes":self.view_backup_codes(&body.user_id,ctx).await?}),
            )
        } else {
            #[derive(Deserialize)]
            struct Body {
                secret: String,
            }
            let body: Body = call.body_as()?;
            EndpointResponse::json(&serde_json::json!({"code":self.generate_totp(&body.secret)?}))
        }
    }
}

fn single_input(name: &str, value: String) -> JsValue {
    JsValue::Object(
        [(name.into(), JsValue::String(value))]
            .into_iter()
            .collect(),
    )
}
