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

/// Session token and public identity returned after authenticator verification.
#[derive(Debug, Deserialize)]
pub struct TotpVerified {
    pub token: String,
    pub user: serde_json::Value,
}

/// A code was persisted and handed to the configured delivery policy.
#[derive(Debug, Deserialize)]
pub struct TwoFactorOtpSent {
    pub status: bool,
}

/// Public recovery result, with a token only when session publication was requested.
#[derive(Debug, Deserialize)]
pub struct BackupCodeVerified {
    pub token: Option<String>,
    pub user: serde_json::Value,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "generateBackupCodes",
            "generateBackupCodes",
            Some("/two-factor/generate-backup-codes"),
            HttpMethod::Post,
        ),
        definition(
            "verifyBackupCode",
            "verifyBackupCode",
            Some("/two-factor/verify-backup-code"),
            HttpMethod::Post,
        ),
        definition(
            "verifyTwoFactorOTP",
            "verifyTwoFactorOTP",
            Some("/two-factor/verify-otp"),
            HttpMethod::Post,
        ),
        definition(
            "sendTwoFactorOTP",
            "sendTwoFactorOTP",
            Some("/two-factor/send-otp"),
            HttpMethod::Post,
        ),
        definition(
            "verifyTOTP",
            "verifyTOTP",
            Some("/two-factor/verify-totp"),
            HttpMethod::Post,
        ),
        definition(
            "getTOTPURI",
            "getTOTPURI",
            Some("/two-factor/get-totp-uri"),
            HttpMethod::Post,
        ),
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

pub(super) fn validate(
    call: &EndpointCall,
    config: &super::TwoFactorConfig,
) -> AuthResult<EndpointInput> {
    let allow_passwordless = config.allow_passwordless;
    if call.operation_id() == "verifyBackupCode" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[
                    JsonField::string("code", true),
                    JsonField {
                        name: "disableSession",
                        kind: crate::authentication_helpers::JsonFieldKind::Boolean,
                        required: false,
                    },
                    JsonField {
                        name: "trustDevice",
                        kind: crate::authentication_helpers::JsonFieldKind::Boolean,
                        required: false,
                    },
                ],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "sendTwoFactorOTP" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[JsonField {
                    name: "trustDevice",
                    kind: crate::authentication_helpers::JsonFieldKind::Boolean,
                    required: false,
                }],
            )?),
            query: call.query().cloned(),
        });
    }
    if matches!(call.operation_id(), "verifyTOTP" | "verifyTwoFactorOTP") {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[
                    JsonField::string("code", true),
                    JsonField {
                        name: "trustDevice",
                        kind: crate::authentication_helpers::JsonFieldKind::Boolean,
                        required: false,
                    },
                ],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "generateBackupCodes" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[JsonField::string(
                    "password",
                    !config
                        .backup_allow_passwordless
                        .unwrap_or(allow_passwordless),
                )],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "getTOTPURI" {
        return Ok(EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                &[JsonField::string(
                    "password",
                    !config.totp_allow_passwordless.unwrap_or(allow_passwordless),
                )],
            )?),
            query: call.query().cloned(),
        });
    }
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

fn verification_response(output: alibi_core::AuthResponse) -> AuthResult<EndpointResponse> {
    let body = alibi_core::utils::json::from_slice::<JsValue>(&output.body).ok();
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

impl TwoFactorPlugin {
    /// Replace the authenticated owner's recovery-code set.
    #[must_use]
    pub fn generate_backup_codes_endpoint(
        input: super::GenerateBackupCodesInput,
    ) -> ServerEndpoint<BackupCodesOutput> {
        let mut body = indexmap::IndexMap::new();
        if let Some(password) = input.password {
            _ = body.insert("password".into(), JsValue::String(password));
        }
        ServerEndpoint::new("two-factor", "generateBackupCodes")
            .with_body_value(JsValue::Object(body))
    }

    async fn generate_backup_endpoint_call(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(call, ctx)).await?;
        match Box::pin(super::generate_backup_codes_core(
            &call.body_as()?,
            &user,
            &self.config,
            ctx,
        ))
        .await
        {
            Ok(output) => EndpointResponse::json(&output),
            Err(BackupOperationError::InvalidGeneration) => Ok(EndpointResponse::error(
                alibi_core::AuthError::internal("Backup code generation failed"),
            )
            .without_error_body()),
            Err(BackupOperationError::Auth(error)) => Err(error),
        }
    }

    /// Consume a recovery code for the current owner or pending sign-in challenge.
    #[must_use]
    pub fn verify_backup_code_endpoint(
        input: super::VerifyBackupCodeInput,
    ) -> ServerEndpoint<BackupCodeVerified> {
        let mut body = [("code".into(), JsValue::String(input.code))]
            .into_iter()
            .collect::<indexmap::IndexMap<_, _>>();
        if let Some(disable_session) = input.disable_session {
            _ = body.insert("disableSession".into(), JsValue::Bool(disable_session));
        }
        if let Some(trust_device) = input.trust_device {
            _ = body.insert("trustDevice".into(), JsValue::Bool(trust_device));
        }
        ServerEndpoint::new("two-factor", "verifyBackupCode").with_body_value(JsValue::Object(body))
    }

    async fn verify_backup_endpoint_call(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        verification_response(self.verify_backup_code(&call.body_as()?, call, ctx).await?)
    }

    /// Verify a delivered code for the current session or pending sign-in challenge.
    #[must_use]
    pub fn verify_two_factor_otp_endpoint(
        input: super::VerifyOtpInput,
    ) -> ServerEndpoint<TotpVerified> {
        let mut body = [("code".into(), JsValue::String(input.code))]
            .into_iter()
            .collect::<indexmap::IndexMap<_, _>>();
        if let Some(trust_device) = input.trust_device {
            _ = body.insert("trustDevice".into(), JsValue::Bool(trust_device));
        }
        ServerEndpoint::new("two-factor", "verifyTwoFactorOTP")
            .with_body_value(JsValue::Object(body))
    }

    async fn verify_otp_endpoint_call(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        verification_response(self.verify_otp(&call.body_as()?, call, ctx).await?)
    }

    /// Persist and deliver a code for the session owner or pending sign-in challenge.
    #[must_use]
    pub fn send_two_factor_otp_endpoint() -> ServerEndpoint<TwoFactorOtpSent> {
        ServerEndpoint::new("two-factor", "sendTwoFactorOTP")
            .with_body_value(JsValue::Object(indexmap::IndexMap::new()))
    }

    async fn send_otp_endpoint_call(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let output = self.send_otp(call, ctx).await?;
        let mut response = if output.status >= 400 {
            EndpointResponse::error(crate::endpoint::error_response(output.clone()))
                .without_error_body()
        } else {
            EndpointResponse::json(&alibi_core::utils::json::from_slice::<JsValue>(
                &output.body,
            )?)?
        };
        response.merge_headers(output.headers);
        Ok(response)
    }

    /// Verify an authenticator code for enrollment or a pending sign-in challenge.
    #[must_use]
    pub fn verify_totp_endpoint(input: super::VerifyTotpInput) -> ServerEndpoint<TotpVerified> {
        let mut body = [("code".into(), JsValue::String(input.code))]
            .into_iter()
            .collect::<indexmap::IndexMap<_, _>>();
        if let Some(trust_device) = input.trust_device {
            _ = body.insert("trustDevice".into(), JsValue::Bool(trust_device));
        }
        ServerEndpoint::new("two-factor", "verifyTOTP").with_body_value(JsValue::Object(body))
    }

    async fn verify_totp_endpoint_call(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let output = self.verify_totp(&call.body_as()?, call, ctx).await?;
        verification_response(output)
    }

    /// Recover the signed-in owner's authenticator URI using configured password policy.
    #[must_use]
    pub fn get_totp_uri_endpoint(
        input: super::GetTotpUriInput,
    ) -> ServerEndpoint<super::TotpUriOutput> {
        let body = input
            .password
            .map(|password| ("password".into(), JsValue::String(password)))
            .into_iter()
            .collect();
        ServerEndpoint::new("two-factor", "getTOTPURI").with_body_value(JsValue::Object(body))
    }

    async fn uri_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = crate::helpers::ordinary_session(call, ctx).await?;
        EndpointResponse::json(
            &super::get_totp_uri_core(&call.body_as()?, &user, &self.config, ctx).await?,
        )
    }

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
        if call.operation_id() == "generateBackupCodes" {
            Box::pin(self.generate_backup_endpoint_call(call, ctx)).await
        } else if call.operation_id() == "verifyBackupCode" {
            Box::pin(self.verify_backup_endpoint_call(call, ctx)).await
        } else if call.operation_id() == "verifyTwoFactorOTP" {
            Box::pin(self.verify_otp_endpoint_call(call, ctx)).await
        } else if call.operation_id() == "sendTwoFactorOTP" {
            Box::pin(self.send_otp_endpoint_call(call, ctx)).await
        } else if call.operation_id() == "verifyTOTP" {
            Box::pin(self.verify_totp_endpoint_call(call, ctx)).await
        } else if call.operation_id() == "getTOTPURI" {
            Box::pin(self.uri_endpoint(call, ctx)).await
        } else if call.operation_id() == "disableTwoFactor" {
            Box::pin(self.disable_endpoint(call, ctx)).await
        } else if call.operation_id() == "enableTwoFactor" {
            Box::pin(self.enable_endpoint(call, ctx)).await
        } else if call.operation_id() == "viewBackupCodes" {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Body {
                user_id: String,
            }
            let body: Body = call.body_as()?;
            EndpointResponse::json(
                &serde_json::json!({"status":true,"backupCodes":Box::pin(self.view_backup_codes(&body.user_id,ctx)).await?}),
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
