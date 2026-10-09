use super::TwoFactorPlugin;
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

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition("viewBackupCodes", "viewBackupCodes", None, HttpMethod::Post),
        definition("generateTOTP", "generateTOTP", None, HttpMethod::Post),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
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
        drop(body.insert(field.into(), JsValue::String(user_id)));
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
        if call.operation_id() == "viewBackupCodes" {
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
