//! Start SP-initiated logout from the real authenticated SAML session.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SsoPlugin, Value, json,
};
use alibi_core::{AuthUser, session::SessionRequest};
use base64::Engine as _;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use std::io::Write as _;
impl SsoPlugin {
    pub fn initiate_slo_endpoint(
        provider_id: &str,
        body: &Value,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "initiateSLO")
            .with_params(&json!({"providerId":provider_id}))?
            .with_body(body)
    }
    pub(super) async fn initiate_logout<S: AuthSchema>(
        &self,
        provider_id: &str,
        body: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, session) = crate::helpers::ordinary_session(request, ctx).await?;
        if !self.config.saml_enable_single_logout {
            return Err(error(
                400,
                "SINGLE_LOGOUT_NOT_ENABLED",
                "Single Logout is not enabled",
            ));
        }
        let provider = ctx
            .database
            .get_sso_provider(provider_id)
            .await?
            .ok_or_else(|| error(404, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found"))?;
        let config = provider
            .saml_config
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|value| !value.is_null())
            .ok_or_else(|| error(404, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found"))?;
        let services = config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("singleLogoutService"))
            .and_then(Value::as_array)
            .filter(|services| !services.is_empty())
            .ok_or_else(|| {
                error(
                    400,
                    "IDP_SLO_NOT_SUPPORTED",
                    "IdP does not support Single Logout Service",
                )
            })?;
        let destination = services
            .iter()
            .find(|service| {
                service.get("Binding").and_then(Value::as_str)
                    == Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            })
            .and_then(|service| service.get("Location"))
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("ERR_NO_REDIRECT_SLO_ENDPOINT"))?;
        let lookup = format!("saml-session-by-id:{}", session.id);
        let stored_lookup = ctx.verifications().find(&lookup).await?;
        let key = stored_lookup
            .as_ref()
            .map(|row| row.value())
            .transpose()?
            .map(str::to_owned);
        let stored = if let Some(key) = key.as_deref() {
            ctx.verifications().find(key).await?
        } else {
            None
        };
        let data = stored
            .as_ref()
            .and_then(|row| row.value().ok())
            .and_then(|value| serde_json::from_str::<Value>(value).ok());
        let name = data
            .as_ref()
            .and_then(|data| data.get("nameID"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .or_else(|| user.email())
            .unwrap_or_default();
        let index = data
            .as_ref()
            .and_then(|data| data.get("sessionIndex"))
            .and_then(Value::as_str);
        let entity = config
            .get("spMetadata")
            .and_then(|metadata| metadata.get("entityID"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .or_else(|| config.get("issuer").and_then(Value::as_str))
            .unwrap_or(&provider.issuer);
        let format = config
            .get("identifierFormat")
            .and_then(Value::as_str)
            .filter(|format| !format.is_empty())
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        let id = format!("_{}", uuid::Uuid::new_v4());
        let instant = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut writer = Writer::new(Vec::new());
        let mut root = BytesStart::new("samlp:LogoutRequest");
        _ = root.extend_attributes([
            ("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"),
            ("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
            ("ID", id.as_str()),
            ("Version", "2.0"),
            ("IssueInstant", instant.as_str()),
            ("Destination", destination),
        ]);
        let mut name_id = BytesStart::new("saml:NameID");
        name_id.push_attribute(("Format", format));
        for event in [
            Event::Start(root),
            Event::Start(BytesStart::new("saml:Issuer")),
            Event::Text(BytesText::new(entity)),
            Event::End(BytesEnd::new("saml:Issuer")),
            Event::Start(name_id),
            Event::Text(BytesText::new(name)),
            Event::End(BytesEnd::new("saml:NameID")),
        ] {
            writer
                .write_event(event)
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        if let Some(index) = index {
            for event in [
                Event::Start(BytesStart::new("samlp:SessionIndex")),
                Event::Text(BytesText::new(index)),
                Event::End(BytesEnd::new("samlp:SessionIndex")),
            ] {
                writer
                    .write_event(event)
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
        writer
            .write_event(Event::End(BytesEnd::new("samlp:LogoutRequest")))
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&writer.into_inner())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            encoder
                .finish()
                .map_err(|error| AuthError::internal(error.to_string()))?,
        );
        let default_callback = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let callback = body
            .get("callbackURL")
            .and_then(JsValue::as_str)
            .filter(|url| !url.is_empty())
            .unwrap_or(&default_callback);
        let query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            _ = query
                .append_pair("SAMLRequest", &encoded)
                .append_pair("RelayState", callback);
            query.finish()
        };
        let separator = if url::Url::parse(destination)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .query()
            .is_some_and(|query| !query.is_empty())
        {
            "&"
        } else {
            "?"
        };
        let location = format!("{destination}{separator}{query}");
        let expires_at = chrono::Utc::now()
            .checked_add_signed(self.config.saml_logout_request_ttl)
            .ok_or_else(|| AuthError::internal("Logout deadline overflow"))?;
        _ = ctx
            .verifications()
            .create(alibi_core::CreateVerification {
                identifier: format!("saml-logout-request:{id}"),
                value: provider_id.into(),
                expires_at,
            })
            .await?;
        if let Some(key) = key
            && let Err(error) = ctx.verifications().delete(&key).await
        {
            tracing::warn!(%error,"Failed to delete SAML session key during logout");
        }
        if let Err(error) = ctx.verifications().delete(&lookup).await {
            tracing::warn!(%error,"Failed to delete SAML session lookup during logout");
        }
        ctx.database.delete_session(&session.token).await?;
        let mut response = crate::authentication_helpers::redirect(&location);
        for cookie in crate::helpers::delete_session_cookie_headers(&ctx.config)? {
            response.headers.append("Set-Cookie", cookie);
        }
        Ok(EndpointResponse::from_http_response(response))
    }
}
fn error(status: u16, code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status,
        code: Some(code.into()),
        message: message.into(),
    }
}
pub(super) fn validate(input: Option<&JsValue>) -> AuthResult<JsValue> {
    crate::endpoint::validate_fields(
        input,
        "body",
        &[crate::authentication_helpers::JsonField::string(
            "callbackURL",
            false,
        )],
    )
}
