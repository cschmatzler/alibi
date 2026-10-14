//! SAML HTTP-Redirect `AuthnRequest` issuance with correlated durable state.
use super::sign_in::{issue_state, provider_reference, random};
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, SsoPlugin, SsoProvider,
    Value, api, json,
};
use base64::Engine as _;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use rsa::{
    pkcs1::DecodeRsaPrivateKey as _,
    pkcs8::DecodePrivateKey as _,
    signature::{SignatureEncoding as _, Signer as _},
};
use std::io::Write as _;
impl SsoPlugin {
    pub(super) async fn saml_sign_in<S: AuthSchema>(
        &self,
        body: &Value,
        provider: &SsoProvider,
        config: &Value,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if body.get("additionalParams").is_some() {
            return Err(api(
                400,
                "additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters.",
            ));
        }
        let metadata = super::sp_metadata_xml::from_config(config)?;
        let signed = metadata.as_ref().map_or_else(
            || config.get("authnRequestsSigned") == Some(&json!(true)),
            |metadata| metadata.authn_requests_signed,
        );
        let private = config
            .get("spMetadata")
            .and_then(|metadata| metadata.get("privateKey"))
            .and_then(Value::as_str)
            .filter(|key| !key.is_empty())
            .or_else(|| {
                config
                    .get("privateKey")
                    .and_then(Value::as_str)
                    .filter(|key| !key.is_empty())
            });
        if signed && private.is_none() {
            return Err(api(
                400,
                "authnRequestsSigned is enabled but no privateKey provided in spMetadata or samlConfig",
            ));
        }
        let callback = body
            .get("callbackURL")
            .and_then(Value::as_str)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| api(400, "callbackURL is required"))?;
        let reference = provider_reference(provider, self.config.domain_verification)?;
        let state = random(32);
        let mut payload = crate::oauth::state::OAuthStatePayload::new(
            callback.into(),
            random(128),
            body.get("errorCallbackURL")
                .and_then(Value::as_str)
                .map(str::to_owned),
            body.get("newUserCallbackURL")
                .and_then(Value::as_str)
                .map(str::to_owned),
            None,
            body.get("requestSignUp").and_then(Value::as_bool),
            serde_json::Map::new(),
        );
        payload.server_context = Some(json!({"ssoProviderReference":reference}));
        _ = payload
            .additional_data
            .insert("oauthState".into(), json!(state));
        let cookie_name =
            alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, "relay_state");
        let cookie = issue_state(&payload, &state, &cookie_name, ctx).await?;
        if config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("metadata"))
            .and_then(Value::as_str)
            .is_some_and(|xml| !xml.is_empty())
        {
            return Err(AuthError::not_implemented(
                "SAML XML metadata authorization is not implemented",
            ));
        }
        let endpoint = if let Some(services) = config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("singleSignOnService"))
            .and_then(Value::as_array)
        {
            services
                .iter()
                .find(|service| {
                    service.get("Binding").and_then(Value::as_str)
                        == Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
                })
                .and_then(|service| service.get("Location"))
                .and_then(Value::as_str)
        } else {
            config.get("entryPoint").and_then(Value::as_str)
        }
        .ok_or_else(|| AuthError::internal("ERR_NO_REDIRECT_SSO_ENDPOINT"))?;
        let id = format!("_{}", uuid::Uuid::new_v4());
        let instant = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let entity = metadata
            .as_ref()
            .map(|metadata| metadata.entity_id.as_str())
            .or_else(|| {
                config
                    .get("spMetadata")
                    .and_then(|metadata| metadata.get("entityID"))
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .or_else(|| config.get("issuer").and_then(Value::as_str))
            })
            .unwrap_or(&provider.issuer);
        let name_id = metadata
            .as_ref()
            .and_then(|metadata| metadata.name_id_formats.first().map(String::as_str))
            .or_else(|| {
                config
                    .get("identifierFormat")
                    .and_then(Value::as_str)
                    .filter(|format| !format.is_empty())
            })
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        let acs = metadata
            .as_ref()
            .and_then(|metadata| metadata.post_services.last())
            .cloned()
            .unwrap_or_else(|| {
                format!(
                    "{}{}/sso/saml2/sp/acs/{}",
                    ctx.config.base_url.trim_end_matches('/'),
                    ctx.config.base_path.trim_end_matches('/'),
                    provider.provider_id
                )
            });
        let mut writer = Writer::new(Vec::new());
        let mut request = BytesStart::new("samlp:AuthnRequest");
        _ = request.extend_attributes([
            ("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"),
            ("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
            ("ID", id.as_str()),
            ("Version", "2.0"),
            ("IssueInstant", instant.as_str()),
            ("Destination", endpoint),
            (
                "ProtocolBinding",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            ),
            ("AssertionConsumerServiceURL", acs.as_str()),
        ]);
        let mut policy = BytesStart::new("samlp:NameIDPolicy");
        _ = policy.extend_attributes([("Format", name_id), ("AllowCreate", "true")]);
        for event in [
            Event::Start(request),
            Event::Start(BytesStart::new("saml:Issuer")),
            Event::Text(BytesText::new(entity)),
            Event::End(BytesEnd::new("saml:Issuer")),
            Event::Empty(policy),
            Event::End(BytesEnd::new("samlp:AuthnRequest")),
        ] {
            writer
                .write_event(event)
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&writer.into_inner())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let request = base64::engine::general_purpose::STANDARD.encode(
            encoder
                .finish()
                .map_err(|error| AuthError::internal(error.to_string()))?,
        );
        let encoded_query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            _ = query
                .append_pair("SAMLRequest", &request)
                .append_pair("RelayState", &state);
            if signed {
                _ = query.append_pair(
                    "SigAlg",
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                );
                let message = query.finish();
                let key = private
                    .ok_or_else(|| AuthError::internal("SAML private key missing"))?
                    .lines()
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join("\n");
                let key = rsa::RsaPrivateKey::from_pkcs8_pem(&key)
                    .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(&key))
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let signature = base64::engine::general_purpose::STANDARD.encode(
                    rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key)
                        .sign(message.as_bytes())
                        .to_vec(),
                );
                query = url::form_urlencoded::Serializer::new(message);
                _ = query.append_pair("Signature", &signature);
            }
            query.finish()
        };
        let separator = if url::Url::parse(endpoint)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .query()
            .is_some_and(|query| !query.is_empty())
        {
            "&"
        } else {
            "?"
        };
        let url = format!("{endpoint}{separator}{encoded_query}");
        if self.config.saml_enable_in_response_to_validation {
            let now = chrono::Utc::now();
            let deadline = now
                .checked_add_signed(self.config.saml_request_ttl)
                .ok_or_else(|| AuthError::internal("SAML request deadline overflow"))?;
            _ = ctx.verifications().create(alibi_core::CreateVerification{identifier:format!("saml-authn-request:{id}"),value:serde_json::to_string(&json!({"id":id,"providerId":provider.provider_id,"providerReference":reference,"createdAt":now.timestamp_millis(),"expiresAt":deadline.timestamp_millis()}))?,expires_at:deadline}).await?;
        }
        Ok(EndpointResponse::json(&json!({"url":url,"redirect":true}))?
            .with_header("Set-Cookie", cookie))
    }
}
