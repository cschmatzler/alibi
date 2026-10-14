//! Public SAML service-provider discovery for registered providers.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SsoPlugin, Value, api, json,
};
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
impl SsoPlugin {
    pub fn sp_metadata_endpoint(provider_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "spMetadata").with_query(&json!({"providerId":provider_id}))
    }
    pub(super) async fn metadata<S: AuthSchema>(
        &self,
        query: &JsValue,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let id = query
            .get("providerId")
            .and_then(JsValue::as_str)
            .ok_or_else(|| crate::endpoint::validation("Missing providerId"))?;
        let provider = ctx
            .database
            .get_sso_provider(id)
            .await?
            .ok_or_else(|| api(404, "No provider found for the given providerId"))?;
        let config = provider
            .saml_config
            .as_deref()
            .and_then(|config| serde_json::from_str::<Value>(config).ok())
            .filter(|config| !config.is_null())
            .ok_or_else(|| api(400, "Invalid SAML configuration"))?;
        _ = super::sp_metadata_xml::from_config(&config)?;
        if let Some(xml) = super::sp_metadata_xml::xml(&config) {
            return Ok(EndpointResponse::from_http_response(
                alibi_core::AuthResponse::text(200, xml)
                    .with_header("content-type", "application/xml"),
            ));
        }
        let entity = config
            .get("spMetadata")
            .and_then(|metadata| metadata.get("entityID"))
            .and_then(Value::as_str)
            .filter(|entity| !entity.is_empty())
            .or_else(|| config.get("issuer").and_then(Value::as_str))
            .unwrap_or(&provider.issuer);
        let name_id = config
            .get("identifierFormat")
            .and_then(Value::as_str)
            .filter(|format| !format.is_empty())
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let acs = format!("{base}/sso/saml2/sp/acs/{id}");
        let signed_assertions = if config.get("wantAssertionsSigned") == Some(&json!(true)) {
            "true"
        } else {
            "false"
        };
        let signed_requests = if config.get("authnRequestsSigned") == Some(&json!(true)) {
            "true"
        } else {
            "false"
        };
        let mut writer = Writer::new(Vec::new());
        let mut root = BytesStart::new("EntityDescriptor");
        _ = root.extend_attributes([
            ("entityID", entity),
            ("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata"),
            ("xmlns:assertion", "urn:oasis:names:tc:SAML:2.0:assertion"),
            ("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"),
        ]);
        let mut descriptor = BytesStart::new("SPSSODescriptor");
        _ = descriptor.extend_attributes([
            ("AuthnRequestsSigned", signed_requests),
            ("WantAssertionsSigned", signed_assertions),
            (
                "protocolSupportEnumeration",
                "urn:oasis:names:tc:SAML:2.0:protocol",
            ),
        ]);
        let mut consumer = BytesStart::new("AssertionConsumerService");
        _ = consumer.extend_attributes([
            ("index", "0"),
            ("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
            ("Location", acs.as_str()),
        ]);
        for event in [
            Event::Start(root),
            Event::Start(descriptor),
            Event::Start(BytesStart::new("NameIDFormat")),
            Event::Text(BytesText::new(name_id)),
            Event::End(BytesEnd::new("NameIDFormat")),
            Event::Start(consumer),
            Event::End(BytesEnd::new("AssertionConsumerService")),
        ] {
            writer
                .write_event(event)
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        if self.config.saml_enable_single_logout {
            let location = format!("{base}/sso/saml2/sp/slo/{id}");
            for binding in ["HTTP-POST", "HTTP-Redirect"] {
                let binding = format!("urn:oasis:names:tc:SAML:2.0:bindings:{binding}");
                let mut service = BytesStart::new("SingleLogoutService");
                _ = service.extend_attributes([
                    ("Binding", binding.as_str()),
                    ("Location", location.as_str()),
                ]);
                writer
                    .write_event(Event::Start(service))
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                writer
                    .write_event(Event::End(BytesEnd::new("SingleLogoutService")))
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
        for name in ["SPSSODescriptor", "EntityDescriptor"] {
            writer
                .write_event(Event::End(BytesEnd::new(name)))
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        let xml = String::from_utf8(writer.into_inner())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(EndpointResponse::from_http_response(
            alibi_core::AuthResponse::text(200, &xml)
                .with_header("content-type", "application/xml"),
        ))
    }
}
