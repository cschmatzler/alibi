//! SAML logout callbacks with configured `IdP` authority and real session retirement.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SsoPlugin, Value, json,
};
use alibi_core::session::SessionRequest;
use base64::Engine as _;
use bergshamra::xml::{Document, NodeId};
use std::io::{Read as _, Write as _};
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
impl SsoPlugin {
    pub fn slo_endpoint(provider_id: &str, body: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "sloEndpoint")
            .with_params(&json!({"providerId":provider_id}))?
            .with_body(body)
    }
    pub(super) async fn slo<S: AuthSchema>(
        &self,
        provider_id: &str,
        body: Option<&Value>,
        query: Option<&Value>,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if !self.config.saml_enable_single_logout {
            return Err(error(
                400,
                "SINGLE_LOGOUT_NOT_ENABLED",
                "Single Logout is not enabled",
            ));
        }
        let string = |name: &str| {
            body.and_then(|body| body.get(name))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    query
                        .and_then(|query| query.get(name))
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                })
        };
        let response = string("SAMLResponse");
        let request_data = string("SAMLRequest");
        let relay = string("RelayState");
        let path = format!(
            "{}/sso/saml2/sp/slo/{provider_id}",
            ctx.config.base_url.trim_end_matches('/')
        );
        let target = super::saml_acs::safe_redirect([relay], &path, ctx);
        if response.is_none() && request_data.is_none() {
            let mut url =
                url::Url::parse(&target).map_err(|error| AuthError::internal(error.to_string()))?;
            _ = url
                .query_pairs_mut()
                .append_pair("error", "invalid_request")
                .append_pair("error_description", "missing_logout_data");
            return Ok(EndpointResponse::from_http_response(
                crate::authentication_helpers::redirect(url.as_str()),
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
            .filter(|config| !config.is_null())
            .ok_or_else(|| error(404, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found"))?;
        let config = super::idp_metadata_xml::effective(&config)?;
        let metadata = super::sp_metadata_xml::from_config(&config)?;
        let is_response = response.is_some();
        let kind = if is_response {
            "LogoutResponse"
        } else {
            "LogoutRequest"
        };
        let invalid = || {
            error(
                400,
                if is_response {
                    "INVALID_LOGOUT_RESPONSE"
                } else {
                    "INVALID_LOGOUT_REQUEST"
                },
                if is_response {
                    "Invalid LogoutResponse"
                } else {
                    "Invalid LogoutRequest"
                },
            )
        };
        let encoded = response.or(request_data).ok_or_else(invalid)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid())?;
        let post = *request.session_method() == alibi_core::HttpMethod::Post
            && body
                .and_then(|body| {
                    body.get(if is_response {
                        "SAMLResponse"
                    } else {
                        "SAMLRequest"
                    })
                })
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        let xml = if post {
            String::from_utf8(raw).map_err(|_| invalid())?
        } else {
            let mut xml = String::new();
            _ = flate2::read::DeflateDecoder::new(raw.as_slice())
                .take(262_145)
                .read_to_string(&mut xml)
                .map_err(|_| invalid())?;
            xml
        };
        if xml.len() > 262_144 || xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
            return Err(invalid());
        }
        let doc = bergshamra::xml::uppsala::parse(&xml).map_err(|_| invalid())?;
        let root = doc.document_element().ok_or_else(invalid)?;
        if !doc
            .element(root)
            .is_some_and(|element| element.name.matches(Some(PROTOCOL), kind))
        {
            return Err(invalid());
        }
        let issuer = children(&doc, root, ASSERTION, "Issuer")
            .first()
            .map(|id| doc.text_content_deep(*id));
        let expected = config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("entityID"))
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if issuer.as_deref() != Some(expected) {
            return Err(invalid());
        }
        let signatures = children(
            &doc,
            root,
            "http://www.w3.org/2000/09/xmldsig#",
            "Signature",
        );
        let required = if is_response {
            self.config.saml_want_logout_response_signed
        } else {
            self.config.saml_want_logout_request_signed
        };
        // A Redirect message needs a detached signature over the original query.
        // This callback, like the reference, cannot substitute an XML signature.
        if !post && required {
            return Err(invalid());
        }
        if required {
            if signatures.is_empty() {
                return Err(invalid());
            }
            verify_signature(&doc, &xml, root, &config).map_err(|()| invalid())?;
        }
        if is_response {
            let status = children(&doc, root, PROTOCOL, "Status")
                .first()
                .and_then(|node| {
                    children(&doc, *node, PROTOCOL, "StatusCode")
                        .first()
                        .copied()
                })
                .and_then(|node| doc.get_attribute(node, "Value"));
            if status.is_some_and(|status| status != "urn:oasis:names:tc:SAML:2.0:status:Success") {
                return Err(error(400, "LOGOUT_FAILED_AT_IDP", "Logout failed at IdP"));
            }
            if let Some(id) = doc.get_attribute(root, "InResponseTo")
                && let Err(error) = ctx
                    .verifications()
                    .delete(&format!("saml-logout-request:{id}"))
                    .await
            {
                tracing::warn!(%error,"Failed to delete logout request proof");
            }
            return cleared(crate::authentication_helpers::redirect(&target), ctx);
        }
        let name = children(&doc, root, ASSERTION, "NameID")
            .first()
            .map(|id| doc.text_content_deep(*id))
            .filter(|name| !name.is_empty())
            .ok_or_else(invalid)?;
        let session_index = children(&doc, root, PROTOCOL, "SessionIndex")
            .first()
            .map(|id| doc.text_content_deep(*id));
        let key = format!("saml-session:{provider_id}:{name}");
        let stored = ctx.verifications().find(&key).await?;
        if let Some(stored) = stored {
            let data = stored
                .value()
                .ok()
                .and_then(|value| serde_json::from_str::<Value>(value).ok());
            if let Some(data) = data {
                let index = data.get("sessionIndex").and_then(Value::as_str);
                if session_index.as_deref().is_none_or(str::is_empty)
                    || index.is_none_or(str::is_empty)
                    || session_index.as_deref() == index
                {
                    if let Some(token) = data.get("sessionToken").and_then(Value::as_str)
                        && let Err(error) = ctx.database.delete_session(token).await
                    {
                        tracing::warn!(%error,"Failed to delete SAML session during SLO");
                    }
                    if let Some(id) = data.get("sessionId").and_then(Value::as_str)
                        && let Err(error) = ctx
                            .verifications()
                            .delete(&format!("saml-session-by-id:{id}"))
                            .await
                    {
                        tracing::warn!(%error,"Failed to delete SAML session lookup during SLO");
                    }
                }
            }
            if let Err(error) = ctx.verifications().delete(&key).await {
                tracing::warn!(%error,"Failed to delete SAML session key during SLO");
            }
        }
        if let Ok((_, session)) = crate::helpers::ordinary_session(request, ctx).await {
            ctx.database.delete_session(&session.token).await?;
        }
        let services = config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("singleLogoutService"))
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let binding = if post {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        } else {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        };
        let destination = services
            .iter()
            .find(|service| service.get("Binding").and_then(Value::as_str) == Some(binding))
            .and_then(|service| service.get("Location"))
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let entity = metadata
            .as_ref()
            .map(|sp| sp.entity_id.as_str())
            .or_else(|| {
                config
                    .get("spMetadata")
                    .and_then(|metadata| metadata.get("entityID"))
                    .and_then(Value::as_str)
                    .filter(|entity| !entity.is_empty())
                    .or_else(|| config.get("issuer").and_then(Value::as_str))
            })
            .unwrap_or(&provider.issuer);
        let id = doc.get_attribute(root, "ID").ok_or_else(invalid)?;
        let response = logout_response(entity, destination, id);
        if post {
            if !url::Url::parse(destination)
                .is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
            {
                return Err(super::api(
                    400,
                    "SAML POST binding location must be an absolute http or https URL",
                ));
            }
            let relay = relay
                .filter(|value| !value.is_empty())
                .map_or_else(String::new, |value| {
                    format!(
                        r#"<input type="hidden" name="RelayState" value="{}" />"#,
                        html_escape(value)
                    )
                });
            let html = format!(
                r#"<!DOCTYPE html><html><body onload="document.forms[0].submit();"><form method="POST" action="{}"><input type="hidden" name="SAMLResponse" value="{}" />{}<noscript><input type="submit" value="Continue" /></noscript></form></body></html>"#,
                html_escape(destination),
                base64::engine::general_purpose::STANDARD.encode(response),
                relay
            );
            return cleared(
                alibi_core::AuthResponse::text(200, &html).with_header("content-type", "text/html"),
                ctx,
            );
        }
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(response.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            encoder
                .finish()
                .map_err(|error| AuthError::internal(error.to_string()))?,
        );
        let query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            _ = query.append_pair("SAMLResponse", &encoded);
            if let Some(relay) = relay {
                _ = query.append_pair("RelayState", relay);
            }
            query.finish()
        };
        cleared(
            crate::authentication_helpers::redirect(&format!("{destination}?{query}")),
            ctx,
        )
    }
}
fn children(doc: &Document<'_>, parent: NodeId, namespace: &str, name: &str) -> Vec<NodeId> {
    doc.children(parent)
        .into_iter()
        .filter(|id| {
            doc.element(*id)
                .is_some_and(|element| element.name.matches(Some(namespace), name))
        })
        .collect()
}
fn verify_signature(doc: &Document<'_>, xml: &str, root: NodeId, config: &Value) -> Result<(), ()> {
    super::saml_crypto::validate_signature_references(doc, root).map_err(|_| ())?;
    let certificates = config
        .get("idpMetadata")
        .and_then(|metadata| metadata.get("cert"))
        .or_else(|| config.get("cert"))
        .ok_or(())?;
    let certificates = if let Some(cert) = certificates.as_str() {
        vec![cert]
    } else {
        certificates
            .as_array()
            .ok_or(())?
            .iter()
            .filter_map(Value::as_str)
            .collect()
    };
    for cert in certificates {
        let key = bergshamra::keys::loader::load_x509_cert_pem(cert.as_bytes()).map_err(|_| ())?;
        let mut manager = bergshamra::KeysManager::new();
        manager.add_key(key);
        let context = bergshamra::DsigContext::new(manager);
        let result =
            bergshamra::dsig::verify::verify_all_document_with_source(&context, doc, Some(xml))
                .map_err(|_| ())?;
        if result.iter().all(bergshamra::VerifyResult::all_reference_digests_verified)&&result.iter().any(|result|matches!(result,bergshamra::VerifyResult::Valid{signature_node,references,..}if doc.parent(*signature_node)==Some(root)&&references.iter().any(|reference|reference.resolved_node==Some(root)&&reference.digest_verified))){return Ok(());}
    }
    Err(())
}
fn logout_response(entity: &str, destination: &str, response_to: &str) -> String {
    let esc = |value: &str| quick_xml::escape::escape(value).into_owned();
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{}"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#,
        uuid::Uuid::new_v4(),
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        esc(destination),
        esc(response_to),
        esc(entity)
    )
}
fn cleared<S: AuthSchema>(
    mut response: alibi_core::AuthResponse,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    for cookie in crate::helpers::delete_session_cookie_headers(&ctx.config)? {
        response.headers.append("Set-Cookie", cookie);
    }
    Ok(EndpointResponse::from_http_response(response))
}
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn error(status: u16, code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status,
        code: Some(code.into()),
        message: message.into(),
    }
}
pub(super) fn validate(input: Option<&JsValue>, location: &str) -> AuthResult<Option<JsValue>> {
    input
        .map(|input| {
            crate::endpoint::validate_fields(
                Some(input),
                location,
                &[
                    crate::authentication_helpers::JsonField::string("SAMLRequest", false),
                    crate::authentication_helpers::JsonField::string("SAMLResponse", false),
                    crate::authentication_helpers::JsonField::string("RelayState", false),
                    crate::authentication_helpers::JsonField::string("SigAlg", false),
                    crate::authentication_helpers::JsonField::string("Signature", false),
                ],
            )
        })
        .transpose()
}
