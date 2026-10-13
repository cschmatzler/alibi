//! DNS-backed domain ownership confirmation.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SessionRequest, SsoPlugin, Value, json,
};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
impl SsoPlugin {
    pub fn verify_domain_endpoint(provider_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "verifyDomain").with_body(&json!({"providerId":provider_id}))
    }
    pub(super) async fn verify_domain<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let provider = self.authorized_provider(input, request, ctx).await?;
        if provider.domain_verified == Some(true) {
            return Err(error(
                409,
                "DOMAIN_VERIFIED",
                "Domain has already been verified",
            ));
        }
        let identifier = self.domain_identifier(&provider.provider_id);
        if identifier.encode_utf16().count() > 63 {
            return Err(error(
                400,
                "IDENTIFIER_TOO_LONG",
                "Verification identifier exceeds the DNS label limit of 63 characters",
            ));
        }
        let proof = ctx
            .verifications()
            .find(&identifier)
            .await?
            .filter(|proof| {
                proof
                    .expires_at()
                    .is_ok_and(|expiry| expiry > chrono::Utc::now())
            })
            .ok_or_else(|| {
                error(
                    404,
                    "NO_PENDING_VERIFICATION",
                    "No pending domain verification exists",
                )
            })?;
        let resolver = if self.config.domain_verification_dns_servers.is_empty() {
            TokioResolver::builder_tokio().map_err(|_| {
                error(
                    500,
                    "DOMAIN_VERIFICATION_FAILED",
                    "Unable to verify domain ownership due to server error",
                )
            })?
        } else {
            let servers = self
                .config
                .domain_verification_dns_servers
                .iter()
                .map(|address| {
                    let mut server = NameServerConfig::udp(address.ip());
                    for connection in &mut server.connections {
                        connection.port = address.port();
                    }
                    server
                })
                .collect();
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            )
        }
        .build()
        .map_err(|_| {
            error(
                500,
                "DOMAIN_VERIFICATION_FAILED",
                "Unable to verify domain ownership due to server error",
            )
        })?;
        let domains = domains(&provider.domain)?;
        let token = proof.value()?;
        let record = format!("{}={token}", proof.identifier()?);
        for domain in domains {
            let answers = resolver.txt_lookup(format!("{identifier}.{domain}.")).await;
            let matched = answers.is_ok_and(|answers| {
                answers.answers().iter().any(|answer| {
                    if let hickory_resolver::proto::rr::RData::TXT(txt) = &answer.data {
                        let joined = txt
                            .txt_data
                            .iter()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect::<Vec<u8>>();
                        String::from_utf8_lossy(&joined).trim() == record
                            || String::from_utf8_lossy(&joined).trim() == token
                    } else {
                        false
                    }
                })
            });
            if !matched {
                return Err(error(
                    502,
                    "DOMAIN_VERIFICATION_FAILED",
                    &format!("Unable to verify domain ownership for {domain}. Try again later"),
                ));
            }
        }
        if !ctx
            .database
            .mark_sso_domain_verified(&provider.id, &provider.domain)
            .await?
        {
            return Err(error(
                409,
                "SSO_PROVIDER_CHANGED",
                "SSO provider changed while domain verification was in progress. Reload the provider and try again",
            ));
        }
        let mut response = EndpointResponse::empty()
            .with_status(204)
            .with_header("Content-Type", "application/json");
        if let Some(http) = response.http_response_mut() {
            http.status = 204;
        }
        Ok(response)
    }
}
fn error(status: u16, code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status,
        code: Some(code.into()),
        message: message.into(),
    }
}
fn domains(raw: &str) -> AuthResult<Vec<String>> {
    let mut values = Vec::new();
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let url = if item.contains("://") {
            url::Url::parse(item)
        } else {
            url::Url::parse(&format!("https://{item}"))
        }
        .map_err(|_| error(400, "INVALID_DOMAIN", "Invalid domain"))?;
        let domain = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| error(400, "INVALID_DOMAIN", "Invalid domain"))?
            .to_ascii_lowercase();
        if !values.contains(&domain) {
            values.push(domain);
        }
    }
    if values.is_empty() {
        return Err(error(400, "INVALID_DOMAIN", "Invalid domain"));
    }
    Ok(values)
}
