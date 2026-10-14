//! OIDC discovery hydration for registered enterprise providers.
use super::{AuthContext, AuthError, AuthResult, AuthSchema, Value, json};
const REQUIRED: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
];
pub(super) async fn resolve<S: AuthSchema>(
    input: &Value,
    issuer: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Value> {
    let endpoint = input
        .get("discoveryEndpoint")
        .and_then(Value::as_str)
        .map_or_else(
            || {
                format!(
                    "{}/.well-known/openid-configuration",
                    issuer.strip_suffix('/').unwrap_or(issuer)
                )
            },
            str::to_owned,
        );
    let url = absolute("discoveryEndpoint", &endpoint)?;
    trusted(&url, "main discovery endpoint", ctx)?;
    let (client, url) = super::callback::outbound_client(url.as_str(), ctx).await?;
    let response = client.get(url).send().await.map_err(|error| {
        if error.is_timeout() {
            failure(
                502,
                "discovery_timeout",
                "OIDC discovery timed out: Discovery request timed out".into(),
            )
        } else {
            failure(
                502,
                "discovery_unexpected_error",
                format!("OIDC discovery failed: Unexpected error during discovery: {error}"),
            )
        }
    })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(failure(400,"discovery_not_found","OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. Discovery endpoint not found".into()));
    }
    if response.status().is_redirection() {
        return Err(failure(
            400,
            "oidc_endpoint_redirect",
            format!(
                "The discoveryEndpoint ({endpoint}) returned an HTTP {} redirect. Configure the final OIDC endpoint URL instead of a redirecting URL.",
                response.status().as_u16()
            ),
        ));
    }
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        return Err(failure(
            502,
            "discovery_unexpected_error",
            format!(
                "OIDC discovery failed: Unexpected discovery error: {}",
                status.canonical_reason().unwrap_or_default()
            ),
        ));
    }
    let document = response
        .error_for_status()
        .map_err(|error| {
            failure(
                502,
                "discovery_unexpected_error",
                format!("OIDC discovery failed: Unexpected discovery error: {error}"),
            )
        })?
        .json::<Value>()
        .await
        .map_err(|_| {
            failure(
                400,
                "discovery_invalid_json",
                "OIDC discovery returned invalid data: Discovery endpoint returned invalid JSON"
                    .into(),
            )
        })?;
    if document.is_null() || document.is_string() {
        let reason = if document.is_null() {
            "Discovery endpoint returned an empty response"
        } else {
            "Discovery endpoint returned invalid JSON"
        };
        return Err(failure(
            400,
            "discovery_invalid_json",
            format!("OIDC discovery returned invalid data: {reason}"),
        ));
    }
    let missing = REQUIRED
        .iter()
        .filter(|field| {
            document.get(**field).is_none_or(|value| {
                value.is_null()
                    || value == &json!("")
                    || value == &json!(false)
                    || value.as_f64() == Some(0.0)
            })
        })
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(failure(
            400,
            "discovery_incomplete",
            format!(
                "OIDC discovery document is missing required fields: Discovery document is missing required fields: {}",
                missing.join(", ")
            ),
        ));
    }
    let discovered = document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::internal("Invalid discovery issuer"))?;
    if discovered.strip_suffix('/').unwrap_or(discovered)
        != issuer.strip_suffix('/').unwrap_or(issuer)
    {
        return Err(failure(
            400,
            "issuer_mismatch",
            format!(
                "OIDC issuer mismatch: Discovered issuer \"{discovered}\" does not match configured issuer \"{issuer}\""
            ),
        ));
    }
    let mut output = input
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Invalid OIDC configuration"))?;
    _ = output.insert("issuer".into(), json!(discovered));
    _ = output.insert("discoveryEndpoint".into(), json!(endpoint));
    for (field, source) in [
        ("authorizationEndpoint", "authorization_endpoint"),
        ("tokenEndpoint", "token_endpoint"),
        ("jwksEndpoint", "jwks_uri"),
        ("userInfoEndpoint", "userinfo_endpoint"),
        ("revocationEndpoint", "revocation_endpoint"),
        ("endSessionEndpoint", "end_session_endpoint"),
        ("introspectionEndpoint", "introspection_endpoint"),
    ] {
        if let Some(value) = document
            .get(source)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            let url = normalize(source, value, issuer)?;
            trusted(&url, source, ctx)?;
            if matches!(
                field,
                "authorizationEndpoint" | "tokenEndpoint" | "jwksEndpoint" | "userInfoEndpoint"
            ) && output.get(field).is_none_or(Value::is_null)
            {
                _ = output.insert(field.into(), json!(url.as_str()));
            }
        }
    }
    if output
        .get("tokenEndpointAuthentication")
        .is_none_or(Value::is_null)
    {
        let methods = document
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array);
        let method = [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ]
        .into_iter()
        .find(|method| {
            methods.is_some_and(|methods| {
                methods
                    .iter()
                    .any(|supported| supported.as_str() == Some(method))
            })
        })
        .unwrap_or("client_secret_basic");
        _ = output.insert("tokenEndpointAuthentication".into(), json!(method));
    }
    Ok(Value::Object(output))
}
fn absolute(name: &str, value: &str) -> AuthResult<url::Url> {
    match url::Url::parse(value) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => Ok(url),
        Ok(_) => Err(failure(
            400,
            "discovery_invalid_url",
            format!(
                "Invalid OIDC endpoint URL: The url \"{name}\" must use the http or https supported protocols: {value}"
            ),
        )),
        Err(_) => Err(failure(
            400,
            "discovery_invalid_url",
            format!("Invalid OIDC endpoint URL: The url \"{name}\" must be valid: {value}"),
        )),
    }
}
fn normalize(name: &str, value: &str, issuer: &str) -> AuthResult<url::Url> {
    if let Ok(url) = absolute(name, value) {
        return Ok(url);
    }
    let base = absolute(name, issuer)?;
    absolute(
        name,
        &format!(
            "{}{}/{}",
            base.origin().ascii_serialization(),
            base.path().trim_end_matches('/'),
            value.trim_start_matches('/')
        ),
    )
}
fn trusted<S: AuthSchema>(url: &url::Url, name: &str, ctx: &AuthContext<S>) -> AuthResult<()> {
    if !ctx.config.is_redirect_target_trusted(url.as_str()) {
        return Err(failure(
            400,
            "discovery_untrusted_origin",
            format!(
                "Untrusted OIDC discovery URL: The {name} \"{url}\" is not trusted by your trusted origins configuration."
            ),
        ));
    }
    Ok(())
}
fn failure(status: u16, code: &str, message: String) -> AuthError {
    AuthError::Api {
        status,
        code: Some(code.into()),
        message,
    }
}

pub(super) async fn ensure<S: AuthSchema>(
    input: &Value,
    issuer: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Value> {
    let mut output = input
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Invalid OIDC configuration"))?;
    if ["authorizationEndpoint", "tokenEndpoint", "jwksEndpoint"]
        .into_iter()
        .any(|field| {
            input
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        let hydrated = resolve(input, issuer, ctx).await?;
        for field in [
            "authorizationEndpoint",
            "tokenEndpoint",
            "jwksEndpoint",
            "userInfoEndpoint",
            "tokenEndpointAuthentication",
        ] {
            if let Some(value) = hydrated.get(field) {
                _ = output.insert(field.into(), value.clone());
            }
        }
    }
    Ok(Value::Object(output))
}
pub(super) fn callback_error_message(error: &AuthError) -> &str {
    let AuthError::Api {
        code: Some(code),
        message,
        ..
    } = error
    else {
        return "unexpected_discovery_error";
    };
    let prefix = match code.as_str() {
        "discovery_timeout" => "OIDC discovery timed out: ",
        "discovery_unexpected_error" => "OIDC discovery failed: ",
        "discovery_not_found" => {
            "OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. "
        }
        "discovery_invalid_url" => "Invalid OIDC endpoint URL: ",
        "discovery_untrusted_origin" => "Untrusted OIDC discovery URL: ",
        "discovery_invalid_json" => "OIDC discovery returned invalid data: ",
        "discovery_incomplete" => "OIDC discovery document is missing required fields: ",
        "issuer_mismatch" => "OIDC issuer mismatch: ",
        _ => "",
    };
    message.strip_prefix(prefix).unwrap_or(message)
}
