use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthScopeOrder, OAuthUserInfo, Value};
use serde_json::Map;
impl OAuthProvider {
    #[must_use]
    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_owned(),
            token_url: "https://discord.com/api/oauth2/token".to_owned(),
            user_info_url: Some("https://discord.com/api/users/@me".to_owned()),
            scopes: vec!["identify".to_owned(), "email".to_owned()],
            authorization: Some(OAuthAuthorizationPolicy {
                scope_order: OAuthScopeOrder::RequestedThenConfigured,
                pkce: false,
                default_prompt: Some("none".into()),
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: Some(discord_user_info),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}

/// Discord's normalized user fields for its declared string profile schema.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
pub(in crate::oauth::providers) fn discord_user_info(
    profile: Value,
) -> Result<OAuthUserInfo, String> {
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing id")?;
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .ok_or("missing email")?;
    let image = if profile.get("avatar").is_some_and(Value::is_null) {
        let discriminator = profile
            .get("discriminator")
            .and_then(Value::as_str)
            .ok_or("missing discriminator")?;
        let index = if discriminator == "0" {
            // Source converts the shifted BigInt to Number before remainder.
            // This must retain f64 rounding and overflow, rather than exact mod.
            if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid Discord decimal snowflake".to_owned());
            }
            let snowflake =
                rsa::BigUint::parse_bytes(id.as_bytes(), 10).ok_or("invalid Discord snowflake")?;
            let shifted = (snowflake >> 22usize)
                .to_str_radix(10)
                .parse::<f64>()
                .map_err(|_error| "invalid Discord snowflake number")?;
            shifted % 6.0
        } else {
            // Discord's declared discriminator consists of decimal digits.
            discriminator
                .parse::<f64>()
                .map_err(|_error| "invalid Discord discriminator")?
                % 5.0
        };
        format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
    } else {
        let avatar = profile
            .get("avatar")
            .and_then(Value::as_str)
            .ok_or("missing avatar")?;
        let format = if avatar.starts_with("a_") {
            "gif"
        } else {
            "png"
        };
        format!("https://cdn.discordapp.com/avatars/{id}/{avatar}.{format}")
    };
    Ok(OAuthUserInfo {
        additional_fields: Map::default(),
        id: id.to_owned(),
        email: email.to_owned(),
        name: Some(
            profile
                .get("global_name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or_else(|| profile.get("username").and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned(),
        ),
        image: Some(image),
        email_verified: profile
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}
