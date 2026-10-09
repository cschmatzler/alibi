use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, Value};
impl OAuthProvider {
    /// GitLab.com social login with the published `read_user` scope and PKCE.
    #[must_use]
    pub fn gitlab(client_id: &str, client_secret: &str) -> Self {
        Self::gitlab_with_issuer(client_id, client_secret, "https://gitlab.com")
    }

    /// GitLab social login hosted at an application-configured issuer.
    ///
    /// The issuer may include a deployment path. Repeated path slashes follow
    /// the pinned provider's endpoint construction rather than URL resolution.
    pub fn gitlab_with_issuer(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        let issuer = if issuer.is_empty() {
            "https://gitlab.com"
        } else {
            issuer
        };
        Self {
            client_id: client_id.into(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.into(),
            auth_url: gitlab_endpoint(issuer, "/oauth/authorize"),
            token_url: gitlab_endpoint(issuer, "/oauth/token"),
            user_info_url: Some(gitlab_endpoint(issuer, "/api/v4/user")),
            scopes: vec!["read_user".into()],
            authorization: Some(OAuthAuthorizationPolicy::default()),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: Some(gitlab_user_info),
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

pub(in crate::oauth::providers) fn gitlab_endpoint(issuer: &str, suffix: &str) -> String {
    format!("{issuer}{suffix}")
        .split("://")
        .map(|part| {
            let mut previous_slash = false;
            part.chars()
                .filter(|character| {
                    let slash = *character == '/';
                    let retain = !slash || !previous_slash;
                    previous_slash = slash;
                    retain
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("://")
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
pub(in crate::oauth::providers) fn gitlab_user_info(
    profile: Value,
) -> Result<OAuthUserInfo, String> {
    let locked = profile.get("locked").is_some_and(|value| match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    });
    if profile.get("state").and_then(Value::as_str) != Some("active") || locked {
        return Err("GitLab account is inactive or locked".into());
    }
    let id = match profile.get("id") {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => {
            alibi_core::utils::json::number_to_string(value).map_err(|error| error.to_string())?
        }
        _ => return Err("Missing GitLab account ID".into()),
    };
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id,
        email: profile
            .get("email")
            .and_then(Value::as_str)
            .ok_or("Missing GitLab email")?
            .into(),
        name: Some(
            profile
                .get("name")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("username").filter(|value| !value.is_null()))
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        ),
        image: profile
            .get("avatar_url")
            .and_then(Value::as_str)
            .map(String::from),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}
