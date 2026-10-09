use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, Value};
use serde_json::Map;
impl OAuthProvider {
    #[must_use]
    pub fn with_hosted_domain(mut self, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        self.authorization_params.retain(|(key, _)| key != "hd");
        self.authorization_params
            .push(("hd".into(), domain.clone()));
        self.hosted_domain = Some(domain);
        self
    }

    #[must_use]
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_url: "https://oauth2.googleapis.com/token".to_owned(),
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_owned()),
            scopes: vec![
                "email".to_owned(),
                "profile".to_owned(),
                "openid".to_owned(),
            ],
            authorization: Some(OAuthAuthorizationPolicy {
                require_client_secret: true,
                ..Default::default()
            }),
            authorization_params: vec![("include_granted_scopes".to_owned(), "true".to_owned())],
            account_subject: None,
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    additional_fields: Map::default(),
                    id: v
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or("missing sub")?
                        .to_owned(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("picture").and_then(|v| v.as_str()).map(String::from),
                    email_verified: v
                        .get("email_verified")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(super::super::id_token::OAuthIdTokenConfig::google()),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
