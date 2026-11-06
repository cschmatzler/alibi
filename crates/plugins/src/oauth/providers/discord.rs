use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthScopeOrder, OAuthUserInfo, Value};
use super::{OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use async_trait::async_trait;
use std::sync::Arc;
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
                source_profile_exceptions: true,
                scope_order: OAuthScopeOrder::RequestedThenConfigured,
                pkce: false,
                default_prompt: Some("none".into()),
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(|profile| {
                super::remaining_profile::raw_subject(profile.get("id"))
            }),
            map_user_info: Some(discord_user_info),
            get_user_info: Some(Arc::new(DiscordUserInfo {
                endpoint: "https://discord.com/api/users/@me".into(),
                mapper: None,
            })),
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

#[derive(Clone)]
struct DiscordUserInfo {
    endpoint: String,
    mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for DiscordUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        Some(Arc::new(Self {
            mapper: Some(mapper),
            ..self.clone()
        }))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let mut profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(request.access_token.as_deref().unwrap_or("undefined"))
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing discord profile".into());
        }
        let user = discord_user_info(profile.clone())
            .map_err(super::remaining_profile::profile_exception)?;
        profile["image_url"] = user.get("image").cloned().unwrap_or(Value::Undefined);
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            profile
                .get("global_name")
                .filter(|value| super::remaining_profile::truthy(value))
                .or_else(|| {
                    profile
                        .get("username")
                        .filter(|value| super::remaining_profile::truthy(value))
                })
                .cloned()
                .unwrap_or(Value::String(String::new().into())),
        );
        for (source, target) in [
            ("email", "email"),
            ("verified", "emailVerified"),
            ("image_url", "image"),
        ] {
            if let Some(value) = profile.get(source) {
                _ = output.insert(target.into(), value.clone());
            }
        }
        if let Some(mapper) = &self.mapper {
            output.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        let mut response = OAuthUserInfoResponse {
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}

/// Discord's normalized user fields for its declared string profile schema.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
pub(in crate::oauth::providers) fn discord_user_info(profile: Value) -> Result<Map, String> {
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing id")?;
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default();
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
        id: id.to_owned().into(),
        email: email.to_owned().into(),
        name: Some(
            profile
                .get("global_name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or_else(|| profile.get("username").and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned()
                .into(),
        ),
        image: Some(image.into()),
        email_verified: profile
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
    .public_profile(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::js as json;

    struct AvatarMapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for AvatarMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(
                profile["image_url"],
                "https://cdn.discordapp.com/avatars/42/a_hash.gif"
            );
            Ok(
                alibi_core::utils::json::from_value(json!({"name":"Mapped","custom":true}))
                    .unwrap(),
            )
        }
    }
    #[tokio::test]
    async fn discord_enriches_profile_before_mapping() {
        let body =
            json!({"id":"42","username":"user","avatar":"a_hash","email":null,"verified":true});

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let mut provider = OAuthProvider::discord("client", "secret");
        provider.get_user_info = Some(Arc::new(DiscordUserInfo {
            endpoint,
            mapper: None,
        }));
        let provider = provider.with_profile_mapper(Arc::new(AvatarMapper));
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            response.data["image_url"],
            "https://cdn.discordapp.com/avatars/42/a_hash.gif"
        );
        assert_eq!(
            response.user.get("name").and_then(Value::as_str),
            Some("Mapped")
        );
        assert!(
            response
                .user
                .get("emailVerified")
                .is_some_and(Value::is_truthy)
        );
        let output = response.user.clone();
        assert_eq!(output["email"], Value::Null);
        assert_eq!(output["custom"], true);
        assert!(!output.contains_key("id"));
    }

    #[tokio::test]
    async fn discord_admission_distinguishes_null_transport_projection_and_mapper() {
        use super::super::admission_tests::{
            HttpFixture, RejectHandler, RejectMapper, assert_outcome, request,
        };
        for (status, profile, throws) in [
            (200, Value::Null, false),
            (500, Value::Null, false),
            (
                200,
                json!({"id":"not-a-number","avatar":null,"discriminator":"0"}),
                true,
            ),
        ] {
            let server = HttpFixture::new(status, profile).await;
            let mut provider = OAuthProvider::discord("client", "secret");
            provider.get_user_info = Some(Arc::new(DiscordUserInfo {
                endpoint: server.url.clone(),
                mapper: None,
            }));
            assert_outcome(provider, request(), throws).await;
        }
        let server = HttpFixture::new(200, json!({"id":"42","avatar":"hash"})).await;
        let mut provider = OAuthProvider::discord("client", "secret");
        provider.get_user_info = Some(Arc::new(DiscordUserInfo {
            endpoint: server.url.clone(),
            mapper: None,
        }));
        assert_outcome(
            provider.clone().with_profile_mapper(Arc::new(RejectMapper)),
            request(),
            true,
        )
        .await;
        provider.get_user_info = Some(Arc::new(RejectHandler));
        assert_outcome(provider, request(), true).await;
    }

    #[test]
    fn discord_optional_email_does_not_reject_profile() {
        let profile = json!({"id":"42","username":"discord-user","avatar":"hash","verified":false});
        assert_eq!(discord_user_info(profile.clone()).unwrap()["email"], "");
        let mut null_email = profile.clone();
        null_email["email"] = Value::Null;
        assert_eq!(discord_user_info(null_email).unwrap()["email"], "");
        let mut with_email = profile;
        with_email["email"] = json!("user@example.com");
        assert_eq!(
            discord_user_info(with_email).unwrap()["email"],
            "user@example.com"
        );
    }
}
