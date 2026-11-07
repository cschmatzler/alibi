//! Profile transports and projections shared by the remaining dedicated factories.
//! Public JSON and typed persistence are kept separate; account identity always
//! comes from the original provider profile, before application mapping.

#[cfg(test)]
pub(super) mod own_fields_tests {
    use super::super::admission_tests::HttpFixture;
    use super::super::*;
    use alibi_core::utils::json::{self, JsObject, JsValue};
    use base64::Engine;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn provider(name: &str, endpoint: &str, email_endpoint: &str) -> OAuthProvider {
        macro_rules! with_endpoint {
            ($options:ident, $factory:ident) => {{
                let mut options = $options::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::$factory(options)
            }};
        }
        match name {
            "dropbox" => with_endpoint!(DropboxOptions, dropbox_with_options),
            "figma" => with_endpoint!(FigmaOptions, figma_with_options),
            "github" => OAuthProvider::github_with_endpoints(
                "client",
                "secret",
                "auth",
                "token",
                endpoint,
                email_endpoint,
            ),
            "google" => OAuthProvider::google("client", "secret"),
            "huggingface" => with_endpoint!(HuggingFaceOptions, huggingface_with_options),
            "kakao" => with_endpoint!(KakaoOptions, kakao_with_options),
            "kick" => with_endpoint!(KickOptions, kick_with_options),
            "linear" => with_endpoint!(LinearOptions, linear_with_options),
            "linkedin" => with_endpoint!(LinkedInOptions, linkedin_with_options),
            "roblox" => with_endpoint!(RobloxOptions, roblox_with_options),
            "salesforce" => with_endpoint!(SalesforceOptions, salesforce_with_options),
            "slack" => with_endpoint!(SlackOptions, slack_with_options),
            "spotify" => with_endpoint!(SpotifyOptions, spotify_with_options),
            "twitch" => with_endpoint!(TwitchOptions, twitch_with_options),
            "twitter" => {
                let mut options = TwitterOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.email_info_endpoint = Some(endpoint.into());
                OAuthProvider::twitter_with_options(options)
            }
            "vercel" => with_endpoint!(VercelOptions, vercel_with_options),
            "vk" => with_endpoint!(VkOptions, vk_with_options),
            "zoom" => with_endpoint!(ZoomOptions, zoom_with_options),
            "facebook-graph" | "facebook-limited" => {
                let mut options = FacebookOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.token_inspection_endpoint = Some(format!("{endpoint}/inspect"));
                OAuthProvider::facebook_with_options(options)
            }
            "microsoft" => {
                let mut options = MicrosoftOptions::new("client", Some("secret".into()));
                options.disable_profile_photo = true;
                OAuthProvider::microsoft(options).unwrap()
            }
            "atlassian" => {
                let mut options = AtlassianOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::atlassian_with_options(options)
            }
            "line-token" | "line-http" => with_endpoint!(LineOptions, line_with_options),
            "naver" => with_endpoint!(NaverOptions, naver_with_options),
            "cloudflare" => with_endpoint!(CloudflareOptions, cloudflare_with_options),
            "paypal" => {
                let mut options = PayPalOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::paypal_with_options(options)
            }
            "cognito-token" | "cognito-http" => {
                let mut options = CognitoOptions::new(
                    "client",
                    Some("secret".into()),
                    "example.com",
                    "us-east-1",
                    "us-east-1_pool",
                );
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::cognito(options).unwrap()
            }
            "gitlab" => OAuthProvider::gitlab_with_issuer("client", "secret", endpoint),
            "apple" => OAuthProvider::apple("client", "secret"),
            "wechat" => {
                let mut options = WeChatOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::wechat_with_options(options)
            }
            "paybin" => OAuthProvider::paybin("client", Some("secret")),
            "polar" => with_endpoint!(PolarOptions, polar_with_options),
            "railway" => with_endpoint!(RailwayOptions, railway_with_options),
            "reddit" => with_endpoint!(RedditOptions, reddit_with_options),
            "notion" => with_endpoint!(NotionOptions, notion_with_options),
            "tiktok" => {
                let mut options = TikTokOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::tiktok_with_options(options)
            }
            _ => panic!("unknown fixture provider {name}"),
        }
    }

    struct Mapper {
        profile: JsValue,
        patch: JsObject,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: JsValue) -> Result<JsObject, String> {
            assert_eq!(profile, self.profile);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.patch.clone())
        }
    }

    pub(in crate::oauth::providers) async fn assert_own_fields(
        provider_names: &[&str],
        factory: fn(&str, &str, &str) -> OAuthProvider,
    ) {
        let fixture =
            json::parse_value(include_str!("remaining_profile_own_fields_cases.json")).unwrap();
        assert_eq!(fixture["better_auth"].as_str(), Some("1.7.18"));
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 276);
        let metadata = &fixture["metadata"];
        assert_eq!(
            metadata["source_revision"],
            "38f43e390920faa400d51ff0bd18570a424d05ce"
        );
        assert_eq!(metadata["case_count"].as_u64(), Some(cases.len() as u64));
        let factories: std::collections::BTreeSet<_> = cases
            .iter()
            .map(|case| case["factory"].as_str().unwrap())
            .collect();
        let branches: std::collections::BTreeSet<_> = cases
            .iter()
            .map(|case| case["provider"].as_str().unwrap())
            .collect();
        assert_eq!(
            factories.iter().copied().collect::<Vec<_>>(),
            metadata["factories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap())
                .collect::<Vec<_>>(),
        );
        assert_eq!(factories.len(), 36);
        assert_eq!(branches.len(), 39);
        assert_eq!(
            metadata["factory_count"].as_u64(),
            Some(factories.len() as u64)
        );
        assert_eq!(
            metadata["branch_count"].as_u64(),
            Some(branches.len() as u64)
        );
        for branch in &branches {
            assert_eq!(
                metadata["branches"][*branch].as_u64(),
                Some(
                    cases
                        .iter()
                        .filter(|case| case["provider"].as_str() == Some(*branch))
                        .count() as u64
                )
            );
        }
        let mut matched = 0;
        for case in cases {
            let name = case["provider"].as_str().unwrap();
            if !provider_names.contains(&name) {
                continue;
            }
            matched += 1;
            let profile = case["profile"].clone();
            let server = HttpFixture::new(200, profile.clone()).await;
            let email_server = if name == "github" {
                Some(HttpFixture::new(200, case["emails"].clone()).await)
            } else {
                None
            };
            let mut provider = factory(
                name,
                &server.url,
                email_server
                    .as_ref()
                    .map_or(&server.url, |fixture| &fixture.url),
            );
            let calls = Arc::new(AtomicUsize::new(0));
            let mapped = !case["mapping"].is_null();
            if mapped {
                let mut patch = case["mapping"].as_object().unwrap().clone();
                for key in case["mapping_undefined"].as_array().unwrap() {
                    _ = patch.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
                }
                provider = provider.with_profile_mapper(Arc::new(Mapper {
                    profile: case["expected_data"].clone(),
                    patch,
                    calls: calls.clone(),
                }));
            }
            let token = format!(
                "h.{}.s",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(json::to_string(&profile).unwrap(),)
            );
            let response = provider
            .get_user_info
            .as_ref()
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                id_token: (!["facebook-graph", "cognito-http", "line-http"].contains(&name))
                    .then_some(token),
                raw: (name == "wechat").then(
                    || crate::oauth::providers::js!({"access_token":"access","openid":"subject"}),
                ),
                ..Default::default()
            })
            .await
            .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(mapped), "{name}");
            let mut expected = case["expected"].as_object().unwrap().clone();
            for key in case["undefined"].as_array().unwrap() {
                let key = key.as_js_string().unwrap();
                assert!(
                    response.user.contains_key(key),
                    "{name}/{} lacks own {key:?}",
                    case["mode"]
                );
                assert_eq!(response.user.get(key), Some(&JsValue::Undefined), "{name}");
                _ = expected.insert(key.clone(), JsValue::Undefined);
            }
            assert_eq!(response.user, expected, "{name}/{}", case["mode"]);
            let keys = JsValue::Array(response.user.keys().cloned().map(JsValue::String).collect());
            assert_eq!(keys, case["keys"], "{name}/{}", case["mode"]);
            assert_eq!(
                response.data, case["expected_data"],
                "{name}/{}",
                case["mode"]
            );
            assert_eq!(
                provider.account_subject.unwrap()(&response.data).unwrap(),
                case["subject"].as_js_string().unwrap().clone()
            );
            if mapped {
                assert_eq!(response.user["id"], JsValue::String("mapped".into()));
            }
            let encoded = json::to_string(&JsValue::Object(response.user)).unwrap();
            assert_eq!(
                encoded,
                case["wire"].as_str().unwrap(),
                "{name}/{}",
                case["mode"]
            );
            let wire = json::parse_value(&encoded).unwrap();
            assert_eq!(wire, case["expected"], "{name}/{}", case["mode"]);
        }
        let expected_count: usize = provider_names
            .iter()
            .map(|name| metadata["branches"][*name].as_u64().unwrap() as usize)
            .sum();
        assert_eq!(matched, expected_count);
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_roblox_salesforce_slack() {
        assert_own_fields(&["roblox", "salesforce", "slack"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_spotify_twitch_twitter() {
        assert_own_fields(&["spotify", "twitch", "twitter"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_vercel_vk_zoom() {
        assert_own_fields(&["vercel", "vk", "zoom"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_facebook_graph_and_limited_login() {
        assert_own_fields(&["facebook-graph", "facebook-limited"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_microsoft() {
        assert_own_fields(&["microsoft"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_paybin_polar_railway() {
        assert_own_fields(&["paybin", "polar", "railway"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_reddit_notion() {
        assert_own_fields(&["reddit", "notion"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_atlassian_line_naver() {
        assert_own_fields(&["atlassian", "line-token", "line-http", "naver"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_cloudflare_paypal() {
        assert_own_fields(&["cloudflare", "paypal"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_cognito_gitlab() {
        assert_own_fields(&["cognito-token", "cognito-http", "gitlab"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_apple_wechat() {
        assert_own_fields(&["apple", "wechat"], provider).await;
    }

    #[tokio::test]
    async fn remaining_literal_own_fields_match_upstream_for_tiktok() {
        assert_own_fields(&["tiktok"], provider).await;
    }

    #[tokio::test]
    async fn all_literal_own_fields_match_upstream_for_dropbox_figma() {
        assert_own_fields(&["dropbox", "figma"], provider).await;
    }

    #[tokio::test]
    async fn all_literal_own_fields_match_upstream_for_github() {
        assert_own_fields(&["github"], provider).await;
    }

    #[tokio::test]
    async fn all_literal_own_fields_match_upstream_for_google_huggingface_kakao() {
        assert_own_fields(&["google", "huggingface", "kakao"], provider).await;
    }

    #[tokio::test]
    async fn all_literal_own_fields_match_upstream_for_kick_linear_linkedin() {
        assert_own_fields(&["kick", "linear", "linkedin"], provider).await;
    }
}

use super::{OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use alibi_core::utils::json::{JsObject as Map, JsString, JsValue as Value};
use base64::Engine;

pub(crate) trait ProfileResponseExt {
    async fn profile_json(self) -> Result<Value, String>;
}
impl ProfileResponseExt for reqwest::Response {
    async fn profile_json(self) -> Result<Value, String> {
        let bytes = self.bytes().await.map_err(|error| error.to_string())?;
        let text = String::from_utf8_lossy(&bytes);
        alibi_core::utils::json::parse_value(text.strip_prefix('\u{feff}').unwrap_or(&text))
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy)]
pub(super) enum ProfileKind {
    Roblox,
    Salesforce,
    Slack,
    Spotify,
    Twitch,
    Twitter,
    Vercel,
    Vk,
    Zoom,
}

#[derive(Clone)]
pub(super) struct PublishedProfile {
    pub kind: ProfileKind,
    pub endpoint: Option<String>,
    pub email_endpoint: Option<String>,
    pub client_id: String,
    pub mapper: Option<fn(Value) -> Result<Map, String>>,
    pub application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}

pub(in crate::oauth) const PROFILE_EXCEPTION_PREFIX: &str = "oauth-profile-exception:";
pub(super) fn profile_exception(error: impl std::fmt::Display) -> String {
    format!("{PROFILE_EXCEPTION_PREFIX}{error}")
}

pub(in crate::oauth) fn truthy(value: &Value) -> bool {
    value.is_truthy()
}

pub(super) fn scalar(value: Option<&Value>) -> Result<Option<JsString>, String> {
    match value {
        Some(value @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) => {
            value.coerce_js_string().map(Some).map_err(str::to_owned)
        }
        _ => Ok(None),
    }
}

pub(super) fn js_string(value: &Value) -> Result<JsString, String> {
    alibi_core::utils::json::JsValue::from(value.clone())
        .coerce_js_string()
        .map_err(str::to_owned)
}

pub(in crate::oauth) fn js_whitespace(value: char) -> bool {
    matches!(
        value,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// Number coercion used by the published grant helpers' multiplication.
pub(in crate::oauth) fn js_number(value: &Value) -> Option<f64> {
    match value {
        Value::Null => Some(0.0),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        Value::Number(value) => Some(*value),
        Value::Undefined | Value::Date(_) | Value::Object(_) => None,
        Value::Array(_) => js_number(&Value::String(js_string(value).ok()?)),
        Value::String(value) => {
            let value = value.as_str()?.trim_matches(js_whitespace);
            if value.is_empty() {
                return Some(0.0);
            }
            for (prefix, radix) in [
                ("0x", 16),
                ("0X", 16),
                ("0b", 2),
                ("0B", 2),
                ("0o", 8),
                ("0O", 8),
            ] {
                if let Some(digits) = value.strip_prefix(prefix) {
                    if digits.is_empty() {
                        return None;
                    }
                    let mut result = 0.0;
                    for digit in digits.chars() {
                        result = result * f64::from(radix) + f64::from(digit.to_digit(radix)?);
                    }
                    return Some(result);
                }
            }
            if matches!(value, "Infinity" | "+Infinity") {
                return Some(f64::INFINITY);
            }
            if value == "-Infinity" {
                return Some(f64::NEG_INFINITY);
            }
            // Rust accepts inf spellings that ECMAScript Number does not.
            if value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                return None;
            }
            value.parse().ok()
        }
    }
}

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "Date arithmetic is JavaScript f64 milliseconds"
)]
pub(in crate::oauth) fn grant_expiry(
    value: &Value,
    require_truthy: bool,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if require_truthy && !truthy(value) {
        return None;
    }
    let timestamp = chrono::Utc::now().timestamp_millis() as f64 + js_number(value)? * 1000.0;
    if !timestamp.is_finite() || timestamp.abs() > 8_640_000_000_000_000.0 {
        return None;
    }
    chrono::DateTime::from_timestamp_millis(timestamp.trunc() as i64)
}

pub(super) fn has_access_token(request: &OAuthUserInfoRequest) -> bool {
    match &request.raw {
        Some(raw) => raw.get("access_token").is_some_and(truthy),
        None => request
            .access_token
            .as_ref()
            .is_some_and(|value| !value.is_empty()),
    }
}

pub(super) fn bearer_access_token(request: &OAuthUserInfoRequest) -> Result<String, String> {
    match &request.raw {
        Some(raw) => raw
            .get("access_token")
            .map(js_string)
            .transpose()?
            .unwrap_or_else(|| "undefined".into())
            .to_utf8()
            .map_err(|error| error.to_string()),
        None => Ok(request
            .access_token
            .clone()
            .unwrap_or_else(|| "undefined".into())),
    }
}

pub(in crate::oauth) fn decode_grant_jwt(token: &str) -> Result<Value, String> {
    let parts: Vec<_> = token.split('.').collect();
    let [_, payload, _] = parts.as_slice() else {
        return Err("Invalid grant ID token".into());
    };
    if payload.is_empty() || payload.bytes().any(|byte| matches!(byte, b'+' | b'/')) {
        return Err("Invalid grant ID-token payload".into());
    }
    let mut encoded = payload
        .bytes()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
        .map(|byte| match byte {
            b'-' => b'+',
            b'_' => b'/',
            byte => byte,
        })
        .collect::<Vec<_>>();
    if encoded.len() % 4 == 0 {
        for _ in 0..2 {
            if encoded.last() == Some(&b'=') {
                _ = encoded.pop();
            }
        }
    }
    let decoder = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let bytes = decoder.decode(encoded).map_err(|error| error.to_string())?;
    let decoded = std::str::from_utf8(&bytes).map_err(|error| error.to_string())?;
    let decoded = decoded.strip_prefix('\u{feff}').unwrap_or(decoded);
    let profile: Value = alibi_core::utils::json::from_slice(decoded.as_bytes())
        .map_err(|error| error.to_string())?;
    if !profile.is_object() {
        return Err("Invalid grant ID-token claims".into());
    }
    Ok(profile)
}

pub(super) fn strict_primitive_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => left == right,
        _ => false,
    }
}

pub(super) fn grant_id_token(request: &OAuthUserInfoRequest) -> Result<Option<String>, String> {
    match &request.raw {
        Some(raw) => match raw.get("id_token").filter(|value| truthy(value)) {
            None => Ok(None),
            Some(Value::String(value)) => {
                value.to_utf8().map(Some).map_err(|error| error.to_string())
            }
            _ => Err("Non-string grant ID token".into()),
        },
        None => Ok(request.id_token.clone().filter(|value| !value.is_empty())),
    }
}

pub(in crate::oauth) fn raw_subject(value: Option<&Value>) -> Result<JsString, String> {
    let subject = js_string(value.ok_or("Missing provider subject")?)?;
    if subject.trim_matches(js_whitespace).is_empty()
        || matches!(subject.as_str(), Some("null" | "undefined"))
    {
        return Err("Invalid provider subject".into());
    }
    Ok(subject)
}

pub(super) fn subject(kind: ProfileKind, profile: &Value) -> Result<JsString, String> {
    let value = match kind {
        ProfileKind::Roblox | ProfileKind::Twitch | ProfileKind::Vercel => profile.get("sub"),
        ProfileKind::Salesforce => profile.get("user_id"),
        ProfileKind::Slack => profile.get("https://slack.com/user_id"),
        ProfileKind::Spotify | ProfileKind::Zoom => profile.get("id"),
        ProfileKind::Twitter => profile.pointer("/data/id"),
        ProfileKind::Vk => profile.pointer("/user/user_id"),
    };
    raw_subject(value)
}

fn copy(output: &mut Map, key: &str, value: Option<&Value>) {
    _ = output.insert(key.into(), value.cloned().unwrap_or(Value::Undefined));
}
fn or_empty<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Value {
    values
        .into_iter()
        .flatten()
        .find(|value| truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(String::new().into()))
}
fn nullish_empty<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Value {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::String(String::new().into()))
}
fn placeholder(identifier: Option<&Value>, namespace: &str) -> Result<Value, String> {
    let identifier = identifier
        .map(js_string)
        .transpose()
        .map_err(profile_exception)?
        .unwrap_or_else(|| "undefined".into());
    let email = identifier.concat(&format!("@{namespace}.placeholder.invalid").into());
    // The published helper validates the generated address rather than accepting
    // routing characters supplied by a malformed profile identifier.
    if !email
        .as_str()
        .is_some_and(crate::authentication_helpers::is_valid_email)
    {
        return Err(profile_exception("Invalid placeholder email"));
    }
    Ok(Value::String(email.into()))
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for PublishedProfile {
    fn configured_client_ids(
        &self,
        ids: &[String],
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        if !matches!(self.kind, ProfileKind::Vk) {
            return None;
        }
        let mut handler = self.clone();
        handler.client_id = ids.join(",");
        Some(std::sync::Arc::new(handler))
    }
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.mapper = None;
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let client = reqwest::Client::new();
        let mut profile: Value = if matches!(self.kind, ProfileKind::Twitch) {
            let token = grant_id_token(&request)
                .map_err(profile_exception)?
                .ok_or("Missing Twitch ID token")?;
            decode_grant_jwt(&token).map_err(profile_exception)?
        } else {
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or("Missing provider userinfo endpoint")?;
            let access = bearer_access_token(&request)?;
            let transport = if matches!(self.kind, ProfileKind::Vk) {
                if !has_access_token(&request) {
                    return Err("Missing VK access token".into());
                }
                client.post(endpoint).form(&[
                    ("access_token", access.as_str()),
                    ("client_id", self.client_id.as_str()),
                ])
            } else {
                client.get(endpoint).bearer_auth(&access)
            };
            transport
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?
                .profile_json()
                .await
                .map_err(|error| error.to_string())?
        };
        if matches!(self.kind, ProfileKind::Salesforce | ProfileKind::Vercel) && !truthy(&profile) {
            return Err("Missing provider profile".into());
        }
        let mut twitter_verified = false;
        if matches!(self.kind, ProfileKind::Twitter) {
            let endpoint = self
                .email_endpoint
                .as_deref()
                .unwrap_or("https://api.x.com/2/users/me?user.fields=confirmed_email");
            if let Ok(response) = client
                .get(endpoint)
                .bearer_auth(bearer_access_token(&request)?)
                .send()
                .await
                && response.status().is_success()
                && let Ok(email_profile) = response.profile_json().await
                && let Some(email) = email_profile
                    .pointer("/data/confirmed_email")
                    .filter(|value| truthy(value))
            {
                let email = email.clone();
                let data = profile
                    .get_mut("data")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| profile_exception("Invalid Twitter email receiver"))?;
                _ = data.insert("email".into(), email);
                twitter_verified = true;
            }
        }
        let application_output = if let Some(mapper) = &self.application_mapper {
            Some(mapper.map_profile(profile.clone()).await.map_err(|error| {
                if matches!(self.kind, ProfileKind::Salesforce) {
                    error
                } else {
                    profile_exception(error)
                }
            })?)
        } else {
            None
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()
            .map_err(|error| {
                if matches!(self.kind, ProfileKind::Salesforce) {
                    error
                } else {
                    profile_exception(error)
                }
            })?;
        // Unlike the caught Salesforce transport, these factory projections
        // access fields directly after invoking the application mapper.
        if profile.is_null() {
            return Err(profile_exception("Null provider profile"));
        }
        let mut output = Map::new();
        match self.kind {
            ProfileKind::Roblox => {
                _ = output.insert(
                    "name".into(),
                    or_empty([profile.get("nickname"), profile.get("preferred_username")]),
                );
                copy(&mut output, "image", profile.get("picture"));
                _ = output.insert("email".into(), placeholder(profile.get("sub"), "roblox")?);
                _ = output.insert("emailVerified".into(), Value::Bool(false));
            }
            ProfileKind::Salesforce => {
                copy(&mut output, "name", profile.get("name"));
                copy(&mut output, "email", profile.get("email"));
                copy(
                    &mut output,
                    "image",
                    profile
                        .pointer("/photos/picture")
                        .filter(|value| truthy(value))
                        .or_else(|| profile.pointer("/photos/thumbnail")),
                );
                _ = output.insert(
                    "emailVerified".into(),
                    profile
                        .get("email_verified")
                        .filter(|value| !value.is_null())
                        .cloned()
                        .unwrap_or(Value::Bool(false)),
                );
            }
            ProfileKind::Slack => {
                _ = output.insert("name".into(), or_empty([profile.get("name")]));
                copy(&mut output, "email", profile.get("email"));
                copy(&mut output, "emailVerified", profile.get("email_verified"));
                copy(
                    &mut output,
                    "image",
                    profile
                        .get("picture")
                        .filter(|value| truthy(value))
                        .or_else(|| profile.get("https://slack.com/user_image_512")),
                );
            }
            ProfileKind::Spotify => {
                copy(&mut output, "name", profile.get("display_name"));
                copy(&mut output, "email", profile.get("email"));
                let images = profile
                    .get("images")
                    .ok_or_else(|| profile_exception("Missing Spotify images"))?;
                if images.is_null() {
                    return Err(profile_exception("Null Spotify images"));
                }
                copy(
                    &mut output,
                    "image",
                    images
                        .as_array()
                        .and_then(|images| images.first())
                        .or_else(|| images.get("0"))
                        .and_then(|image| image.get("url")),
                );
                _ = output.insert("emailVerified".into(), Value::Bool(false));
            }
            ProfileKind::Twitch => {
                for (key, field) in [
                    ("name", "preferred_username"),
                    ("email", "email"),
                    ("image", "picture"),
                    ("emailVerified", "email_verified"),
                ] {
                    copy(&mut output, key, profile.get(field));
                }
            }
            ProfileKind::Twitter => {
                let data = profile
                    .get("data")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| profile_exception("Missing Twitter data"))?;
                copy(&mut output, "name", data.get("name"));
                _ = output.insert(
                    "email".into(),
                    match data.get("email").filter(|value| truthy(value)) {
                        Some(email) => email.clone(),
                        None => placeholder(data.get("id"), "twitter")?,
                    },
                );
                copy(&mut output, "image", data.get("profile_image_url"));
                _ = output.insert("emailVerified".into(), Value::Bool(twitter_verified));
            }
            ProfileKind::Vercel => {
                _ = output.insert(
                    "name".into(),
                    nullish_empty([profile.get("name"), profile.get("preferred_username")]),
                );
                copy(&mut output, "email", profile.get("email"));
                copy(&mut output, "image", profile.get("picture"));
                _ = output.insert(
                    "emailVerified".into(),
                    profile
                        .get("email_verified")
                        .filter(|value| !value.is_null())
                        .cloned()
                        .unwrap_or(Value::Bool(false)),
                );
            }
            ProfileKind::Vk => {
                let user = profile
                    .get("user")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| profile_exception("Missing VK user"))?;
                if !user.get("email").is_some_and(truthy)
                    && mapped
                        .as_ref()
                        .is_none_or(|user| !user.get("email").is_some_and(Value::is_truthy))
                    && !application_output
                        .as_ref()
                        .and_then(|output| output.get("email"))
                        .is_some_and(truthy)
                {
                    return Err("Missing VK email".into());
                }
                for field in ["first_name", "last_name"] {
                    copy(&mut output, field, user.get(field));
                }
                copy(&mut output, "email", user.get("email"));
                copy(&mut output, "image", user.get("avatar"));
                _ = output.insert("emailVerified".into(), Value::Bool(false));
                for field in ["birthday", "sex"] {
                    copy(&mut output, field, user.get(field));
                }
                let template =
                    |value: Option<&Value>| -> Result<alibi_core::utils::json::JsString, String> {
                        match value {
                            None => Ok("undefined".into()),
                            Some(Value::Null) => Ok("null".into()),
                            Some(value) => js_string(value),
                        }
                    };
                _ = output.insert(
                    "name".into(),
                    Value::String(
                        template(user.get("first_name"))?
                            .concat(&" ".into())
                            .concat(&template(user.get("last_name"))?),
                    ),
                );
            }
            ProfileKind::Zoom => {
                copy(&mut output, "name", profile.get("display_name"));
                copy(&mut output, "image", profile.get("pic_url"));
                copy(&mut output, "email", profile.get("email"));
                _ = output.insert(
                    "emailVerified".into(),
                    Value::Bool(profile.get("verified").is_some_and(truthy)),
                );
            }
        }
        if let Some(mapped) = &mapped {
            output.extend(mapped.clone());
        }
        if let Some(mapped) = application_output {
            output.extend(mapped);
        }
        Ok(OAuthUserInfoResponse {
            user: output,
            account_subject: None,
            data: if matches!(self.kind, ProfileKind::Roblox | ProfileKind::Zoom) {
                Value::Object(object_spread(profile))
            } else {
                profile
            },
        })
    }
}

pub(super) fn object_spread(value: Value) -> Map {
    value.spread()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_jwt_decoding_matches_jose_forgiving_payload_rules() {
        for payload in ["e30", "e30=", "e31", "e31=", " e\t3\n0\x0c=\r", "77u_e30="] {
            assert_eq!(
                decode_grant_jwt(&format!(".{payload}.")).unwrap(),
                crate::oauth::providers::js!({})
            );
        }
        for payload in ["e30==", "e30===", "e30\x0b=", "e=30", "e", "===="] {
            assert!(
                decode_grant_jwt(&format!(".{payload}.")).is_err(),
                "{payload:?}"
            );
        }
    }

    #[test]
    fn grant_jwt_decoding_rejects_malformed_utf8() {
        for bytes in [
            b"{\"x\":\"\xff\"}".as_slice(),
            b"{\"x\":\"\xc0\xaf\"}",
            b"{\"x\":\"\xed\xa0\x80\"}",
            b"{\"x\":\"\xf0\x9f\"}",
        ] {
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            assert!(decode_grant_jwt(&format!(".{payload}.")).is_err());
        }
        assert_eq!(
            decode_grant_jwt(".eyJ4Ijoi77-9In0.").unwrap(),
            crate::oauth::providers::js!({"x": "\u{fffd}"})
        );
    }

    #[test]
    fn grant_jwt_decoding_rejects_standard_base64_alphabet() {
        for payload in ["77u/e30=", "eyJ4Ijoi/yJ9", "eyJuYW1lIjoi8J+kmSJ9"] {
            assert!(
                decode_grant_jwt(&format!(".{payload}.")).is_err(),
                "{payload}"
            );
        }
        assert_eq!(
            decode_grant_jwt(".eyJuYW1lIjoi8J-kmSJ9.").unwrap(),
            crate::oauth::providers::js!({"name": "🤙"})
        );
    }

    async fn serve_profile(profile: Value) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            stream.read(&mut buffer).await.unwrap();
            let body = profile.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        endpoint
    }

    #[tokio::test]
    async fn copied_profiles_spread_arrays_and_primitives() {
        for kind in [ProfileKind::Roblox, ProfileKind::Zoom] {
            for (profile, expected) in [
                (
                    crate::oauth::providers::js!(42),
                    crate::oauth::providers::js!({}),
                ),
                (
                    crate::oauth::providers::js!(false),
                    crate::oauth::providers::js!({}),
                ),
                (
                    crate::oauth::providers::js!(["a", 2]),
                    crate::oauth::providers::js!({"0":"a","1":2}),
                ),
                (
                    crate::oauth::providers::js!("ab"),
                    crate::oauth::providers::js!({"0":"a","1":"b"}),
                ),
                (
                    Value::String("é😀".into()),
                    Value::Object(
                        [
                            ("0".into(), Value::String("é".into())),
                            (
                                "1".into(),
                                Value::String(JsString::from_code_units(vec![0xd83d])),
                            ),
                            (
                                "2".into(),
                                Value::String(JsString::from_code_units(vec![0xde00])),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                ),
                (
                    crate::oauth::providers::js!({"sub":"one", "id":"two"}),
                    crate::oauth::providers::js!({"sub":"one", "id":"two"}),
                ),
            ] {
                let handler = PublishedProfile {
                    kind,
                    endpoint: Some(serve_profile(profile).await),
                    email_endpoint: None,
                    client_id: "client".into(),
                    mapper: None,
                    application_mapper: None,
                };
                let response = handler
                    .get_user_info(OAuthUserInfoRequest::default())
                    .await
                    .unwrap();
                assert_eq!(response.data, expected);
            }
        }
    }

    #[tokio::test]
    async fn twitch_malformed_id_tokens_are_profile_exceptions() {
        let provider = super::super::OAuthProvider::twitch("client", Some("secret"));
        for token in [
            crate::oauth::providers::js!("malformed"),
            crate::oauth::providers::js!(42),
        ] {
            let error = crate::oauth::handlers::fetch_user_info_from_provider(
                &provider,
                OAuthUserInfoRequest {
                    raw: Some(crate::oauth::providers::js!({"id_token": token})),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, alibi_core::AuthError::Api { status: 500, code: Some(code), .. } if code == "OAUTH_PROFILE_EXCEPTION")
            );
        }
        let error = provider
            .get_user_info
            .as_ref()
            .unwrap()
            .get_user_info(OAuthUserInfoRequest::default())
            .await
            .unwrap_err();
        assert!(!error.starts_with(PROFILE_EXCEPTION_PREFIX));
    }
}
