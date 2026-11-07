use super::super::admission_tests::HttpFixture;
use super::super::*;
use alibi_core::utils::json::{self, JsObject, JsValue};
use base64::Engine;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn provider(name: &str, endpoint: &str) -> OAuthProvider {
    macro_rules! with_endpoint {
        ($options:ident, $factory:ident) => {{
            let mut options = $options::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::$factory(options)
        }};
    }
    match name {
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
    factory: fn(&str, &str) -> OAuthProvider,
) {
    let fixture =
        json::parse_value(include_str!("remaining_profile_own_fields_cases.json")).unwrap();
    assert_eq!(fixture["better_auth"].as_str(), Some("1.7.18"));
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 179);
    let mut matched = 0;
    for case in cases {
        let name = case["provider"].as_str().unwrap();
        if !provider_names.contains(&name) {
            continue;
        }
        matched += 1;
        let profile = case["profile"].clone();
        let server = HttpFixture::new(200, profile.clone()).await;
        let mut provider = factory(name, &server.url);
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
        let wire =
            json::parse_value(&json::to_string(&JsValue::Object(response.user)).unwrap()).unwrap();
        assert_eq!(wire, case["expected"], "{name}/{}", case["mode"]);
    }
    let expected_count: usize = provider_names
        .iter()
        .map(|name| if *name == "tiktok" { 5 } else { 6 })
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
