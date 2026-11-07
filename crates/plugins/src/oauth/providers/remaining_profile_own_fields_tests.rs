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

async fn assert_own_fields(provider_names: &[&str]) {
    let fixture =
        json::parse_value(include_str!("remaining_profile_own_fields_cases.json")).unwrap();
    assert_eq!(fixture["better_auth"].as_str(), Some("1.7.18"));
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 54);
    let mut matched = 0;
    for case in cases {
        let name = case["provider"].as_str().unwrap();
        if !provider_names.contains(&name) {
            continue;
        }
        matched += 1;
        let profile = case["profile"].clone();
        let server = HttpFixture::new(200, profile.clone()).await;
        let mut provider = provider(name, &server.url);
        let calls = Arc::new(AtomicUsize::new(0));
        let mapped = !case["mapping"].is_null();
        if mapped {
            let mut patch = case["mapping"].as_object().unwrap().clone();
            for key in case["mapping_undefined"].as_array().unwrap() {
                _ = patch.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
            }
            provider = provider.with_profile_mapper(Arc::new(Mapper {
                profile: profile.clone(),
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
                id_token: Some(token),
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
        assert_eq!(response.data, profile, "{name}/{}", case["mode"]);
        assert_eq!(
            provider.account_subject.unwrap()(&response.data).unwrap(),
            "subject"
        );
        if mapped {
            assert_eq!(response.user["id"], JsValue::String("mapped".into()));
        }
        let wire =
            json::parse_value(&json::to_string(&JsValue::Object(response.user)).unwrap()).unwrap();
        assert_eq!(wire, case["expected"], "{name}/{}", case["mode"]);
    }
    assert_eq!(matched, provider_names.len() * 6);
}

#[tokio::test]
async fn remaining_literal_own_fields_match_upstream_for_roblox_salesforce_slack() {
    assert_own_fields(&["roblox", "salesforce", "slack"]).await;
}

#[tokio::test]
async fn remaining_literal_own_fields_match_upstream_for_spotify_twitch_twitter() {
    assert_own_fields(&["spotify", "twitch", "twitter"]).await;
}

#[tokio::test]
async fn remaining_literal_own_fields_match_upstream_for_vercel_vk_zoom() {
    assert_own_fields(&["vercel", "vk", "zoom"]).await;
}
