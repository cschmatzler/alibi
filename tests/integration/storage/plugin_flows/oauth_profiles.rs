//! Real provider factories exchange grants and map distinct remote wire profiles.
//! The local peer records delivered requests; it does not supply mapped users.
use super::*;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

backend_tests!(provider_profile_protocols_preserve_raw_identity);
postgres_tests!(provider_profile_protocols_preserve_raw_identity);

#[derive(Clone)]
pub(super) struct ProfileCase {
    pub(super) variant: &'static str,
    pub(super) name: &'static str,
    pub(super) basic_auth: bool,
    pub(super) authorization_pkce: bool,
    pub(super) grant_pkce: bool,
    pub(super) factory: fn(&str) -> OAuthProvider,
    pub(super) profile: Value,
    pub(super) subject_pointer: &'static str,
    pub(super) account: &'static str,
    pub(super) email: &'static str,
    pub(super) display: &'static str,
    pub(super) image: &'static str,
    pub(super) verified: bool,
    pub(super) method: &'static str,
}

// Options are passed before construction: dedicated handlers capture their
// configured endpoint. Replacing a mapper would bypass the contract under test.
macro_rules! factory {
    ($options:ident, $method:ident) => {
        |endpoint| {
            let mut options = $options::new("native-client", Some("native-secret".into()));
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::$method(options)
        }
    };
}

pub(super) fn profiles() -> Vec<ProfileCase> {
    let mut cases = vec![
        ProfileCase {
            variant: "default",
            name: "discord",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: |endpoint| {
                let mut provider = OAuthProvider::discord("native-client", "native-secret");
                provider.user_info_url = Some(endpoint.into());
                provider
            },
            profile: json!({"id":"123","email":"discord@example.test","global_name":"Discord User","username":"Other Name","avatar":"a_animated","discriminator":"0","verified":true}),
            subject_pointer: "/id",
            account: "123",
            email: "discord@example.test",
            display: "Discord User",
            image: "https://cdn.discordapp.com/avatars/123/a_animated.gif",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "twitch",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: |_| OAuthProvider::twitch("native-client", Some("native-secret")),
            profile: json!({"sub":"twitch-41","preferred_username":"Twitch User","email":"twitch@example.test","picture":"https://images.test/twitch","email_verified":true}),
            subject_pointer: "/sub",
            account: "twitch-41",
            email: "twitch@example.test",
            display: "Twitch User",
            image: "https://images.test/twitch",
            verified: true,
            method: "JWT",
        },
        ProfileCase {
            variant: "default",
            name: "paybin",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: |_| OAuthProvider::paybin("native-client", Some("native-secret")),
            profile: json!({"sub":"paybin-41","name":"","preferred_username":"Paybin User","email":"paybin@example.test","picture":"https://images.test/paybin","email_verified":true}),
            subject_pointer: "/sub",
            account: "paybin-41",
            email: "paybin@example.test",
            display: "Paybin User",
            image: "https://images.test/paybin",
            verified: true,
            method: "JWT",
        },
        ProfileCase {
            variant: "default",
            name: "atlassian",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: |endpoint| {
                let mut options = AtlassianOptions::new("native-client", "native-secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::atlassian_with_options(options)
            },
            profile: json!({"account_id":"at-41","name":"Atlassian User","email":"atlassian@example.test","picture":"https://images.test/atlassian"}),
            subject_pointer: "/account_id",
            account: "at-41",
            email: "atlassian@example.test",
            display: "Atlassian User",
            image: "https://images.test/atlassian",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "paypal",
            basic_auth: true,
            authorization_pkce: true,
            grant_pkce: true,
            factory: |endpoint| {
                let mut options = PayPalOptions::new("native-client", "native-secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::paypal_with_options(options)
            },
            profile: json!({"user_id":"pp-41","name":"PayPal User","email":"paypal@example.test","picture":"https://images.test/paypal","email_verified":true}),
            subject_pointer: "/user_id",
            account: "pp-41",
            email: "paypal@example.test",
            display: "PayPal User",
            image: "https://images.test/paypal",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "polar",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(PolarOptions, polar_with_options),
            profile: json!({"id":"polar-41","public_name":"","username":"Polar User","email":"polar@example.test","avatar_url":"https://images.test/polar","email_verified":true}),
            subject_pointer: "/id",
            account: "polar-41",
            email: "polar@example.test",
            display: "Polar User",
            image: "https://images.test/polar",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "railway",
            basic_auth: true,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(RailwayOptions, railway_with_options),
            profile: json!({"sub":"rw-41","name":"Railway User","email":"railway@example.test","picture":"https://images.test/railway"}),
            subject_pointer: "/sub",
            account: "rw-41",
            email: "railway@example.test",
            display: "Railway User",
            image: "https://images.test/railway",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "reddit",
            basic_auth: true,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(RedditOptions, reddit_with_options),
            profile: json!({"id":"rd-41","name":"Reddit User","icon_img":"https://images.test/reddit?size=64"}),
            subject_pointer: "/id",
            account: "rd-41",
            email: "rd-41@reddit.placeholder.invalid",
            display: "Reddit User",
            image: "https://images.test/reddit",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "tiktok",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: true,
            factory: |endpoint| {
                let mut options = TikTokOptions::new("native-client", "native-secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::tiktok_with_options(options)
            },
            profile: json!({"data":{"user":{"open_id":"tt-41","display_name":"TikTok User","username":"Other Name","avatar_large_url":"https://images.test/tiktok"}}}),
            subject_pointer: "/data/user/open_id",
            account: "tt-41",
            email: "tt-41@tiktok.placeholder.invalid",
            display: "TikTok User",
            image: "https://images.test/tiktok",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "twitter",
            basic_auth: true,
            authorization_pkce: true,
            grant_pkce: true,
            factory: |endpoint| {
                let mut options =
                    TwitterOptions::new("native-client", Some("native-secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.email_info_endpoint = Some(
                    url::Url::parse(endpoint)
                        .unwrap()
                        .join("email")
                        .unwrap()
                        .into(),
                );
                OAuthProvider::twitter_with_options(options)
            },
            profile: json!({"data":{"id":"tw-41","name":"Twitter User","profile_image_url":"https://images.test/twitter"}}),
            subject_pointer: "/data/id",
            account: "tw-41",
            email: "twitter@example.test",
            display: "Twitter User",
            image: "https://images.test/twitter",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "dropbox",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(DropboxOptions, dropbox_with_options),
            profile: json!({"account_id":"dbid:41","email":"dropbox@example.test","name":{"display_name":"Dropbox User"},"profile_photo_url":"https://images.test/dropbox","email_verified":true}),
            subject_pointer: "/account_id",
            account: "dbid:41",
            email: "dropbox@example.test",
            display: "Dropbox User",
            image: "https://images.test/dropbox",
            verified: true,
            method: "POST",
        },
        ProfileCase {
            variant: "default",
            name: "cloudflare",
            basic_auth: true,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(CloudflareOptions, cloudflare_with_options),
            profile: json!({"success":true,"result":{"id":"cf-41","email":"cloudflare@example.test","first_name":"Cloud","last_name":"User"}}),
            subject_pointer: "/result/id",
            account: "cf-41",
            email: "cloudflare@example.test",
            display: "Cloud User",
            image: "",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "figma",
            basic_auth: true,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(FigmaOptions, figma_with_options),
            profile: json!({"id":"figma-41","email":"figma@example.test","handle":"Figma User","img_url":"https://images.test/figma"}),
            subject_pointer: "/id",
            account: "figma-41",
            email: "figma@example.test",
            display: "Figma User",
            image: "https://images.test/figma",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "huggingface",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(HuggingFaceOptions, huggingface_with_options),
            profile: json!({"sub":"hf-41","email":"huggingface@example.test","name":"","preferred_username":"HF User","picture":"https://images.test/hf","email_verified":true}),
            subject_pointer: "/sub",
            account: "hf-41",
            email: "huggingface@example.test",
            display: "HF User",
            image: "https://images.test/hf",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "kakao",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(KakaoOptions, kakao_with_options),
            profile: json!({"id":4100,"kakao_account":{"email":"kakao@example.test","is_email_valid":true,"is_email_verified":true,"profile":{"nickname":"Kakao User","profile_image_url":"https://images.test/kakao"}}}),
            subject_pointer: "/id",
            account: "4100",
            email: "kakao@example.test",
            display: "Kakao User",
            image: "https://images.test/kakao",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "kick",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(KickOptions, kick_with_options),
            profile: json!({"data":[{"user_id":42,"name":"Kick User","email":"kick@example.test","profile_picture":"https://images.test/kick"},{"user_id":99,"name":"Wrong User"}]}),
            subject_pointer: "/data/0/user_id",
            account: "42",
            email: "kick@example.test",
            display: "Kick User",
            image: "https://images.test/kick",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "linkedin",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(LinkedInOptions, linkedin_with_options),
            profile: json!({"sub":"li-41","email":"linkedin@example.test","name":"LinkedIn User","picture":"https://images.test/linkedin","email_verified":null}),
            subject_pointer: "/sub",
            account: "li-41",
            email: "linkedin@example.test",
            display: "LinkedIn User",
            image: "https://images.test/linkedin",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "linear",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(LinearOptions, linear_with_options),
            profile: json!({"data":{"viewer":{"id":"linear-41","name":"Linear User","email":"linear@example.test","avatarUrl":"https://images.test/linear","active":true,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}}}),
            subject_pointer: "/data/viewer/id",
            account: "linear-41",
            email: "linear@example.test",
            display: "Linear User",
            image: "https://images.test/linear",
            verified: false,
            method: "POST",
        },
        ProfileCase {
            variant: "default",
            name: "naver",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(NaverOptions, naver_with_options),
            profile: json!({"resultcode":"00","response":{"id":"naver-41","name":"","nickname":"Naver User","email":"naver@example.test","profile_image":"https://images.test/naver"}}),
            subject_pointer: "/response/id",
            account: "naver-41",
            email: "naver@example.test",
            display: "Naver User",
            image: "https://images.test/naver",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "notion",
            basic_auth: true,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(NotionOptions, notion_with_options),
            profile: json!({"bot":{"owner":{"user":{"id":"notion-41","name":"Notion User","person":{"email":"notion@example.test"},"avatar_url":"https://images.test/notion"}}}}),
            subject_pointer: "/bot/owner/user/id",
            account: "notion-41",
            email: "notion@example.test",
            display: "Notion User",
            image: "https://images.test/notion",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "roblox",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(RobloxOptions, roblox_with_options),
            profile: json!({"sub":"41","nickname":"","preferred_username":"Roblox User","picture":"https://images.test/roblox"}),
            subject_pointer: "/sub",
            account: "41",
            email: "41@roblox.placeholder.invalid",
            display: "Roblox User",
            image: "https://images.test/roblox",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "salesforce",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(SalesforceOptions, salesforce_with_options),
            profile: json!({"user_id":"sf-41","name":"Salesforce User","email":"salesforce@example.test","email_verified":true,"photos":{"picture":"","thumbnail":"https://images.test/salesforce"}}),
            subject_pointer: "/user_id",
            account: "sf-41",
            email: "salesforce@example.test",
            display: "Salesforce User",
            image: "https://images.test/salesforce",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "slack",
            basic_auth: false,
            authorization_pkce: false,
            grant_pkce: false,
            factory: factory!(SlackOptions, slack_with_options),
            profile: json!({"https://slack.com/user_id":"slack-41","name":"Slack User","email":"slack@example.test","email_verified":true,"picture":"","https://slack.com/user_image_512":"https://images.test/slack"}),
            subject_pointer: "/https:~1~1slack.com~1user_id",
            account: "slack-41",
            email: "slack@example.test",
            display: "Slack User",
            image: "https://images.test/slack",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "spotify",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(SpotifyOptions, spotify_with_options),
            profile: json!({"id":"spotify-41","display_name":"Spotify User","email":"spotify@example.test","images":[{"url":"https://images.test/spotify"},{"url":"https://images.test/wrong"}]}),
            subject_pointer: "/id",
            account: "spotify-41",
            email: "spotify@example.test",
            display: "Spotify User",
            image: "https://images.test/spotify",
            verified: false,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "vercel",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(VercelOptions, vercel_with_options),
            profile: json!({"sub":"vercel-41","name":null,"preferred_username":"Vercel User","email":"vercel@example.test","email_verified":true,"picture":"https://images.test/vercel"}),
            subject_pointer: "/sub",
            account: "vercel-41",
            email: "vercel@example.test",
            display: "Vercel User",
            image: "https://images.test/vercel",
            verified: true,
            method: "GET",
        },
        ProfileCase {
            variant: "default",
            name: "vk",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(VkOptions, vk_with_options),
            profile: json!({"user":{"user_id":"vk-41","first_name":"VK","last_name":"User","email":"vk@example.test","avatar":"https://images.test/vk"}}),
            subject_pointer: "/user/user_id",
            account: "vk-41",
            email: "vk@example.test",
            display: "VK User",
            image: "https://images.test/vk",
            verified: false,
            method: "POST",
        },
        ProfileCase {
            variant: "default",
            name: "zoom",
            basic_auth: false,
            authorization_pkce: true,
            grant_pkce: true,
            factory: factory!(ZoomOptions, zoom_with_options),
            profile: json!({"id":"zoom-41","display_name":"Zoom User","email":"zoom@example.test","pic_url":"https://images.test/zoom","verified":1}),
            subject_pointer: "/id",
            account: "zoom-41",
            email: "zoom@example.test",
            display: "Zoom User",
            image: "https://images.test/zoom",
            verified: true,
            method: "GET",
        },
    ];
    for field in ["is_email_valid", "is_email_verified"] {
        let mut case = cases
            .iter()
            .find(|case| case.name == "kakao")
            .unwrap()
            .clone();
        case.variant = field;
        case.profile["kakao_account"][field] = json!(false);
        case.verified = false;
        cases.push(case);
    }
    let mut twitter = cases
        .iter()
        .find(|case| case.name == "twitter")
        .unwrap()
        .clone();
    twitter.variant = "email-unavailable";
    twitter.email = "tw-41@twitter.placeholder.invalid";
    twitter.verified = false;
    cases.push(twitter);
    let mut basic = cases
        .iter()
        .find(|case| case.name == "railway")
        .unwrap()
        .clone();
    basic.variant = "credential-delimiters";
    cases.push(basic);
    for name in ["atlassian", "cloudflare", "naver"] {
        let mut case = cases.iter().find(|case| case.name == name).unwrap().clone();
        case.variant = "legacy-mapper";
        case.email = "legacy@example.test";
        case.display = "Legacy mapped";
        case.image = "";
        case.verified = false;
        case.factory = match name {
            "atlassian" => |endpoint| {
                let mut options = AtlassianOptions::new("native-client", "native-secret");
                options.user_info_endpoint = Some(endpoint.into());
                options.map_profile_to_user = Some(legacy_atlassian);
                OAuthProvider::atlassian_with_options(options)
            },
            "cloudflare" => |endpoint| {
                let mut options =
                    CloudflareOptions::new("native-client", Some("native-secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.map_profile_to_user = Some(legacy_cloudflare);
                OAuthProvider::cloudflare_with_options(options)
            },
            _ => |endpoint| {
                let mut options = NaverOptions::new("native-client", Some("native-secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.map_profile_to_user = Some(legacy_naver);
                OAuthProvider::naver_with_options(options)
            },
        };
        cases.push(case);
    }
    cases
}

fn legacy_user() -> OAuthUserInfo {
    OAuthUserInfo {
        id: "legacy-presentation-id".into(),
        email: "legacy@example.test".into(),
        name: Some("Legacy mapped".into()),
        image: None,
        email_verified: false,
        additional_fields: Default::default(),
    }
}
fn legacy_atlassian(profile: Value) -> Result<OAuthUserInfo, String> {
    assert_eq!(profile["name"], "Atlassian User");
    Ok(legacy_user())
}
fn legacy_cloudflare(profile: Value) -> Result<OAuthUserInfo, String> {
    assert!(profile.get("success").is_none());
    assert_eq!(profile["email"], "cloudflare@example.test");
    Ok(legacy_user())
}
fn legacy_naver(profile: Value) -> Result<OAuthUserInfo, String> {
    assert_eq!(profile["resultcode"], "00");
    assert_eq!(profile["response"]["email"], "naver@example.test");
    Ok(legacy_user())
}

pub(super) async fn begin<S: AuthSchema>(
    auth: &BetterAuth<S>,
    name: &str,
) -> (HashMap<String, String>, String) {
    let started = call(auth, request("/sign-in/social", Some(json!({"provider":name,"callbackURL":format!("{ORIGIN}/done"),"errorCallbackURL":format!("{ORIGIN}/failed"),"disableRedirect":true})), ""), 200).await;
    let url = url::Url::parse(body(&started)["url"].as_str().unwrap()).unwrap();
    (url.query_pairs().into_owned().collect(), cookies(&started))
}

pub(super) async fn complete<S: AuthSchema>(
    auth: &BetterAuth<S>,
    name: &str,
    authorization: &HashMap<String, String>,
    cookie: &str,
) -> AuthResponse {
    let mut callback = request(&format!("/callback/{name}"), None, cookie);
    callback.query.extend([
        ("state".into(), authorization["state"].clone()),
        ("code".into(), "one-use-grant".into()),
    ]);
    call(auth, callback, 302).await
}

pub(super) struct PartialProfileMapper(pub(super) Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl OAuthProfileMapper for PartialProfileMapper {
    async fn map_profile(
        &self,
        profile: Value,
    ) -> Result<alibi_core::field_policy::FieldOutput, String> {
        self.0.lock().unwrap().push(profile);
        Ok([
            ("id".into(), json!("application-presentation-id")),
            ("name".into(), json!("Application display")),
        ]
        .into_iter()
        .collect())
    }
}

pub(super) struct FailedMapper;
#[async_trait::async_trait]
impl OAuthProfileMapper for FailedMapper {
    async fn map_profile(&self, _: Value) -> Result<alibi_core::field_policy::FieldOutput, String> {
        Err("Application profile rejected".into())
    }
}
struct CustomProfile;
#[async_trait::async_trait]
impl OAuthUserInfoHandler for CustomProfile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        assert_eq!(request.access_token.as_deref(), Some("remote-access"));
        Ok(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "custom-display-id".into(),
                email: "custom@example.test".into(),
                name: Some("Custom handler".into()),
                image: None,
                email_verified: false,
                additional_fields: Default::default(),
            },
            data: json!({"sub":"custom-raw-subject"}),
            user_output: None,
        })
    }
}

async fn provider_profile_protocols_preserve_raw_identity<B: Backend>(db: Db) -> TestResult {
    for (case, mapping) in [false, true].into_iter().flat_map(|mapping| {
        profiles()
            .into_iter()
            .filter(move |case| {
                !mapping
                    || (case.variant == "default"
                        && matches!(
                            case.name,
                            "twitch"
                                | "paybin"
                                | "paypal"
                                | "polar"
                                | "railway"
                                | "reddit"
                                | "tiktok"
                                | "twitter"
                                | "notion"
                                | "roblox"
                                | "salesforce"
                                | "slack"
                                | "spotify"
                                | "vercel"
                                | "vk"
                                | "zoom"
                        ))
            })
            .map(move |case| (case, mapping))
    }) {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let remote = Provider::start("application/json", "{}").await;
        remote.respond_at(
            "/token",
            200,
            if case.name == "paypal" {
                grant_response(Some(&json!({"sub":case.account})))
            } else {
                grant_response((case.method == "JWT").then_some(&case.profile))
            },
        );
        remote.respond_at("/profile", 200, case.profile.clone());
        remote.respond_at(
            "/email",
            200,
            json!({"data":{"confirmed_email":"twitter@example.test"}}),
        );
        if case.variant == "email-unavailable" {
            remote.respond_at("/email", 503, json!({"error":"temporarily unavailable"}));
        }
        let mut provider = (case.factory)(remote.url.join("profile")?.as_str());
        let (client, secret) = if case.variant == "credential-delimiters" {
            ("client: +", "secret:& +")
        } else {
            ("native-client", "native-secret")
        };
        provider.client_id = client.into();
        provider.client_secret = secret.into();
        provider.token_url = remote.url.join("token")?.into();
        let mapped_profiles = Arc::new(Mutex::new(Vec::new()));
        if mapping {
            provider = provider
                .with_profile_mapper(Arc::new(PartialProfileMapper(mapped_profiles.clone())));
        }
        let auth = builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider(case.name, provider))
            .build()
            .await?;
        let (authorization, state_cookie) = begin(&auth, case.name).await;
        assert_eq!(
            authorization[if case.name == "tiktok" {
                "client_key"
            } else {
                "client_id"
            }],
            client,
            "{}",
            case.name
        );
        assert_eq!(
            authorization["redirect_uri"],
            format!("{ORIGIN}/api/auth/callback/{}", case.name)
        );
        let accepted = if matches!(case.name, "discord" | "reddit") {
            let mut post = request(
                &format!("/callback/{}", case.name),
                Some(
                    json!({"state":"body-state-must-lose","code":"body-code-must-lose","bodyOnly":"retained"}),
                ),
                &state_cookie,
            );
            if case.name == "discord" {
                drop(post.headers.insert(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ));
                post.body = Some(
                    b"state=body-state-must-lose&code=body-code-must-lose&bodyOnly=retained"
                        .to_vec(),
                );
            }
            post.query.extend([
                ("state".into(), authorization["state"].clone()),
                ("code".into(), "one-use-grant".into()),
            ]);
            let redirected = call(&auth, post, 302).await;
            assert!(
                remote.take().is_empty(),
                "form-post callback must redirect before exchanging a grant"
            );
            assert_eq!(db.count("users").await?, 0);
            let url = url::Url::parse(redirected.headers.get("location").unwrap())?;
            assert_eq!(url.path(), format!("/api/auth/callback/{}", case.name));
            let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
            assert_eq!(query["state"], authorization["state"]);
            assert_eq!(query["code"], "one-use-grant");
            assert_eq!(query["bodyOnly"], "retained");
            let mut get = request(&format!("/callback/{}", case.name), None, &state_cookie);
            get.query = query;
            call(&auth, get, 302).await
        } else {
            complete(&auth, case.name, &authorization, &state_cookie).await
        };
        assert_eq!(
            accepted.headers.get("location").map(String::as_str),
            Some(format!("{ORIGIN}/done").as_str()),
            "{}: {:?}",
            case.name,
            accepted.headers
        );
        authenticated(&auth, &cookies(&accepted), case.email).await;
        assert_eq!(db.count("users").await?, 1, "{}", case.name);
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id = $1 AND account_id = $2",
                &[case.name, case.account]
            )
            .await?,
            1,
            "{}",
            case.name
        );
        assert_eq!(
            db.text("SELECT name FROM users", &[]).await?.as_deref(),
            Some(if mapping && case.name != "tiktok" {
                "Application display"
            } else {
                case.display
            }),
            "{}",
            case.name
        );
        let actual_image = db
            .text("SELECT image FROM users", &[])
            .await?
            .unwrap_or_default();
        assert_eq!(actual_image, case.image, "{}", case.name);
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email_verified = true",
                &[]
            )
            .await?,
            i64::from(case.verified),
            "{}",
            case.name
        );
        let exchanges = remote.take();
        let token = exchanges
            .iter()
            .find(|exchange| exchange.path == "/token")
            .unwrap();
        assert_eq!(token.method, "POST", "{}", case.name);
        let form: HashMap<String, String> = url::form_urlencoded::parse(&token.body)
            .into_owned()
            .collect();
        assert_eq!(form["code"], "one-use-grant");
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(
            authorization.contains_key("code_challenge"),
            case.authorization_pkce,
            "{} authorization PKCE",
            case.name
        );
        assert_eq!(
            form.contains_key("code_verifier"),
            case.grant_pkce,
            "{} grant PKCE",
            case.name
        );
        if case.basic_auth {
            let encoded = token.headers["authorization"]
                .to_str()?
                .strip_prefix("Basic ")
                .unwrap();
            assert_eq!(
                STANDARD.decode(encoded)?,
                if case.variant == "credential-delimiters" {
                    b"client%3A+%2B:secret%3A%26+%2B".as_slice()
                } else {
                    b"native-client:native-secret".as_slice()
                },
                "{} credentials",
                case.name
            );
            assert!(
                !form.contains_key("client_secret"),
                "{} duplicated secret",
                case.name
            );
        } else {
            assert!(
                !token.headers.contains_key("authorization"),
                "{} unexpected Basic auth",
                case.name
            );
            assert_eq!(
                form["client_secret"], "native-secret",
                "{} secret",
                case.name
            );
            if case.name == "tiktok" {
                assert!(!form.contains_key("client_id"));
                assert!(!authorization.contains_key("client_id"));
                assert_eq!(form["client_key"], "native-client");
            } else {
                assert_eq!(form["client_id"], "native-client", "{} client", case.name);
            }
        }
        if let Some(challenge) = authorization.get("code_challenge") {
            assert_eq!(authorization["code_challenge_method"], "S256");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
                *challenge,
                "{}",
                case.name
            );
        }
        if case.method == "JWT" {
            assert!(exchanges.iter().all(|exchange| exchange.path == "/token"));
            let original = db.tables(&["users", "accounts", "sessions"]).await?;
            let denied = call(&auth, request("/sign-in/social", Some(json!({"provider":case.name,"idToken":{"token":grant_response(Some(&case.profile))["id_token"]}})), ""), 404).await;
            assert_eq!(body(&denied)["code"], "ID_TOKEN_NOT_SUPPORTED");
            assert_eq!(
                db.tables(&["users", "accounts", "sessions"]).await?,
                original
            );
        } else {
            let profile = exchanges
                .iter()
                .find(|exchange| exchange.path.split('?').next() == Some("/profile"))
                .unwrap();
            assert_eq!(profile.method, case.method, "{}", case.name);
            if case.name == "vk" {
                let form: HashMap<String, String> = url::form_urlencoded::parse(&profile.body)
                    .into_owned()
                    .collect();
                assert_eq!(form["access_token"], "remote-access");
                assert_eq!(form["client_id"], "native-client");
            } else {
                assert_eq!(
                    profile.headers["authorization"], "Bearer remote-access",
                    "{}",
                    case.name
                );
            }
            let profile_url = remote.url.join(&profile.path)?;
            let query: HashMap<String, String> = profile_url.query_pairs().into_owned().collect();
            if case.name == "paypal" {
                assert_eq!(query["schema"], "paypalv1.1");
            }
            if case.name == "tiktok" {
                assert_eq!(
                    query["fields"],
                    "open_id,avatar_large_url,display_name,username"
                );
                assert_eq!(form["client_key"], "native-client");
            }
            if case.name == "reddit" {
                assert_eq!(profile.headers["user-agent"], "better-auth");
                assert_eq!(token.headers["accept"], "text/plain");
            }
            if case.name == "twitter" {
                let email = exchanges
                    .iter()
                    .find(|exchange| exchange.path == "/email")
                    .unwrap();
                assert_eq!(email.method, "GET");
                assert_eq!(email.headers["authorization"], "Bearer remote-access");
            }
            if case.name == "dropbox" {
                assert!(profile.body.is_empty());
            }
            if case.name == "linear" {
                let query: Value = serde_json::from_slice(&profile.body)?;
                let query = query["query"].as_str().unwrap();
                for field in ["viewer", "id", "name", "email", "avatarUrl"] {
                    assert!(query.contains(field), "GraphQL selection omits {field}");
                }
            }
            if case.name == "notion" {
                assert_eq!(profile.headers["notion-version"], "2022-06-28");
            }
        }
        if mapping {
            let received = mapped_profiles.lock().unwrap().clone();
            if case.name == "tiktok" {
                assert!(
                    received.is_empty(),
                    "TikTok intentionally ignores application mapping"
                );
            } else {
                let mut expected = match case.name {
                    "notion" => case.profile.pointer("/bot/owner/user").unwrap().clone(),
                    _ => case.profile.clone(),
                };
                if case.name == "twitter" {
                    expected["data"]["email"] = json!("twitter@example.test");
                }
                assert_eq!(received, vec![expected], "{} mapper input", case.name);
            }
            if matches!(case.name, "railway" | "paypal") {
                let original = db.tables(&["users", "accounts", "sessions"]).await?;
                let mut failed = (case.factory)(remote.url.join("profile")?.as_str())
                    .with_profile_mapper(Arc::new(FailedMapper));
                failed.token_url = remote.url.join("token")?.into();
                let failed_auth = builder::<B>(&connection)
                    .plugin(OAuthPlugin::new().add_provider(case.name, failed.clone()))
                    .build()
                    .await?;
                let (authorization, cookie) = begin(&failed_auth, case.name).await;
                let mut callback = request(&format!("/callback/{}", case.name), None, &cookie);
                callback.query.extend([
                    ("state".into(), authorization["state"].clone()),
                    ("code".into(), "one-use-grant".into()),
                ]);
                let denied = call(
                    &failed_auth,
                    callback,
                    if case.name == "railway" { 500 } else { 302 },
                )
                .await;
                if case.name == "paypal" {
                    assert_eq!(
                        url::Url::parse(denied.headers.get("location").unwrap())?.path(),
                        "/failed"
                    );
                }
                assert!(!cookies(&denied).contains("session_token="));
                assert_eq!(
                    db.tables(&["users", "accounts", "sessions"]).await?,
                    original
                );
                drop(remote.take());
                if case.name == "railway" {
                    // A later application handler supersedes the installed
                    // factory mapper, whose error would otherwise reject login.
                    failed.get_user_info = Some(Arc::new(CustomProfile));
                    let custom = builder::<B>(&connection)
                        .plugin(OAuthPlugin::new().add_provider(case.name, failed))
                        .build()
                        .await?;
                    let (authorization, cookie) = begin(&custom, case.name).await;
                    let accepted = complete(&custom, case.name, &authorization, &cookie).await;
                    authenticated(&custom, &cookies(&accepted), "custom@example.test").await;
                    assert_eq!(
                        db.count_where(
                            "SELECT COUNT(*) FROM accounts WHERE account_id=$1",
                            &["custom-raw-subject"]
                        )
                        .await?,
                        1
                    );
                    assert_eq!(
                        db.text(
                            "SELECT name FROM users WHERE email=$1",
                            &["custom@example.test"]
                        )
                        .await?
                        .as_deref(),
                        Some("Custom handler")
                    );
                    assert!(
                        remote
                            .take()
                            .iter()
                            .all(|exchange| exchange.path == "/token")
                    );
                }
            }
            B::close(connection).await?;
            continue;
        }
        if matches!(case.name, "cloudflare" | "naver" | "paypal") {
            let original = db.tables(&["users", "accounts", "sessions"]).await?;
            let controls = if case.name == "paypal" {
                vec![json!("foreign-subject"), json!(41)]
            } else {
                vec![Value::Null]
            };
            for control in controls {
                if case.name == "paypal" {
                    // The otherwise successful userinfo must not substitute for
                    // the identity returned by the grant endpoint.
                    if control.is_number() {
                        let mut profile = case.profile.clone();
                        profile["user_id"] = json!("41");
                        remote.respond_at("/profile", 200, profile);
                    }
                    remote.respond_at("/token", 200, grant_response(Some(&json!({"sub":control}))));
                } else {
                    let mut envelope = case.profile.clone();
                    if case.name == "cloudflare" {
                        envelope["success"] = json!(false);
                    } else {
                        envelope["resultcode"] = json!("99");
                    }
                    remote.respond_at("/profile", 200, envelope);
                }
                let (authorization, cookie) = begin(&auth, case.name).await;
                let denied = complete(&auth, case.name, &authorization, &cookie).await;
                assert_eq!(
                    url::Url::parse(denied.headers.get("location").unwrap())?.path(),
                    "/failed"
                );
                assert!(!cookies(&denied).contains("session_token="));
                assert_eq!(
                    db.tables(&["users", "accounts", "sessions"]).await?,
                    original
                );
                assert!(!remote.take().is_empty());
            }
            remote.respond_at("/profile", 200, case.profile.clone());
        }
        if matches!(case.name, "notion" | "vercel") {
            let original = db.table("accounts").await?;
            let account = db.text("SELECT id FROM accounts", &[]).await?.unwrap();
            remote.respond_at("/token",200,json!({"access_token":"refresh-access","refresh_token":"refresh-rotated","expires_in":3600}));
            let response = call(
                &auth,
                request(
                    "/refresh-token",
                    Some(json!({"accountId":account})),
                    &cookies(&accepted),
                ),
                if case.name == "notion" { 200 } else { 400 },
            )
            .await;
            if case.name == "vercel" {
                assert_eq!(body(&response)["code"], "TOKEN_REFRESH_NOT_SUPPORTED");
                assert!(remote.take().is_empty());
                assert_eq!(db.table("accounts").await?, original);
            } else {
                let exchanges = remote.take();
                assert_eq!(exchanges.len(), 1);
                assert_eq!(exchanges[0].path, "/token");
                assert!(!exchanges[0].headers.contains_key("authorization"));
                let form: HashMap<String, String> = url::form_urlencoded::parse(&exchanges[0].body)
                    .into_owned()
                    .collect();
                assert_eq!(form["grant_type"], "refresh_token");
                assert_eq!(form["refresh_token"], "remote-refresh");
                assert_eq!(form["client_id"], "native-client");
                assert_eq!(form["client_secret"], "native-secret");
                assert_eq!(body(&response)["accessToken"], "refresh-access");
                assert_eq!(
                    db.text("SELECT refresh_token FROM accounts", &[])
                        .await?
                        .as_deref(),
                    Some("refresh-rotated")
                );
            }
        }
        // A structurally usable profile with only its raw subject removed must
        // not borrow identity from an existing email or create another account.
        let mut invalid = case.profile;
        *invalid.pointer_mut(case.subject_pointer).unwrap() = Value::Null;
        if case.method == "JWT" {
            remote.respond_at("/token", 200, grant_response(Some(&invalid)));
        } else {
            remote.respond_at("/profile", 200, invalid);
        }
        let original = db.tables(&["users", "accounts", "sessions"]).await?;
        let (authorization, state_cookie) = begin(&auth, case.name).await;
        let denied = complete(&auth, case.name, &authorization, &state_cookie).await;
        let target = url::Url::parse(denied.headers.get("location").unwrap())?;
        assert_eq!(target.path(), "/failed", "{}", case.name);
        assert!(
            target.query_pairs().any(|(key, _)| key == "error"),
            "{}",
            case.name
        );
        assert!(
            !cookies(&denied).contains("session_token="),
            "{}",
            case.name
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            original,
            "{}",
            case.name
        );
        assert!(
            remote
                .take()
                .iter()
                .any(|exchange| exchange.path.split('?').next()
                    == Some(if case.method == "JWT" {
                        "/token"
                    } else {
                        "/profile"
                    }))
        );
        B::close(connection).await?;
    }
    Ok(())
}

fn grant_response(profile: Option<&Value>) -> Value {
    let mut grant = json!({"access_token":"remote-access","refresh_token":"remote-refresh","token_type":"Bearer","expires_in":3600});
    if let Some(profile) = profile {
        // These factories decode claims delivered by their trusted token endpoint;
        // they intentionally expose no standalone ID-token verification API.
        grant["id_token"] = json!(format!(
            "e30.{}.grant-signature",
            URL_SAFE_NO_PAD.encode(profile.to_string())
        ));
    }
    grant
}
