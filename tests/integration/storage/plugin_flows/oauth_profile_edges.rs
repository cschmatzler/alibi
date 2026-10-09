//! Provider profile handlers and account-subject rules driven directly with wire profiles.
use super::oauth_profiles::profiles;
use super::*;
use alibi::plugins::oauth::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

type Mapper = fn(Value) -> Result<OAuthUserInfo, String>;
type Build = fn(&str, Option<Mapper>) -> OAuthProvider;

macro_rules! build {
    ($options:ident, $method:ident, $secret:expr) => {
        |endpoint, mapper| {
            let mut options = $options::new("native-client", $secret);
            options.user_info_endpoint = Some(endpoint.into());
            options.map_profile_to_user = mapper;
            OAuthProvider::$method(options)
        }
    };
}

fn optional() -> Option<String> {
    Some("native-secret".into())
}

fn bearer_providers() -> Vec<(&'static str, Build)> {
    vec![
        (
            "atlassian",
            build!(AtlassianOptions, atlassian_with_options, "native-secret"),
        ),
        (
            "cloudflare",
            build!(CloudflareOptions, cloudflare_with_options, optional()),
        ),
        (
            "dropbox",
            build!(DropboxOptions, dropbox_with_options, optional()),
        ),
        (
            "figma",
            build!(FigmaOptions, figma_with_options, optional()),
        ),
        (
            "huggingface",
            build!(HuggingFaceOptions, huggingface_with_options, optional()),
        ),
        (
            "kakao",
            build!(KakaoOptions, kakao_with_options, optional()),
        ),
        ("kick", build!(KickOptions, kick_with_options, optional())),
        (
            "linear",
            build!(LinearOptions, linear_with_options, optional()),
        ),
        (
            "linkedin",
            build!(LinkedInOptions, linkedin_with_options, optional()),
        ),
        (
            "naver",
            build!(NaverOptions, naver_with_options, optional()),
        ),
        (
            "notion",
            build!(NotionOptions, notion_with_options, optional()),
        ),
        (
            "paypal",
            build!(PayPalOptions, paypal_with_options, "native-secret"),
        ),
        (
            "polar",
            build!(PolarOptions, polar_with_options, optional()),
        ),
        (
            "railway",
            build!(RailwayOptions, railway_with_options, optional()),
        ),
        (
            "reddit",
            build!(RedditOptions, reddit_with_options, optional()),
        ),
    ]
}

/// Atlassian dispatches to a dedicated handler only when a mapper is configured.
fn plain_mapper(name: &str) -> Option<Mapper> {
    (name == "atlassian").then_some(mapped as Mapper)
}

pub(super) fn mapped(_: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: "mapped-id".into(),
        email: "mapped@example.test".into(),
        name: Some("Mapped".into()),
        image: Some("https://images.test/mapped".into()),
        email_verified: true,
        additional_fields: Default::default(),
    })
}

pub(super) fn wire(name: &str) -> (Value, &'static str) {
    let case = profiles()
        .into_iter()
        .find(|case| case.name == name && case.variant == "default")
        .unwrap();
    (case.profile, case.subject_pointer)
}

pub(super) async fn fetch(
    provider: &OAuthProvider,
    id_token: Option<String>,
) -> Result<OAuthUserInfoResponse, String> {
    provider
        .get_user_info
        .as_ref()
        .unwrap()
        .get_user_info(OAuthUserInfoRequest {
            access_token: Some("access".into()),
            id_token,
            ..Default::default()
        })
        .await
}

/// Admission outcome: the profile handler and the account-subject rule must both accept.
pub(super) async fn admitted(
    provider: &OAuthProvider,
    id_token: Option<String>,
) -> Result<String, String> {
    let response = fetch(provider, id_token).await?;
    match provider.account_subject {
        Some(subject) => subject(&response.data),
        None => Ok(response.user.id),
    }
}

pub(super) fn unsigned(claims: &Value) -> String {
    format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
}

#[tokio::test]
async fn handlers_publish_application_mapped_profiles() {
    for (name, build) in bearer_providers() {
        let (profile, _) = wire(name);
        let remote = Provider::start("application/json", profile.to_string()).await;
        let provider = build(remote.url.as_str(), Some(mapped));
        let response = fetch(&provider, None).await.unwrap();
        assert_eq!(response.user.email, "mapped@example.test", "{name}");
        if !matches!(name, "reddit" | "atlassian" | "cloudflare") {
            assert_eq!(response.user.id, "mapped-id", "{name}");
        }
        if let Some(output) = response.user_output {
            assert_eq!(output["email"], "mapped@example.test", "{name}");
        }
    }
}

#[tokio::test]
async fn account_subjects_accept_numbers_and_reject_blank_or_literal_nulls() {
    for (name, build) in bearer_providers() {
        let (profile, pointer) = wire(name);
        for (replacement, expected) in [
            (json!(42), Some("42")),
            (json!(1.5), Some("1.5")),
            (json!(" "), None),
            (json!("undefined"), None),
            (json!("null"), None),
            (json!(""), None),
        ] {
            let mut profile = profile.clone();
            *profile.pointer_mut(pointer).unwrap() = replacement.clone();
            let remote = Provider::start("application/json", profile.to_string()).await;
            let provider = build(remote.url.as_str(), plain_mapper(name));
            let outcome = admitted(&provider, None).await;
            match expected {
                Some(subject) => assert_eq!(outcome.as_deref(), Ok(subject), "{name}"),
                None => assert!(outcome.is_err(), "{name} {replacement}: {outcome:?}"),
            }
        }
    }
}

#[tokio::test]
async fn handlers_fail_closed_on_remote_failures_and_malformed_bodies() {
    for (name, build) in bearer_providers() {
        let remote = Provider::start("application/json", "{}").await;
        let provider = build(remote.url.as_str(), plain_mapper(name));
        for (status, body) in [(500, "{}"), (200, "not json"), (200, "null"), (200, "{}")] {
            remote.respond(status, "application/json", body);
            let outcome = admitted(&provider, None).await;
            assert!(outcome.is_err(), "{name} {status} {body}: {outcome:?}");
        }
    }
}

#[tokio::test]
async fn kakao_profile_falls_back_through_name_and_thumbnail() {
    let remote = Provider::start(
        "application/json",
        json!({"id":7,"kakao_account":{"name":"Account Name","email":"k@example.test","is_email_valid":1,"is_email_verified":1.5,"profile":{"nickname":"","profile_image_url":0,"thumbnail_image_url":"https://images.test/thumb"}}}).to_string(),
    )
    .await;
    let build: Build = build!(KakaoOptions, kakao_with_options, optional());
    let provider = build(remote.url.as_str(), None);
    let user = fetch(&provider, None).await.unwrap().user;
    assert_eq!(user.name.as_deref(), Some("Account Name"));
    assert_eq!(user.image.as_deref(), Some("https://images.test/thumb"));
    assert!(user.email_verified);
}

#[tokio::test]
async fn id_token_profiles_are_decoded_before_any_remote_lookup() {
    let remote = Provider::start("application/json", "{}").await;
    let endpoint = remote.url.join("profile").unwrap();
    let line = |mapper| {
        let mut options = LineOptions::new("native-client", optional());
        options.user_info_endpoint = Some(endpoint.to_string());
        options.map_profile_to_user = mapper;
        OAuthProvider::line_with_options(options)
    };
    let facebook = |mapper| {
        let mut options = FacebookOptions::new("native-client", optional());
        options.user_info_endpoint = Some(endpoint.to_string());
        options.map_profile_to_user = mapper;
        OAuthProvider::facebook_with_options(options)
    };
    let cognito = |mapper| {
        let mut options = CognitoOptions::new(
            "native-client",
            optional(),
            "pool.example.test",
            "us-east-1",
            "pool",
        );
        options.user_info_endpoint = Some(endpoint.to_string());
        options.map_profile_to_user = mapper;
        OAuthProvider::cognito(options).unwrap()
    };
    let paybin = |mapper| {
        let mut options = PaybinOptions::new("native-client", optional());
        options.map_profile_to_user = mapper;
        OAuthProvider::paybin_with_options(options)
    };
    let providers: Vec<(&str, Box<dyn Fn(Option<Mapper>) -> OAuthProvider>)> = vec![
        ("line", Box::new(line)),
        ("facebook", Box::new(facebook)),
        ("cognito", Box::new(cognito)),
        ("paybin", Box::new(paybin)),
    ];
    for (name, make) in &providers {
        let claims = json!({"sub":42,"name":"Token User","email":"token@example.test","picture":"https://images.test/token"});
        let provider = make(None);
        assert_eq!(
            admitted(&provider, Some(unsigned(&claims)))
                .await
                .as_deref(),
            Ok("42"),
            "{name}"
        );
        for blank in [json!(" "), json!("undefined")] {
            let mut claims = claims.clone();
            claims["sub"] = blank;
            let outcome = admitted(&provider, Some(unsigned(&claims))).await;
            assert!(outcome.is_err(), "{name}: {outcome:?}");
        }
        let response = fetch(&make(Some(mapped)), Some(unsigned(&claims)))
            .await
            .unwrap();
        assert_eq!(response.user.id, "mapped-id", "{name}");
        assert!(remote.take().is_empty(), "{name} must not call out");
    }
}

#[tokio::test]
async fn undecodable_id_tokens_defer_to_the_profile_endpoint_or_fail() {
    let remote = Provider::start(
        "application/json",
        json!({"sub":"remote-sub","id":"remote-sub","email":"remote@example.test"}).to_string(),
    )
    .await;
    let endpoint = remote.url.join("profile").unwrap().to_string();
    let mut options = CognitoOptions::new(
        "native-client",
        optional(),
        "pool.example.test",
        "us-east-1",
        "pool",
    );
    options.user_info_endpoint = Some(endpoint.clone());
    let cognito = OAuthProvider::cognito(options).unwrap();
    for token in ["one-part", &unsigned(&json!([1]))] {
        let response = fetch(&cognito, Some(token.into())).await.unwrap();
        assert_eq!(response.user.id, "remote-sub");
    }
    let mut options = FacebookOptions::new("native-client", optional());
    options.user_info_endpoint = Some(endpoint);
    let facebook = OAuthProvider::facebook_with_options(options);
    let outcome = fetch(&facebook, Some(unsigned(&json!([1])))).await;
    assert_eq!(outcome.unwrap_err(), "Invalid Facebook ID profile");
}
