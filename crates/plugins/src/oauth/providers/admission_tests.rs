use super::*;
use crate::oauth::handlers::{callback_core, fetch_user_info_from_provider};
use crate::oauth::state::{OAuthStatePayload, state_verification_identifier};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::{
    AuthError, AuthRequest, AuthResponse, CreateVerification, HttpMethod, OAuthStateStrategy,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) struct HttpFixture {
    pub(super) url: String,
    server: tokio::task::JoinHandle<()>,
}
impl HttpFixture {
    pub(super) async fn new(status: u16, body: Value) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 8192];
                let _ = stream.read(&mut request).await.unwrap();
                let inspect = request.starts_with(b"GET /inspect?");
                let status = if inspect { 200 } else { status };
                let body = if inspect {
                    crate::oauth::providers::js!({"data":{"is_valid":true,"app_id":"client","user_id":"1"}})
                        .to_string()
                } else {
                    body.to_string()
                };
                stream.write_all(format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await.unwrap();
            }
        });
        Self { url, server }
    }
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct RawIdMapper(Value);
#[async_trait]
impl OAuthProfileMapper for RawIdMapper {
    async fn map_profile(&self, _: Value) -> Result<Map, String> {
        Ok(crate::oauth::providers::js!({"id": self.0})
            .as_object()
            .unwrap()
            .clone())
    }
}

#[tokio::test]
async fn mapped_public_ids_do_not_run_object_to_primitive_coercion() {
    use base64::Engine;
    for mapped_id in [
        crate::oauth::providers::js!({"toString":0}),
        crate::oauth::providers::js!([{"toString":0}]),
        Value::Null,
    ] {
        let profile = crate::oauth::providers::js!({"sub":"subject","email":"a@example.com"});
        let token = format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
        );
        let mut generic = GenericOAuthConfig::new("client", "secret");
        generic.map_profile = Some(Arc::new(RawIdMapper(mapped_id.clone())));
        for provider in [
            OAuthProvider::google("client", "secret")
                .with_profile_mapper(Arc::new(RawIdMapper(mapped_id.clone()))),
            generic.resolve().await.unwrap().unwrap().provider,
        ] {
            let response = fetch_user_info_from_provider(
                &provider,
                OAuthUserInfoRequest {
                    id_token: Some(token.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(response.user["id"], mapped_id);
            assert_eq!(response.data["sub"], "subject");
            assert_eq!(
                provider.account_subject.unwrap()(&response.data).unwrap(),
                "subject"
            );
        }
    }
}

pub(super) struct RejectMapper;
#[async_trait]
impl OAuthProfileMapper for RejectMapper {
    async fn map_profile(&self, _: Value) -> Result<Map, String> {
        Err("application mapping threw".into())
    }
}
pub(super) struct RejectHandler;
#[async_trait]
impl OAuthUserInfoHandler for RejectHandler {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        Err("application profile handler threw".into())
    }
}
struct Grant(OAuthTokenSet);
#[async_trait]
impl OAuthAuthorizationCodeHandler for Grant {
    async fn validate_authorization_code(
        &self,
        _: OAuthAuthorizationCodeContext,
    ) -> Result<OAuthTokenSet, String> {
        Ok(self.0.clone())
    }
}

fn provider(name: &str, endpoint: &str) -> OAuthProvider {
    macro_rules! endpoint_provider {
        ($options:ident, $factory:ident) => {{
            let mut options = $options::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::$factory(options)
        }};
    }
    match name {
        "atlassian" => {
            let mut options = AtlassianOptions::new("client", "secret");
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::atlassian_with_options(options)
        }
        "dropbox" => endpoint_provider!(DropboxOptions, dropbox_with_options),
        "figma" => endpoint_provider!(FigmaOptions, figma_with_options),
        "huggingface" => endpoint_provider!(HuggingFaceOptions, huggingface_with_options),
        "kakao" => endpoint_provider!(KakaoOptions, kakao_with_options),
        "kick" => endpoint_provider!(KickOptions, kick_with_options),
        "line" => endpoint_provider!(LineOptions, line_with_options),
        "linear" => endpoint_provider!(LinearOptions, linear_with_options),
        "linkedin" => endpoint_provider!(LinkedInOptions, linkedin_with_options),
        "facebook" => {
            let mut options = FacebookOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint.into());
            options.token_inspection_endpoint = Some(format!("{endpoint}/inspect"));
            OAuthProvider::facebook_with_options(options)
        }
        "cloudflare" => {
            let mut options = CloudflareOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::cloudflare_with_options(options)
        }
        "cognito" => {
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
        "paypal" => {
            let mut options = PayPalOptions::new("client", "secret");
            options.user_info_endpoint = Some(endpoint.into());
            OAuthProvider::paypal_with_options(options)
        }
        "github" => OAuthProvider::github_with_endpoints(
            "client", "secret", endpoint, endpoint, endpoint, endpoint,
        ),
        "gitlab" => OAuthProvider::gitlab_with_issuer("client", "secret", endpoint),
        _ => panic!("unregistered fixture {name}"),
    }
}

pub(super) fn request() -> OAuthUserInfoRequest {
    OAuthUserInfoRequest {
        access_token: Some("access".into()),
        ..Default::default()
    }
}
fn is_exception(error: &AuthError) -> bool {
    matches!(error, AuthError::Api { code: Some(code), .. } if code == "OAUTH_PROFILE_EXCEPTION")
}
pub(super) async fn callback(mut provider: OAuthProvider, tokens: OAuthTokenSet) -> AuthResponse {
    provider.authorization.as_mut().unwrap().authorization_code =
        Some(OAuthAuthorizationCodeCallback(Arc::new(Grant(tokens))));
    let mut config = crate::test_helpers::create_test_config();
    config.account.store_state_strategy = OAuthStateStrategy::Database;
    config.account.skip_state_cookie_check = true;
    let ctx = crate::test_helpers::create_test_context_with_config(config).await;
    let payload = OAuthStatePayload::new(
        "http://localhost:3000/done".into(),
        "verifier".into(),
        None,
        None,
        None,
        None,
        serde_json::Map::new(),
    );
    ctx.verifications()
        .create(CreateVerification {
            identifier: state_verification_identifier("state"),
            value: serde_json::to_string(&payload).unwrap(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap()
        .unwrap();
    let config = OAuthConfig {
        providers: HashMap::from([("provider".into(), provider)]),
        ..Default::default()
    };
    callback_core(
        &config,
        "provider",
        &HashMap::from([
            ("state".into(), "state".into()),
            ("code".into(), "code".into()),
        ]),
        &AuthRequest::new(HttpMethod::Get, "/callback/provider"),
        &ctx,
    )
    .await
    .unwrap()
}
pub(super) async fn assert_outcome(
    provider: OAuthProvider,
    request: OAuthUserInfoRequest,
    exception: bool,
) {
    let error = fetch_user_info_from_provider(&provider, request.clone())
        .await
        .unwrap_err();
    assert_eq!(is_exception(&error), exception, "{error:?}");
    let response = callback(
        provider,
        OAuthTokenSet {
            access_token: request.access_token,
            id_token: request.id_token,
            raw: request.raw,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(response.status, if exception { 500 } else { 302 });
    if exception {
        assert!(!response.headers.contains_key("location"));
        assert!(!response.headers.contains_key("set-cookie"));
    } else {
        assert!(response.headers["location"].contains("unable_to_get_user_info"));
        assert!(response.headers.contains_key("set-cookie"));
    }
}

#[tokio::test]
async fn dedicated_profiles_distinguish_null_transport_and_mapping_exceptions_through_callback() {
    let profile = crate::oauth::providers::js!({
        "id":"1", "sub":"subject", "oid":"object", "user_id":"user", "account_id":"account",
        "state":"active", "email":"user@example.com", "name":"User",
        "picture":{"data":{"url":"https://example.com/photo"}},
        "data":[{"user_id":1,"name":"User","email":"user@example.com"}],
        "success":true, "result":{"id":"cf","email":"user@example.com"}
    });
    for name in [
        "atlassian",
        "cloudflare",
        "cognito",
        "dropbox",
        "facebook",
        "figma",
        "github",
        "gitlab",
        "huggingface",
        "kakao",
        "kick",
        "line",
        "linear",
        "linkedin",
        "paypal",
    ] {
        let mut body = profile.clone();
        if name == "linear" {
            body = crate::oauth::providers::js!({"data":{"viewer":{"id":"viewer","name":"User"}}});
        }
        let server = HttpFixture::new(200, body).await;
        let mapped = provider(name, &server.url).with_profile_mapper(Arc::new(RejectMapper));
        let caught = matches!(name, "atlassian" | "cognito" | "figma" | "paypal");
        assert_outcome(mapped, request(), !caught).await;

        let failure = HttpFixture::new(500, Value::Null).await;
        assert_outcome(provider(name, &failure.url), request(), false).await;

        let mut custom = provider(name, &server.url);
        custom.get_user_info = Some(Arc::new(RejectHandler));
        assert_outcome(custom, request(), true).await;
    }
}

#[tokio::test]
async fn dedicated_raw_fields_and_account_subjects_do_not_require_scalar_profiles() {
    for name in [
        "atlassian",
        "cloudflare",
        "cognito",
        "dropbox",
        "figma",
        "huggingface",
        "kakao",
        "kick",
        "line",
        "linear",
        "linkedin",
    ] {
        for subject in [
            crate::oauth::providers::js!({}),
            crate::oauth::providers::js!(["raw", 7]),
            Value::Null,
        ] {
            let raw = crate::oauth::providers::js!({
                "id":subject, "sub":subject, "account_id":subject, "user_id":subject,
                "email":{"raw":true}, "name":{"raw":true}, "handle":{"raw":true},
                "picture":{"raw":true}, "img_url":{"raw":true}, "avatarUrl":{"raw":true},
                "kakao_account":{"email":{"raw":true},"profile":{"nickname":{"raw":true}}},
            });
            let body = match name {
                "cloudflare" => crate::oauth::providers::js!({"success":true,"result":raw}),
                "kick" => crate::oauth::providers::js!({"data":[raw]}),
                "linear" => crate::oauth::providers::js!({"data":{"viewer":raw}}),
                _ => raw.clone(),
            };
            let server = HttpFixture::new(200, body).await;
            let provider = provider(name, &server.url);
            let response = fetch_user_info_from_provider(&provider, request())
                .await
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(response.data, raw, "{name}");
            let expected = super::remaining_profile::raw_subject(Some(&subject));
            assert_eq!(
                provider.account_subject.unwrap()(&response.data),
                expected,
                "{name}"
            );
            assert!(!response.user.is_empty(), "{name}");
        }
    }
    let provider = OAuthProvider::facebook("client", "secret");
    for subject in [
        crate::oauth::providers::js!({}),
        crate::oauth::providers::js!(["raw", 7]),
        Value::Null,
    ] {
        assert_eq!(
            provider.account_subject.unwrap()(
                &crate::oauth::providers::js!({"sub":subject,"id":"fallback"})
            ),
            super::remaining_profile::raw_subject(Some(&subject))
        );
    }
}

#[tokio::test]
async fn kick_profile_indexing_accepts_object_properties_and_bmp_strings() {
    for (rows, expected) in [
        (
            crate::oauth::providers::js!({"0":{"user_id":"one","name":"User"}}),
            crate::oauth::providers::js!({"user_id":"one","name":"User"}),
        ),
        (
            crate::oauth::providers::js!("éz"),
            crate::oauth::providers::js!("é"),
        ),
    ] {
        let server = HttpFixture::new(200, crate::oauth::providers::js!({"data":rows})).await;
        let response = fetch_user_info_from_provider(&provider("kick", &server.url), request())
            .await
            .unwrap();
        assert_eq!(response.data, expected);
    }
    struct NullMapper(Arc<std::sync::atomic::AtomicUsize>);
    #[async_trait]
    impl OAuthProfileMapper for NullMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile, Value::Null);
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Map::new())
        }
    }
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = HttpFixture::new(200, crate::oauth::providers::js!({"data":{"0":null}})).await;
    assert_outcome(
        provider("kick", &server.url).with_profile_mapper(Arc::new(NullMapper(calls.clone()))),
        request(),
        true,
    )
    .await;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cloudflare_name_join_coercion_is_a_source_exception() {
    let server = HttpFixture::new(
        200,
        crate::oauth::providers::js!({
            "success":true, "result":{"id":"cf","first_name":{"toString":0}}
        }),
    )
    .await;
    assert_outcome(provider("cloudflare", &server.url), request(), true).await;
}

#[tokio::test]
async fn repository_profiles_defer_missing_subject_admission_until_after_mapping() {
    for (name, profile) in [
        (
            "github",
            crate::oauth::providers::js!({"email":"a@example.com"}),
        ),
        (
            "gitlab",
            crate::oauth::providers::js!({"state":"active","email":"a@example.com"}),
        ),
    ] {
        let server = HttpFixture::new(200, profile).await;
        let provider = provider(name, &server.url);
        let response = fetch_user_info_from_provider(&provider, request())
            .await
            .unwrap();
        assert!(provider.account_subject.unwrap()(&response.data).is_err());
        assert_outcome(
            provider.with_profile_mapper(Arc::new(RejectMapper)),
            request(),
            true,
        )
        .await;
    }
}

#[tokio::test]
async fn dedicated_null_profile_admission_matches_source_checks() {
    for (name, throws) in [
        ("atlassian", false),
        ("cloudflare", false),
        ("cognito", false),
        ("dropbox", true),
        ("facebook", false),
        ("figma", false),
        ("github", false),
        ("gitlab", true),
        ("huggingface", true),
        ("kakao", false),
        ("kick", true),
        ("line", false),
        ("linear", false),
        ("linkedin", true),
        ("paypal", false),
    ] {
        let server = HttpFixture::new(200, Value::Null).await;
        assert_outcome(provider(name, &server.url), request(), throws).await;
    }
}

#[tokio::test]
async fn jwt_profile_admission_distinguishes_absence_decode_and_mapping_exceptions() {
    let mut microsoft = MicrosoftOptions::new("client", Some("secret".into()));
    microsoft.disable_profile_photo = true;
    for provider in [
        OAuthProvider::apple("client", "secret"),
        OAuthProvider::google("client", "secret"),
        OAuthProvider::microsoft(microsoft).unwrap(),
        OAuthProvider::twitch("client", Some("secret")),
    ] {
        assert_outcome(provider.clone(), request(), false).await;
        assert_outcome(
            provider.clone(),
            OAuthUserInfoRequest {
                id_token: Some("malformed".into()),
                ..request()
            },
            true,
        )
        .await;
        use base64::Engine;
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(r#"{"sub":"subject","oid":"object"}"#)
        );
        assert_outcome(
            provider.with_profile_mapper(Arc::new(RejectMapper)),
            OAuthUserInfoRequest {
                id_token: Some(token),
                ..request()
            },
            true,
        )
        .await;
    }
}

#[tokio::test]
async fn microsoft_verification_throws_after_mapping_and_uses_raw_email() {
    use base64::Engine;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountMapper(Arc<AtomicUsize>);
    #[async_trait]
    impl OAuthProfileMapper for CountMapper {
        async fn map_profile(&self, _: Value) -> Result<Map, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Map::new())
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let mut options = MicrosoftOptions::new("client", None);
    options.disable_profile_photo = true;
    let provider = OAuthProvider::microsoft(options)
        .unwrap()
        .with_profile_mapper(Arc::new(CountMapper(count.clone())));
    for (list, verified) in [
        (crate::oauth::providers::js!([7]), true),
        (crate::oauth::providers::js!(["7"]), false),
        (crate::oauth::providers::js!("prefix7suffix"), true),
    ] {
        let profile =
            crate::oauth::providers::js!({"oid":"object","email":7,"verified_primary_email":list});
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
        );
        let response = fetch_user_info_from_provider(
            &provider,
            OAuthUserInfoRequest {
                id_token: Some(token),
                ..request()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.user["emailVerified"], verified);
    }
    let token = format!(
        "e30.{}.sig",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"oid":"object","email":7,"verified_primary_email":true}"#)
    );
    assert_outcome(
        provider,
        OAuthUserInfoRequest {
            id_token: Some(token),
            ..request()
        },
        true,
    )
    .await;
    assert_eq!(count.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn apple_missing_subject_still_runs_mapper_before_account_admission() {
    assert_outcome(
        OAuthProvider::apple("client", "secret").with_profile_mapper(Arc::new(RejectMapper)),
        OAuthUserInfoRequest {
            id_token: Some("e30.e30.sig".into()),
            ..request()
        },
        true,
    )
    .await;
}

#[tokio::test]
async fn facebook_inspection_null_and_custom_handler_throw_are_distinct() {
    let server = HttpFixture::new(200, Value::Null).await;
    let mut options = FacebookOptions::new("client", Some("secret".into()));
    options.token_inspection_endpoint = Some(format!("{}/inspect", server.url));
    options.get_user_info = Some(Arc::new(RejectHandler));
    assert_outcome(
        OAuthProvider::facebook_with_options(options.clone()),
        request(),
        true,
    )
    .await;
    options.token_inspection_endpoint = Some(server.url.clone());
    assert_outcome(
        OAuthProvider::facebook_with_options(options),
        request(),
        false,
    )
    .await;
}

#[tokio::test]
async fn facebook_missing_picture_is_a_source_exception_not_profile_null() {
    let server = HttpFixture::new(
        200,
        crate::oauth::providers::js!({"id":"1","email":"user@example.com"}),
    )
    .await;
    assert_outcome(provider("facebook", &server.url), request(), true).await;
}
