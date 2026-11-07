use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyRegistrationContext, PasskeyRegistrationUser, PasskeyUserResolver,
};
use alibi::utils::json::{self as native, JsValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

struct QueryResolver {
    seen: Arc<Mutex<Option<JsValue>>>,
    verified: Arc<Mutex<Option<JsValue>>>,
    resolved: JsValue,
}

#[tokio::test]
async fn passkey_null_extensions_match_actual_registration_options() {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/generation_extension_cases.json"
    ))
    .unwrap();
    let expected = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["operation"] == "registration"
                && case["resolver"] == false
                && case["mode"] == "null"
        })
        .unwrap();
    let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
        .plugin(EmailPasswordPlugin::new())
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .origin(ORIGIN)
                .registration(alibi::plugins::passkey::PasskeyRegistrationConfig {
                    extensions: Some(alibi::plugins::passkey::PasskeyExtensions::Static(
                        json!(null).into(),
                    )),
                    ..Default::default()
                }),
        )
        .build()
        .await
        .unwrap();
    let cookie = cookies(&signup(&auth, "null-extensions@example.com").await);
    let output = Box::pin(auth.dispatch_endpoint(
        PasskeyPlugin::generate_passkey_registration_options_endpoint(),
        alibi::endpoint::EndpointOptions {
            headers: Some([("cookie".into(), cookie)].into()),
            ..Default::default()
        },
    ))
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(output["extensions"], expected["extensions"]);
}

#[async_trait::async_trait]
impl PasskeyUserResolver for QueryResolver {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        context: Option<&alibi::utils::json::JsString>,
    ) -> alibi::AuthResult<Option<PasskeyRegistrationUser>> {
        *self.seen.lock().unwrap() =
            Some(context.map_or(JsValue::Null, |context| JsValue::String(context.clone())));
        Ok(Some(native::from_value(self.resolved.clone())?))
    }
}

#[async_trait::async_trait]
impl alibi::plugins::passkey::PasskeyRegistrationAfterVerification for QueryResolver {
    async fn after_verification(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: &alibi::plugins::passkey::VerifiedPasskeyRegistration,
        user: &PasskeyRegistrationUser,
        _: &JsValue,
        context: Option<&alibi::utils::json::JsString>,
    ) -> alibi::AuthResult<Option<alibi::plugins::passkey::PasskeyRegistrationOverride>> {
        assert_eq!(native::to_js_value(user)?, self.resolved);
        *self.verified.lock().unwrap() =
            Some(context.map_or(JsValue::Null, |context| JsValue::String(context.clone())));
        Ok(None)
    }
}

#[tokio::test]
async fn passkey_generation_queries_match_actual_endpoint_and_stored_context() {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/generation_query_cases.json"
    ))
    .unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let seen = Arc::new(Mutex::new(None));
        let verified = Arc::new(Mutex::new(None));
        let policy = Arc::new(QueryResolver {
            seen: seen.clone(),
            verified: verified.clone(),
            resolved: case["resolved"].clone(),
        });
        let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
            .plugin(
                PasskeyPlugin::new()
                    .rp_id("localhost")
                    .rp_name("Names")
                    .origin(ORIGIN)
                    .registration(alibi::plugins::passkey::PasskeyRegistrationConfig {
                        require_session: false,
                        resolve_user: Some(policy.clone()),
                        after_verification: Some(policy),
                        ..Default::default()
                    }),
            )
            .build()
            .await
            .unwrap();
        let result = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::generate_passkey_registration_options_endpoint()
                    .with_query_value(case["query"].clone()),
                alibi::endpoint::EndpointOptions::default(),
            ),
        )
        .await;
        let mode = case["mode"].as_str().unwrap();
        if let Some(error) = case.get("error") {
            let rejected = result.unwrap_err();
            assert_eq!(
                u64::from(rejected.error.status_code()),
                error["status"].as_u64().unwrap(),
                "{mode}"
            );
            assert_eq!(
                rejected.error.error_payload().2,
                error["body"]["message"].as_str().unwrap(),
                "{mode}"
            );
            assert!(seen.lock().unwrap().is_none(), "{mode}");
            continue;
        }
        let output = result
            .unwrap_or_else(|error| panic!("{mode}: {}", error.error))
            .into_response()
            .unwrap();
        let value = native::from_slice::<JsValue>(&output.body).unwrap();
        let mut stable = value.clone();
        _ = stable.as_object_mut().unwrap().shift_remove("challenge");
        _ = stable["user"].as_object_mut().unwrap().shift_remove("id");
        assert_eq!(stable, case["options"], "{mode}: stable generation options");
        assert_eq!(value["user"]["name"], case["user"]["name"], "{mode}");
        assert_eq!(
            value["user"]["displayName"], case["user"]["displayName"],
            "{mode}"
        );
        assert_eq!(seen.lock().unwrap().as_ref(), Some(&case["seen"]), "{mode}");
        let signed = cookies(&output);
        let token = signed.split_once('=').unwrap().1;
        let claims = native::from_slice::<JsValue>(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let stored = auth
            .context()
            .verifications()
            .find(claims["token"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        let state = native::parse_value(stored.value().unwrap()).unwrap();
        assert_eq!(state["context"], case["stored"], "{mode}");
        assert_eq!(state["user"], case["stored_user"], "{mode}");
        let key = super::passkey_matrix::Authenticator::new(41, "query-key");
        let proof = key.registration(
            &json!({"type":"webauthn.create","challenge":value["challenge"].as_str().unwrap(),"origin":ORIGIN}),
            &key.attestation("localhost", super::passkey_matrix::USER_PRESENT | super::passkey_matrix::USER_VERIFIED, 6), false,
        );
        let registered = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::verify_passkey_registration_endpoint(
                alibi::plugins::passkey::PasskeyRegistrationInput {
                    response: native::parse_value(&proof.to_string()).unwrap(),
                    name: None,
                    create_session: None,
                },
            ),
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), signed), ("origin".into(), ORIGIN.into())].into()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("{mode}: {}", error.error));
        assert_eq!(registered.decode().unwrap()["userId"], "owner");
        assert_eq!(
            verified.lock().unwrap().as_ref(),
            Some(&case["stored"]),
            "{mode}"
        );
    }
}
