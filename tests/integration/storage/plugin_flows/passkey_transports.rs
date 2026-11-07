use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, VerifiedPasskeyRegistration,
};
use alibi::utils::json::{self as native, JsString, JsValue};

backend_tests!(passkey_transport_metadata_matches_actual_registration);

struct TransportPolicy(Arc<Mutex<Vec<Option<JsValue>>>>);

#[async_trait::async_trait]
impl PasskeyRegistrationAfterVerification for TransportPolicy {
    async fn after_verification(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: &VerifiedPasskeyRegistration,
        _: &PasskeyRegistrationUser,
        client: &JsValue,
        _: Option<&JsString>,
    ) -> alibi::AuthResult<Option<PasskeyRegistrationOverride>> {
        self.0
            .lock()
            .unwrap()
            .push(client["response"].get("transports").cloned());
        Ok(None)
    }
}

fn plugin(observed: Arc<Mutex<Vec<Option<JsValue>>>>) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Names")
        .origin(ORIGIN)
        .registration(PasskeyRegistrationConfig {
            after_verification: Some(Arc::new(TransportPolicy(observed))),
            ..Default::default()
        })
}

async fn check_transports<S: AuthSchema>(
    auth: &Alibi<S>,
    backend: &str,
    observed: Arc<Mutex<Vec<Option<JsValue>>>>,
) {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/transport_cases.json"
    ))
    .unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let owner = cookies(&signup(auth, "transports@example.com").await);
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend)
    {
        count += 1;
        let mode = case["mode"].as_str().unwrap();
        let credentials = || alibi::endpoint::EndpointOptions {
            headers: Some(
                [
                    ("cookie".into(), owner.clone()),
                    ("origin".into(), ORIGIN.into()),
                ]
                .into(),
            ),
            ..Default::default()
        };
        let options = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_registration_options_endpoint(),
            credentials(),
        ))
        .await
        .unwrap()
        .into_response()
        .unwrap();
        let key = super::passkey_matrix::Authenticator::new(43, &format!("transport-{mode}"));
        let options_value = native::from_slice::<JsValue>(&options.body).unwrap();
        let proof = key.registration(
            &json!({"type":"webauthn.create","challenge":options_value["challenge"].as_str().unwrap(),"origin":ORIGIN}),
            &key.attestation("localhost", super::passkey_matrix::USER_PRESENT | super::passkey_matrix::USER_VERIFIED, 6), false,
        );
        let mut proof = native::parse_value(&proof.to_string()).unwrap();
        _ = proof["response"]
            .as_object_mut()
            .unwrap()
            .shift_remove("transports");
        let mut transport = case["input"].clone();
        for path in case["undefined_paths"].as_array().unwrap() {
            let mut slot = &mut transport;
            for index in path.as_array().unwrap() {
                let JsValue::Array(values) = slot else {
                    panic!("fixture path must address an array")
                };
                slot = &mut values[usize::try_from(index.as_u64().unwrap()).unwrap()];
            }
            *slot = JsValue::Undefined;
        }
        let expected = if case["present"].as_bool().unwrap() {
            _ = proof["response"]
                .as_object_mut()
                .unwrap()
                .insert("transports".into(), transport.clone());
            Some(transport)
        } else {
            None
        };
        let result = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::verify_passkey_registration_endpoint(
                    alibi::plugins::passkey::PasskeyRegistrationInput {
                        response: proof.clone(),
                        name: None,
                        create_session: None,
                    },
                ),
                alibi::endpoint::EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), format!("{owner}; {}", cookies(&options))),
                            ("origin".into(), ORIGIN.into()),
                        ]
                        .into(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        {
            let calls = observed.lock().unwrap();
            assert_eq!(calls.len(), count, "{backend}/{mode}: callback count");
            assert_eq!(
                calls.last().unwrap(),
                &expected,
                "{backend}/{mode}: original metadata"
            );
        }
        let stored = auth
            .store()
            .get_passkey_by_credential_id(proof["id"].as_str().unwrap())
            .await
            .unwrap();
        if let Some(error) = case.get("error") {
            let error_native = result.unwrap_err().error;
            assert_eq!(
                u64::from(error_native.status_code()),
                error["status"].as_u64().unwrap()
            );
            assert_eq!(
                error_native.error_payload().1.as_deref(),
                error["body"]["code"].as_str()
            );
            assert_eq!(
                error_native.error_payload().2,
                error["body"]["message"].as_str().unwrap()
            );
            assert!(stored.is_none());
            continue;
        }
        let output = result
            .unwrap_or_else(|error| panic!("{backend}/{mode}: {}", error.error))
            .decode()
            .unwrap();
        assert_eq!(output["transports"], case["transports"]);
        assert_eq!(
            output["createdAt"].as_date().is_some(),
            case["date"].as_bool().unwrap()
        );
        assert_eq!(stored.unwrap().transports, case["transports"]);
        let registration = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_registration_options_endpoint(),
            credentials(),
        ))
        .await
        .unwrap()
        .decode()
        .unwrap();
        let descriptor = registration["excludeCredentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|credential| credential["id"] == proof["id"])
            .unwrap();
        assert_eq!(*descriptor, case["registration_descriptor"]);
        let authentication = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_authentication_options_endpoint(),
            credentials(),
        ))
        .await
        .unwrap()
        .decode()
        .unwrap();
        let descriptor = authentication["allowCredentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|credential| credential["id"] == proof["id"])
            .unwrap();
        assert_eq!(*descriptor, case["authentication_descriptor"]);
    }
    assert_eq!(count, 16);
}

async fn passkey_transport_metadata_matches_actual_registration<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let auth = builder::<B>(&connection)
        .plugin(plugin(observed.clone()))
        .build()
        .await?;
    check_transports(&auth, "sqlite", observed).await;
    B::close(connection).await
}

#[tokio::test]
async fn memory_passkey_transport_metadata_matches_actual_registration() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(plugin(observed.clone()))
        .build()
        .await
        .unwrap();
    check_transports(&auth, "memory", observed).await;
}
