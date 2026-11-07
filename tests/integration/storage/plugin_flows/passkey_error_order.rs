use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyUserResolver,
    VerifiedPasskeyRegistration,
};
use alibi::utils::json::{self as native, JsString, JsValue};

backend_tests!(passkey_registration_missing_user_precedes_transport_failure);

struct Policy {
    user_id: Mutex<String>,
    callbacks: Mutex<usize>,
}

#[async_trait::async_trait]
impl PasskeyUserResolver for Policy {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: Option<&JsString>,
    ) -> alibi::AuthResult<Option<PasskeyRegistrationUser>> {
        Ok(Some(PasskeyRegistrationUser {
            id: self.user_id.lock().unwrap().clone(),
            name: "Owner".into(),
            display_name: None,
        }))
    }
}

#[async_trait::async_trait]
impl PasskeyRegistrationAfterVerification for Policy {
    async fn after_verification(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: &VerifiedPasskeyRegistration,
        _: &PasskeyRegistrationUser,
        _: &JsValue,
        _: Option<&JsString>,
    ) -> alibi::AuthResult<Option<PasskeyRegistrationOverride>> {
        *self.callbacks.lock().unwrap() += 1;
        Ok(None)
    }
}

fn plugin(policy: Arc<Policy>) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Names")
        .origin(ORIGIN)
        .registration(PasskeyRegistrationConfig {
            require_session: false,
            resolve_user: Some(policy.clone()),
            after_verification: Some(policy),
            ..Default::default()
        })
}

async fn check_order<S: AuthSchema>(auth: &Alibi<S>, backend: &str, policy: Arc<Policy>) {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/registration_error_order_cases.json"
    ))
    .unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let user_id = body(&signup(auth, "registration-order@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend)
    {
        count += 1;
        let owner = if case["user_exists"] == true || case["create_session"] == false {
            user_id.clone()
        } else {
            "missing-owner".into()
        };
        *policy.user_id.lock().unwrap() = owner;
        let options = Box::pin(auth.dispatch_endpoint(
            PasskeyPlugin::generate_passkey_registration_options_endpoint(),
            Default::default(),
        ))
        .await
        .unwrap()
        .into_response()
        .unwrap();
        let key =
            super::passkey_matrix::Authenticator::new(47, &format!("registration-order-{count}"));
        let proof = key.registration(
            &json!({"type":"webauthn.create","challenge":body(&options)["challenge"],"origin":ORIGIN}),
            &key.attestation("localhost", super::passkey_matrix::USER_PRESENT | super::passkey_matrix::USER_VERIFIED, 6), false,
        );
        let mut proof = native::parse_value(&proof.to_string()).unwrap();
        proof["response"]["transports"] = case["transports"].clone();
        let result = Box::pin(
            auth.dispatch_endpoint(
                PasskeyPlugin::verify_passkey_registration_endpoint(
                    alibi::plugins::passkey::PasskeyRegistrationInput {
                        response: proof.clone(),
                        name: None,
                        create_session: Some(case["create_session"].as_bool().unwrap()),
                    },
                ),
                alibi::endpoint::EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookies(&options)),
                            ("origin".into(), ORIGIN.into()),
                        ]
                        .into(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        assert_eq!(*policy.callbacks.lock().unwrap(), count);
        if let Some(expected) = case.get("error") {
            let error = result.unwrap_err().error;
            assert_eq!(
                u64::from(error.status_code()),
                expected["status"].as_u64().unwrap()
            );
            assert_eq!(
                error.error_payload().1.as_deref(),
                expected["body"]["code"].as_str(),
                "{backend}/{count}"
            );
            assert_eq!(
                error.error_payload().2,
                expected["body"]["message"].as_str().unwrap()
            );
        } else {
            assert!(result.is_ok());
        }
        assert_eq!(
            auth.store()
                .get_passkey_by_credential_id(proof["id"].as_str().unwrap())
                .await
                .unwrap()
                .is_some(),
            case["persisted"] == 1
        );
    }
    assert_eq!(count, 11);
}

async fn passkey_registration_missing_user_precedes_transport_failure<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy {
        user_id: Mutex::new("initial".into()),
        callbacks: Mutex::new(0),
    });
    let auth = builder::<B>(&connection)
        .plugin(plugin(policy.clone()))
        .build()
        .await?;
    check_order(&auth, "sqlite", policy).await;
    B::close(connection).await
}

#[tokio::test]
async fn memory_passkey_registration_missing_user_precedes_transport_failure() {
    let policy = Arc::new(Policy {
        user_id: Mutex::new("initial".into()),
        callbacks: Mutex::new(0),
    });
    let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(plugin(policy.clone()))
        .build()
        .await
        .unwrap();
    check_order(&auth, "memory", policy).await;
}
