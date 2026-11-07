use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyExtensions, PasskeyExtensionsResolver, PasskeyOptionsContext, PasskeyRegistrationConfig,
};
use alibi::utils::json::{self as native, JsValue};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Observe(AtomicUsize);

#[async_trait::async_trait]
impl PasskeyExtensionsResolver for Observe {
    async fn resolve(&self, _: &PasskeyOptionsContext<'_>) -> alibi::AuthResult<JsValue> {
        _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(JsValue::Object(Default::default()))
    }
}

fn plugin(observe: Arc<Observe>) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .origin(ORIGIN)
        .registration(PasskeyRegistrationConfig {
            extensions: Some(PasskeyExtensions::Resolver(observe.clone())),
            ..Default::default()
        })
        .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
            extensions: Some(PasskeyExtensions::Resolver(observe)),
            after_verification: None,
        })
}

async fn check_descriptors<S: AuthSchema>(
    auth: &Alibi<S>,
    observe: &Observe,
    physical: Option<&Db>,
) -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/stored_descriptor_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    let owner = signup(auth, "descriptors@example.com").await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    for (index, case) in cases.iter().enumerate() {
        let row = auth
            .store()
            .create_passkey(alibi::CreatePasskey {
                user_id: user_id.clone(),
                name: JsValue::Undefined,
                public_key: "public".into(),
                credential_id: case["input"].as_str().unwrap().into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: JsValue::String("usb,nfc".into()),
                created_at: JsValue::Undefined,
                aaguid: JsValue::Undefined,
            })
            .await?;
        let before = if let Some(db) = physical {
            Some(db.count("verification").await?)
        } else {
            None
        };
        let registration = case["operation"] == "registration";
        let endpoint = if registration {
            PasskeyPlugin::generate_passkey_registration_options_endpoint()
        } else {
            PasskeyPlugin::generate_passkey_authentication_options_endpoint()
        };
        let result = Box::pin(auth.dispatch_endpoint(
            endpoint,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into()),
                ..Default::default()
            },
        ))
        .await;
        assert_eq!(observe.0.load(Ordering::SeqCst), index + 1);
        if case.get("error").is_some() {
            let error = result.expect_err(case["mode"].as_str().unwrap());
            assert_eq!(error.error.status_code(), 500);
            if let Some(db) = physical {
                assert_eq!(Some(db.count("verification").await?), before);
            }
        } else {
            let output = result.unwrap().decode()?;
            let field = if registration {
                "excludeCredentials"
            } else {
                "allowCredentials"
            };
            let descriptor = &output[field].as_array().unwrap()[0];
            assert_eq!(
                *descriptor,
                case["descriptor"],
                "{}",
                case["mode"].as_str().unwrap()
            );
            let keys = JsValue::Array(
                descriptor
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .map(JsValue::String)
                    .collect(),
            );
            assert_eq!(keys, case["keys"]);
        }
        auth.store().delete_passkey(&row.id).await?;
    }
    Ok(())
}

backend_tests!(stored_passkey_descriptors_match_actual_generator);

async fn stored_passkey_descriptors_match_actual_generator<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observe = Arc::new(Observe(AtomicUsize::new(0)));
    let auth = builder::<B>(&connection)
        .plugin(plugin(observe.clone()))
        .build()
        .await?;
    check_descriptors(&auth, &observe, Some(&db)).await?;
    B::close(connection).await
}

#[tokio::test]
async fn memory_stored_passkey_descriptors_match_actual_generator() -> TestResult {
    let observe = Arc::new(Observe(AtomicUsize::new(0)));
    let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(plugin(observe.clone()))
        .build()
        .await?;
    check_descriptors(&auth, &observe, None).await
}
