use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyExtensions, PasskeyExtensionsResolver, PasskeyOptionsContext, PasskeyRegistrationConfig,
};
use alibi::store::PasskeyStore;
use alibi::utils::json::{self as native, JsValue};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ValueResolver(JsValue, Arc<AtomicUsize>);

#[async_trait::async_trait]
impl PasskeyExtensionsResolver for ValueResolver {
    async fn resolve(&self, _: &PasskeyOptionsContext<'_>) -> alibi::AuthResult<JsValue> {
        _ = self.1.fetch_add(1, Ordering::SeqCst);
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn passkey_extension_values_match_actual_generation() {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/generation_extension_cases.json"
    ))
    .unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for (index, case) in cases.iter().enumerate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let input = case["input"].clone();
        let resolver = case["resolver"].as_bool().unwrap();
        let extension = if resolver {
            PasskeyExtensions::Resolver(Arc::new(ValueResolver(input, calls.clone())))
        } else {
            PasskeyExtensions::Static(input)
        };
        let registration = case["operation"] == "registration";
        let plugin = PasskeyPlugin::new()
            .rp_id("localhost")
            .rp_name("Names")
            .origin(ORIGIN);
        let plugin = if registration {
            plugin.registration(PasskeyRegistrationConfig {
                extensions: Some(extension),
                ..Default::default()
            })
        } else {
            plugin.authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                extensions: Some(extension),
                after_verification: None,
            })
        };
        let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(plugin)
            .build()
            .await
            .unwrap();
        let owner = cookies(&signup(&auth, &format!("extensions-{index}@example.com")).await);
        let endpoint = if registration {
            PasskeyPlugin::generate_passkey_registration_options_endpoint()
        } else {
            PasskeyPlugin::generate_passkey_authentication_options_endpoint()
        };
        let output = Box::pin(auth.dispatch_endpoint(
            endpoint,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), owner)].into()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("{}: {}", case["mode"].as_str().unwrap(), error.error));
        let result = output.decode().unwrap();
        assert_eq!(
            result["extensions"],
            case["extensions"],
            "{registration}/{resolver}/{}",
            case["mode"].as_str().unwrap()
        );
        assert_eq!(
            result.as_object().unwrap().contains_key("extensions"),
            case["own"].as_bool().unwrap()
        );
        assert_eq!(
            result["extensions"].is_undefined(),
            case["undefined"].as_bool().unwrap()
        );
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(resolver));
        let undefined = JsValue::Array(
            result
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, value)| value.is_undefined())
                .map(|(key, _)| JsValue::String(key.clone()))
                .collect(),
        );
        assert_eq!(undefined, case["undefined_keys"]);
        let wire = native::from_slice::<JsValue>(&output.into_response().unwrap().body).unwrap();
        let mut stable = wire.clone();
        _ = stable.as_object_mut().unwrap().shift_remove("challenge");
        let mut expected = case["options"].clone();
        if registration {
            _ = stable["user"].as_object_mut().unwrap().shift_remove("id");
            let email = JsValue::String(format!("extensions-{index}@example.com").into());
            expected["user"]["name"] = email.clone();
            expected["user"]["displayName"] = email;
        }
        assert_eq!(stable, expected);
        if case["undefined"] == true {
            assert!(wire.get("extensions").is_none());
        } else {
            assert_eq!(wire["extensions"], case["extensions"]);
        }
    }
}

struct Mutation {
    store: Arc<dyn PasskeyStore>,
    user_id: Mutex<String>,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl PasskeyExtensionsResolver for Mutation {
    async fn resolve(&self, _: &PasskeyOptionsContext<'_>) -> alibi::AuthResult<JsValue> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let user_id = self.user_id.lock().unwrap().clone();
        _ = self
            .store
            .create_passkey(alibi::CreatePasskey {
                user_id,
                name: JsValue::Undefined,
                public_key: "public".into(),
                credential_id: URL_SAFE_NO_PAD.encode(format!("extension-{call}")),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: JsValue::String("usb".into()),
                created_at: JsValue::Undefined,
                aaguid: JsValue::Undefined,
            })
            .await?;
        Ok(JsValue::Object(Default::default()))
    }
}

fn mutation_plugin(policy: Arc<Mutation>, registration: bool) -> PasskeyPlugin {
    let plugin = PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Names")
        .origin(ORIGIN);
    if registration {
        plugin.registration(PasskeyRegistrationConfig {
            extensions: Some(PasskeyExtensions::Resolver(policy)),
            ..Default::default()
        })
    } else {
        plugin.authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
            extensions: Some(PasskeyExtensions::Resolver(policy)),
            after_verification: None,
        })
    }
}

async fn check_read_order<S: AuthSchema>(
    auth: &Alibi<S>,
    policy: &Mutation,
    backend: &str,
    registration: bool,
) {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/plugins/src/passkey/generation_read_order_cases.json"
    ))
    .unwrap();
    let operation = if registration {
        "registration"
    } else {
        "authentication"
    };
    let owner = signup(auth, &format!("read-order-{operation}@example.com")).await;
    *policy.user_id.lock().unwrap() = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend && case["operation"] == operation)
    {
        count += 1;
        let endpoint = if registration {
            PasskeyPlugin::generate_passkey_registration_options_endpoint()
        } else {
            PasskeyPlugin::generate_passkey_authentication_options_endpoint()
        };
        let output = Box::pin(auth.dispatch_endpoint(
            endpoint,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into()),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .decode()
        .unwrap();
        let field = if registration {
            "excludeCredentials"
        } else {
            "allowCredentials"
        };
        assert_eq!(
            output[field], case["descriptors"],
            "{backend}/{operation}/{count}"
        );
        assert_eq!(policy.calls.load(Ordering::SeqCst), count);
        let user_id = policy.user_id.lock().unwrap().clone();
        assert_eq!(
            policy
                .store
                .list_passkeys_by_user(&user_id)
                .await
                .unwrap()
                .len(),
            count
        );
    }
    assert_eq!(count, 2);
}

backend_tests!(passkey_extensions_mutate_after_credential_reads);

async fn passkey_extensions_mutate_after_credential_reads<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for registration in [true, false] {
        let store = Arc::new(B::store(Arc::new(AuthConfig::new(SECRET)), &connection));
        let policy = Arc::new(Mutation {
            store: store.clone(),
            user_id: Mutex::new(String::new()),
            calls: AtomicUsize::new(0),
        });
        let auth = builder::<B>(&connection)
            .store_arc(store)
            .plugin(mutation_plugin(policy.clone(), registration))
            .build()
            .await?;
        check_read_order(&auth, &policy, "sqlite", registration).await;
    }
    B::close(connection).await
}

#[tokio::test]
async fn memory_passkey_extensions_mutate_after_credential_reads() {
    for registration in [true, false] {
        let store = Arc::new(alibi::store::stateless::StatelessStore::default());
        let policy = Arc::new(Mutation {
            store: store.clone(),
            user_id: Mutex::new(String::new()),
            calls: AtomicUsize::new(0),
        });
        let auth = AuthBuilder::without_database(AuthConfig::new(SECRET).base_url(ORIGIN))
            .store_arc(store)
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(mutation_plugin(policy.clone(), registration))
            .build()
            .await
            .unwrap();
        check_read_order(&auth, &policy, "memory", registration).await;
    }
}
