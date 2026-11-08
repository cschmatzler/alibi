use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyRegistrationConfig, PasskeyRegistrationContext, PasskeyRegistrationUser,
    PasskeyUserResolver,
};
use alibi::utils::json::{self as native, JsString, JsValue};
use std::collections::BTreeMap;

backend_tests!(passkey_registration_clock_matches_actual_millisecond_storage);
postgres_tests!(passkey_registration_clock_matches_actual_millisecond_storage);

#[derive(Default)]
struct Owner(Mutex<String>);

#[async_trait::async_trait]
impl PasskeyUserResolver for Owner {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: Option<&JsString>,
    ) -> alibi::AuthResult<Option<PasskeyRegistrationUser>> {
        Ok(Some(PasskeyRegistrationUser {
            id: self.0.lock().unwrap().clone(),
            name: "Clock".into(),
            display_name: None,
        }))
    }
}

async fn exchange<S: AuthSchema>(
    auth: &Alibi<S>,
    jar: &mut BTreeMap<String, String>,
    path: &str,
    input: Option<Value>,
) -> TestResult<Value> {
    let mut request = AuthRequest::new(
        if input.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        format!("/api/auth{path}"),
    );
    request.headers.extend([
        ("origin".into(), "http://localhost".into()),
        ("content-type".into(), "application/json".into()),
        (
            "cookie".into(),
            jar.iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    ]);
    request.body = input.map(|input| serde_json::to_vec(&input)).transpose()?;
    let response = Box::pin(auth.handle_request(request)).await?;
    for header in response.headers.get_all("set-cookie") {
        let (name, value) = header.split(';').next().unwrap().split_once('=').unwrap();
        if value.is_empty() {
            _ = jar.remove(name);
        } else {
            _ = jar.insert(name.into(), value.into());
        }
    }
    let output: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(response.status, 200, "{path}: {output}");
    Ok(output)
}

async fn passkey_registration_clock_matches_actual_millisecond_storage<B: Backend>(
    db: Db,
) -> TestResult {
    let secret = "passkey-clock-source-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/passkey-registration-clock.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let cases = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let owner = Arc::new(Owner::default());
        let config = AuthConfig::new(secret).base_url("http://localhost");
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(
                PasskeyPlugin::new()
                    .rp_id("localhost")
                    .rp_name("Clock")
                    .origin("http://localhost")
                    .registration(PasskeyRegistrationConfig {
                        require_session: mode == "session",
                        resolve_user: if mode != "session" {
                            Some(owner.clone())
                        } else {
                            None
                        },
                        ..Default::default()
                    }),
            )
            .build()
            .await?;
        let mut jar = BTreeMap::new();
        let user = exchange(&auth, &mut jar, "/sign-up/email", Some(json!({"name":"Clock","email":format!("{mode}@passkey-clock.example.com"),"password":"Password123!"}))).await?;
        *owner.0.lock().unwrap() = user["user"]["id"].as_str().unwrap().into();
        if mode != "session" {
            jar.clear();
        }
        let generated =
            exchange(&auth, &mut jar, "/passkey/generate-register-options", None).await?;
        let key = super::passkey_matrix::Authenticator::new(77, &format!("clock-{mode}"));
        let mut proof = key.registration(&json!({"type":"webauthn.create","challenge":generated["challenge"],"origin":"http://localhost"}), &key.attestation("localhost", super::passkey_matrix::USER_PRESENT | super::passkey_matrix::USER_VERIFIED, 6), false);
        _ = proof["response"]
            .as_object_mut()
            .unwrap()
            .remove("transports");
        let credential = proof["id"].as_str().unwrap().to_owned();
        let mut input = json!({"response":proof});
        if mode == "resolved-session" {
            input["createSession"] = json!(true);
        }
        let output = exchange(&auth, &mut jar, "/passkey/verify-registration", Some(input)).await?;
        let stored = auth
            .store()
            .get_passkey_by_credential_id(&credential)
            .await?
            .ok_or("registered passkey missing")?;
        let JsValue::Date(date) = &stored.created_at else {
            panic!("generated registration clock must be a Date")
        };
        let clock = json!({"millisecond_aligned": date.timestamp_subsec_nanos() % 1_000_000 == 0, "persisted_matches_output": native::to_value(&stored.created_at)? == output["createdAt"]});
        assert_eq!(clock, case["clock"], "{backend}/{mode}");
    }
    B::close(connection).await
}
