//! Phone database hooks must apply through every trusted store facade and remain local to one auth instance.

use better_auth::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthAccount, AuthSession, AuthUser, CreateUser, UpdateUser};
use better_auth_seaorm::{Database, SeaOrmStore};
use std::sync::Arc;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned plugins/phone-number/index: init installs the null-phone reset before
    // user updates, including internalAdapter updates outside public endpoint guards.
    #[tokio::test]
    async fn phone_null_update_hook_is_local_to_the_auth_instance_and_all_store_facades() {
        let config = AuthConfig::new("phone-hook-fixture-secret-minimum-32-characters");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
        let enabled = AuthBuilder::new(config.clone())
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&store))
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
            .build()
            .await
            .unwrap();
        let disabled = AuthBuilder::new(config)
            .store_arc(store)
            .build()
            .await
            .unwrap();

        for (instance, auth) in [("enabled", &enabled), ("disabled", &disabled)] {
            for via_context in [false, true] {
                let writer = if via_context {
                    &auth.context().database
                } else {
                    auth.store()
                };
                let mut input = CreateUser::new()
                    .with_email(format!("{instance}-{via_context}@phone-hook.fixture.test"))
                    .with_name("Verified Phone");
                input.phone_number = Some(format!(
                    "+12025550{}{}",
                    if instance == "enabled" { "1" } else { "2" },
                    if via_context { "10" } else { "11" }
                ));
                input.phone_number_verified = Some(true);
                let user = writer.create_user(input).await.unwrap();

                let renamed = writer
                    .update_user(
                        &user.id(),
                        UpdateUser {
                            name: Some("Same Phone".into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(renamed.phone_number_verified(), Some(true));
                assert_eq!(renamed.phone_number(), user.phone_number());

                let cleared = writer
                    .update_user(
                        &user.id(),
                        UpdateUser {
                            phone_number: Some(None),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(cleared.phone_number(), None);
                assert_eq!(
                    cleared.phone_number_verified(),
                    Some(instance == "disabled"),
                    "instance {instance}, context facade {via_context}"
                );
                let persisted = auth
                    .store()
                    .get_user_by_id(&user.id())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(persisted.phone_number(), None);
                assert_eq!(
                    persisted.phone_number_verified(),
                    cleared.phone_number_verified()
                );
            }
        }
    }

    // The enabled phone schema accepts ownership claims, but its verification field
    // is server-owned. The disabled instance treats these as unregistered inputs.
    #[tokio::test]
    async fn signup_phone_fields_require_the_plugin_and_cannot_claim_verification() {
        use better_auth::plugins::EmailPasswordPlugin;
        use better_auth_core::{AuthRequest, HttpMethod};
        use serde_json::{Value, json};

        let config = AuthConfig::new("phone-signup-fixture-secret-minimum-32-characters");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
        let enabled = AuthBuilder::new(config.clone())
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&store))
            .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
            .build()
            .await
            .unwrap();
        let disabled = AuthBuilder::new(config)
            .store_arc(store)
            .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .build()
            .await
            .unwrap();

        for (instance, auth) in [("enabled", &enabled), ("disabled", &disabled)] {
            for (index, (input, expected, rejected)) in [
                (
                    json!({"phoneNumber":"+12025550911"}),
                    Some("+12025550911"),
                    false,
                ),
                (json!({"phoneNumber":1234}), Some("1234"), false),
                (json!({"phoneNumber":true}), Some("1"), false),
                (
                    json!({"phoneNumber":null,"phoneNumberVerified":false}),
                    None,
                    false,
                ),
                (json!({"phoneNumberVerified":0}), None, false),
                (json!({"phoneNumberVerified":""}), None, false),
                (json!({"phoneNumberVerified":true}), None, true),
                (json!({"phoneNumberVerified":[]}), None, true),
            ]
            .into_iter()
            .enumerate()
            {
                let email = format!("{instance}-{index}@phone-signup.fixture.test");
                let mut body = json!({"email":email,"password":"password123","name":"Phone Owner"});
                body.as_object_mut()
                    .unwrap()
                    .extend(input.as_object().unwrap().clone());
                let mut req = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
                req.body = Some(serde_json::to_vec(&body).unwrap());
                drop(
                    req.headers
                        .insert("content-type".into(), "application/json".into()),
                );
                drop(
                    req.headers
                        .insert("origin".into(), "http://localhost:3000".into()),
                );
                let response = auth.handle_request(req).await.unwrap();
                let payload: Value = serde_json::from_slice(&response.body).unwrap();
                let stored = auth.store().get_user_by_email(&email).await.unwrap();
                if instance == "enabled" && rejected {
                    assert_eq!(response.status, 400);
                    assert_eq!(
                        payload,
                        json!({"code":"FIELD_NOT_ALLOWED","message":"phoneNumberVerified is not allowed to be set"})
                    );
                    assert!(stored.is_none());
                    assert!(!response.headers.contains_key("set-cookie"));
                    continue;
                }
                assert_eq!(response.status, 200, "{instance}, {input}");
                let user = stored.unwrap();
                assert_eq!(
                    user.phone_number(),
                    if instance == "enabled" {
                        expected
                    } else {
                        None
                    }
                );
                assert_eq!(user.phone_number_verified(), None);
                let token = payload.get("token").and_then(Value::as_str).unwrap();
                let session = auth.store().get_session(token).await.unwrap().unwrap();
                assert_eq!(session.user_id(), user.id());
                let accounts = auth.store().get_user_accounts(&user.id()).await.unwrap();
                assert_eq!(accounts.len(), 1);
                assert_eq!(accounts.first().unwrap().provider_id(), "credential");
            }
        }
    }

    // The real adapter owns numeric text affinity. The same JS-rounded number can
    // have a distinct stored value depending on the primitive binding type.
    #[tokio::test]
    async fn numeric_phone_signup_uses_actual_adapter_text_coercion() {
        use better_auth::plugins::EmailPasswordPlugin;
        use better_auth_core::store::NumericTextInput;
        use better_auth_core::{AuthRequest, HttpMethod};

        let config = AuthConfig::new("phone-numeric-fixture-secret-minimum-32-characters");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database))
            .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
            .build()
            .await
            .unwrap();

        // JSON numeric overflow reaches infinity in JavaScript. NaN has no valid
        // JSON number spelling and must never enter the finite conversion.
        for value in [f64::NAN] {
            let error = auth
                .store()
                .coerce_user_text_number(NumericTextInput::Real(value))
                .await
                .unwrap_err();
            assert_eq!(error.status_code(), 400);
        }
        assert_eq!(
            auth.store()
                .coerce_user_text_number(NumericTextInput::Integer(i64::MAX))
                .await
                .unwrap(),
            "9223372036854775807"
        );
        for (index, (literal, expected)) in [
            ("1.0", "1"),
            ("1e3", "1000"),
            ("1e-5", "1.0e-05"),
            ("1e20", "1.0e+20"),
            ("-0.0", "0.0"),
            ("2147483648", "2147483648"),
            ("1e14", "100000000000000"),
            ("2251799813685247", "2251799813685247"),
            ("-2251799813685248", "-2251799813685248"),
            ("47.49", "47.49"),
            ("1e400", "Inf"),
            ("-1e400", "-Inf"),
        ]
        .into_iter()
        .enumerate()
        {
            let email = format!("numeric-{index}@phone-numeric.fixture.test");
            let mut req = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
            req.body=Some(format!("{{\"email\":\"{email}\",\"password\":\"password123\",\"name\":\"Phone Numeric\",\"phoneNumber\":{literal}}}").into_bytes());
            drop(
                req.headers
                    .insert("content-type".into(), "application/json".into()),
            );
            drop(
                req.headers
                    .insert("origin".into(), "http://localhost:3000".into()),
            );
            let response = auth.handle_request(req).await.unwrap();
            assert_eq!(response.status, 200, "raw phone number {literal}");
            let user = auth
                .store()
                .get_user_by_email(&email)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                user.phone_number(),
                Some(expected),
                "raw phone number {literal}"
            );
            assert_eq!(user.phone_number_verified(), None);
            let payload: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            let token = (*(payload).get("token").unwrap_or(&serde_json::Value::Null))
                .as_str()
                .unwrap();
            assert_eq!(
                auth.store()
                    .get_session(token)
                    .await
                    .unwrap()
                    .unwrap()
                    .user_id(),
                user.id()
            );
            assert_eq!(
                auth.store()
                    .get_user_accounts(&user.id())
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}
