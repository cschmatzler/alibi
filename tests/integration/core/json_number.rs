//! JSON wire conversion must not mask incorrect persisted metadata or mutate delivery inputs.

use async_trait::async_trait;
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink,
};
use better_auth::plugins::{ApiKeyPlugin, EmailPasswordPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::{
    AuthRequest, AuthResponse, AuthResult, CreateOrganization, HttpMethod, UpdateOrganization,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::Value;
use std::sync::{Arc, Mutex};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://json-numbers.fixture.test";

const METADATA: &str = r#"{"z":1,"a":2,"10":1e21,"2":1e400,"1":-0.0,"rounded":9007199254740993,"nested":[-1e400,229069639655724.625],"scientific":1e21,"fixed":1e20,"tiny":3.8730639354761726e-71,"reserved":{"$serde_json::private::Number":"1e400"},"raw":{"$serde_json::private::RawValue":"hello"}}"#;

const STORED_METADATA: &str = r#"{"1":0,"2":null,"10":1e+21,"z":1,"a":2,"rounded":9007199254740992,"nested":[null,229069639655724.62],"scientific":1e+21,"fixed":100000000000000000000,"tiny":3.8730639354761726e-71,"reserved":{"$serde_json::private::Number":"1e400"},"raw":{"$serde_json::private::RawValue":"hello"}}"#;

#[derive(Default)]
struct Sender(Mutex<Vec<MagicLinkDelivery>>);

#[async_trait]
impl SendMagicLink for Sender {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

async fn post(
    auth: &BetterAuth<Schema>,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> (AuthResponse, Value) {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(request.headers.insert("origin".into(), ORIGIN.into()));
    if let Some(cookie) = cookie {
        drop(request.headers.insert("cookie".into(), cookie.into()));
    }
    request.body = Some(body.as_bytes().to_vec());
    let response = auth.handle_request(request).await.unwrap();
    let payload = better_auth_core::utils::json::from_slice(&response.body).unwrap();
    (response, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Input schema validation and callback Number semantics precede JSON emission.
    // Premature conversion would silently replace Infinity in application delivery data.
    #[tokio::test]
    async fn magic_delivery_retains_decoded_numbers_until_serialization() {
        let config = AuthConfig::new("json-delivery-secret-minimum-32-characters").base_url(ORIGIN);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let sender = Arc::new(Sender::default());
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database))
            .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                send_magic_link: Some(Arc::<Sender>::clone(&sender)),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap();
        let (response, _) = post(
            &auth,
            "/sign-in/magic-link",
            &format!(r#"{{"email":"delivery@json-numbers.fixture.test","metadata":{METADATA}}}"#),
            None,
        )
        .await;
        assert_eq!(response.status, 200);
        let deliveries = sender.0.lock().unwrap();
        assert_eq!(deliveries.len(), 1);
        let delivery = deliveries.first().unwrap();
        let metadata = delivery.metadata.as_ref().unwrap();
        assert_eq!(
            metadata
                .get("2")
                .and_then(better_auth_core::utils::json::JsValue::as_f64),
            Some(f64::INFINITY)
        );
        assert!(
            metadata
                .get("1")
                .and_then(better_auth_core::utils::json::JsValue::as_f64)
                .unwrap()
                .is_sign_negative()
        );
        assert_eq!(
            metadata
                .get("rounded")
                .and_then(better_auth_core::utils::json::JsValue::as_f64),
            Some(9_007_199_254_740_992.0)
        );
        assert_eq!(
            (*(*(metadata.to_json_value().unwrap())
                .get("nested")
                .unwrap_or(&Value::Null))
            .get(1)
            .unwrap_or(&Value::Null))
            .as_f64(),
            Some(229_069_639_655_724.63)
        );
        let serialized = serde_json::to_value(delivery).unwrap();
        assert!(
            (*(*(serialized).get("metadata").unwrap_or(&Value::Null))
                .get("2")
                .unwrap_or(&Value::Null))
            .is_null()
        );
        assert_eq!(
            (*(*(serialized).get("metadata").unwrap_or(&Value::Null))
                .get("1")
                .unwrap_or(&Value::Null)),
            0
        );
        assert_eq!(
            (*(*(serialized).get("metadata").unwrap_or(&Value::Null))
                .get("fixed")
                .unwrap_or(&Value::Null))
            .as_f64(),
            Some(1e20)
        );
        assert_eq!(
            (*(*(*(serialized).get("metadata").unwrap_or(&Value::Null))
                .get("raw")
                .unwrap_or(&Value::Null))
            .get("$serde_json::private::RawValue")
            .unwrap_or(&Value::Null)),
            "hello"
        );
        assert_eq!(
            metadata
                .get("2")
                .and_then(better_auth_core::utils::json::JsValue::as_f64),
            Some(f64::INFINITY)
        );
        drop(deliveries);
    }

    // Read the actual SQLite JSON columns: a response-only fix would leave lexical
    // overflow and excess integer precision in persistence while these reads fail.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn arbitrary_metadata_stores_javascript_json_and_rejects_foreign_updates() {
        let config = AuthConfig::new("json-storage-secret-minimum-32-characters").base_url(ORIGIN);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(ApiKeyPlugin::builder().enable_metadata(true).build())
            .build()
            .await
            .unwrap();
        let (signup, owner) = post(
        &auth,
        "/sign-up/email",
        r#"{"email":"owner@json-numbers.fixture.test","password":"password123","name":"JSON Owner"}"#,
        None,
    )
    .await;
        assert_eq!(signup.status, 200);
        let cookie = create_session_cookie(
            (*(owner).get("token").unwrap_or(&Value::Null))
                .as_str()
                .unwrap(),
            auth.config(),
        );
        let (created_response, created) = post(
            &auth,
            "/api-key/create",
            &format!(r#"{{"metadata":{METADATA}}}"#),
            Some(&cookie),
        )
        .await;
        assert_eq!(created_response.status, 200);
        assert_eq!(
            (*(created).get("referenceId").unwrap_or(&Value::Null)),
            (*(*(owner).get("user").unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null))
        );
        let key_id = (*(created).get("id").unwrap_or(&Value::Null))
            .as_str()
            .unwrap();
        let row = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata, reference_id FROM api_keys WHERE id = ?",
                [key_id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "metadata").unwrap(),
            STORED_METADATA
        );
        assert_eq!(
            row.try_get::<String>("", "reference_id").unwrap(),
            (*(*(owner).get("user").unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null))
        );

        let (update_response, updated) = post(
        &auth,
        "/api-key/update",
        &format!(
            r#"{{"keyId":"{key_id}","metadata":{{"replacement":[1e400,-0.0,9007199254740993]}}}}"#
        ),
        Some(&cookie),
    )
    .await;
        assert_eq!(update_response.status, 200);
        assert_eq!(
            (*(updated).get("id").unwrap_or(&Value::Null)),
            (*(created).get("id").unwrap_or(&Value::Null))
        );
        let (_, foreign) = post(
        &auth,
        "/sign-up/email",
        r#"{"email":"foreign@json-numbers.fixture.test","password":"password123","name":"Foreign Owner"}"#,
        None,
    )
    .await;
        let foreign_cookie = create_session_cookie(
            (*(foreign)
                .get("token")
                .expect("fixture contains the requested index"))
            .as_str()
            .unwrap(),
            auth.config(),
        );
        let (denied, _) = post(
            &auth,
            "/api-key/update",
            &format!(r#"{{"keyId":"{key_id}","metadata":{METADATA}}}"#),
            Some(&foreign_cookie),
        )
        .await;
        assert_eq!(denied.status, 404);
        let row_2 = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata, reference_id FROM api_keys WHERE id = ?",
                [key_id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row_2.try_get::<String>("", "metadata").unwrap(),
            r#"{"replacement":[null,0,9007199254740992]}"#
        );
        assert_eq!(
            row_2.try_get::<String>("", "reference_id").unwrap(),
            (*(*(owner).get("user").unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null))
        );

        let mut native_metadata = better_auth_core::utils::json::parse_value(METADATA)
            .unwrap()
            .to_json_value()
            .unwrap();
        drop(
            native_metadata
                .as_object_mut()
                .expect("metadata is an object")
                .insert("rounded".to_owned(), Value::from(9_007_199_254_740_993_u64)),
        );
        let organization = auth
            .store()
            .create_organization(
                CreateOrganization::new("JSON Organization", "json-organization")
                    .with_metadata(native_metadata),
            )
            .await
            .unwrap();
        assert_eq!(
            organization.metadata.as_ref().unwrap()["tiny"]
                .as_f64()
                .unwrap()
                .to_bits(),
            0x3151_1b97_697f_234c
        );
        let read = auth
            .store()
            .get_organization_by_id(&organization.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read.metadata.as_ref().unwrap()["tiny"]
                .as_f64()
                .unwrap()
                .to_bits(),
            0x3151_1b97_697f_234c
        );
        let renamed = auth
            .store()
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    name: Some("Readback".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            renamed.metadata.as_ref().unwrap()["tiny"]
                .as_f64()
                .unwrap()
                .to_bits(),
            0x3151_1b97_697f_234c
        );
        let row_3 = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata FROM organization WHERE id = ?",
                [organization.id.clone().into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row_3.try_get::<String>("", "metadata").unwrap(),
            STORED_METADATA
        );
        let updated_metadata = serde_json::json!({"overflow":null,"zero":-0.0,"fixed":1e20,"rounded":9_007_199_254_740_993_u64,"private":{"$serde_json::private::RawValue":"hello"}});
        let updated_organization = auth
            .store()
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    metadata: Some(updated_metadata),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated_organization.id, organization.id);
        let row_4 = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata FROM organization WHERE id = ?",
                [organization.id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row_4.try_get::<String>("", "metadata").unwrap(),
            r#"{"overflow":null,"zero":0,"fixed":100000000000000000000,"rounded":9007199254740992,"private":{"$serde_json::private::RawValue":"hello"}}"#
        );
    }

    // Binding type is observable in text affinity, including the Int52 boundary,
    // IEEE754 rounding, subnormals, and real overflow. Read real persisted rows and
    // enforce the phone column's unique constraint without installing a plugin.
    #[tokio::test]
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    async fn sqlite_numeric_user_text_affinity_preserves_binding_and_uniqueness() {
        use better_auth_core::store::NumericTextInput::{Integer, Real};
        use better_auth_core::{AuthUser, CreateUser};
        let config = AuthConfig::new("numeric-binding-secret-minimum-32-characters");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .build()
            .await
            .unwrap();
        for (index, (input, expected)) in [
            (Integer(1), "1"),
            (Real(1.0), "1.0"),
            (Integer(2_251_799_813_685_247), "2251799813685247"),
            (Real(2_251_799_813_685_248.0), "2251799813685248.0"),
            (Integer(-2_251_799_813_685_248), "-2251799813685248"),
            (Real(-0.0), "0.0"),
            (Real(47.49), "47.49"),
            (Real(2.878_199_999_999_999_7), "2.8781999999999997"),
            (Real(1.234_567_890_123_456e-5), "1.2345678901234559e-05"),
            (Real(5e-324), "4.9406564584124654e-324"),
            (Real(1e20), "1.0e+20"),
            (Real(9_007_199_254_740_993_u64 as f64), "9007199254740992.0"),
            (Real(f64::INFINITY), "Inf"),
            (Real(f64::NEG_INFINITY), "-Inf"),
        ]
        .into_iter()
        .enumerate()
        {
            let text = auth.store().coerce_user_text_number(input).await.unwrap();
            assert_eq!(text, expected, "binding {input:?}");
            let mut create =
                CreateUser::new().with_email(format!("binding-{index}@numeric.fixture.test"));
            create.phone_number = Some(text);
            let owner = auth.store().create_user(create).await.unwrap();
            let row = database
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT phone_number FROM users WHERE id = ?",
                    [owner.id().into()],
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get::<String>("", "phone_number").unwrap(), expected);
            let repeated = auth
                .context()
                .database
                .coerce_user_text_number(input)
                .await
                .unwrap();
            let mut collision =
                CreateUser::new().with_email(format!("collision-{index}@numeric.fixture.test"));
            collision.phone_number = Some(repeated);
            assert!(auth.store().create_user(collision).await.is_err());
            assert!(
                auth.store()
                    .get_user_by_email(&format!("collision-{index}@numeric.fixture.test"))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                auth.store()
                    .get_user_by_phone_number(expected)
                    .await
                    .unwrap()
                    .unwrap()
                    .id(),
                owner.id()
            );
        }
        assert!(
            auth.store()
                .coerce_user_text_number(Real(f64::NAN))
                .await
                .is_err()
        );
    }

    // A permissive number scanner must never turn malformed JSON into delivery or
    // persisted login state. Exercise the actual configured authentication router.
    #[tokio::test]
    async fn malformed_json_cannot_issue_magic_link_proofs_or_deliver_notifications() {
        let config = AuthConfig::new("json-parser-secret-minimum-32-characters").base_url(ORIGIN);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let sender = Arc::new(Sender::default());
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database.clone()))
            .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
            .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                send_magic_link: Some(Arc::<Sender>::clone(&sender)),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap();
        for literal in [
            "01",
            "-01",
            "+1",
            ".1",
            "1.",
            "1e",
            "1e+",
            "NaN",
            "Infinity",
            "[1,]",
            "{\"x\":1,}",
            "\"\\x00\"",
            "\"\\uZZZZ\"",
            "true false",
        ] {
            let body = format!(r#"{{"email":"parser@numeric.fixture.test","metadata":{literal}}}"#);
            let (response, _) = post(&auth, "/sign-in/magic-link", &body, None).await;
            assert_eq!(response.status, 400, "malformed input {literal}");
            assert!(!response.headers.contains_key("set-cookie"));
        }
        let deeply_nested = format!("{}0{}", "[".repeat(128), "]".repeat(128));
        let (response, _) = post(
            &auth,
            "/sign-in/magic-link",
            &format!(r#"{{"email":"parser@numeric.fixture.test","metadata":{deeply_nested}}}"#),
            None,
        )
        .await;
        assert_eq!(response.status, 400);
        assert!(sender.0.lock().unwrap().is_empty());
        let row = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM verifications".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
    }
}
