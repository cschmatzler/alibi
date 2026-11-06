use super::*;
use alibi_core::session::cookie_cache::jwt::CookieCacheSigner;
use alibi_core::utils::json::{self, JsValue};

#[tokio::test]
async fn managed_cache_signer_authenticates_rich_canonical_claims() {
    let ctx = crate::test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let mut payload = json::parse_value(r#"{"user":{"id":"u","metadata":{"\ud800":"\udfff","nested":{"iso":"2020-01-01T00:00:00.123456Z"},"alibi::JsValue/v1":"literal","null":null}},"session":{"token":"t"},"updatedAt":0,"version":"1"}"#).unwrap();
    let fields = payload.as_object_mut().unwrap()["user"]
        .as_object_mut()
        .unwrap()["metadata"]
        .as_object_mut()
        .unwrap();
    _ = fields.insert("undefined".into(), JsValue::Undefined);
    _ = fields.insert(
        "date".into(),
        JsValue::Date(chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap()),
    );
    let expected =
        json::parse_value(&json::to_string(&payload["user"]["metadata"]).unwrap()).unwrap();
    let token = CookieCacheSigner::sign(&plugin, payload, 300.0, &ctx, None)
        .await
        .unwrap();
    let verified = CookieCacheSigner::verify(&plugin, &token, &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(verified["user"]["metadata"], expected);
    assert_eq!(verified["sub"], "u");
    assert_eq!(verified["sid"], "t");
    // JWT authentication parses JSON, not safeJSONParse's storage date reviver.
    assert!(verified["user"]["metadata"]["nested"]["iso"].is_string());
}
