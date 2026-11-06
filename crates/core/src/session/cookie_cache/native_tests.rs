use super::*;
use crate::utils::json::{self, JsValue};

#[test]
fn native_cache_formats_preserve_rich_metadata_and_source_date_revival() {
    let mut user: UserView = json::from_value(json::parse_value(r#"{"id":"native-user","name":"Native","email":"native@fixture.test","emailVerified":false,"createdAt":"2020-01-01T00:00:00.000Z","updatedAt":"2020-01-01T00:00:00.000Z"}"#).unwrap()).unwrap();
    let mut session: SessionView = json::from_value(json::parse_value(r#"{"id":"native-session","token":"native-token","userId":"native-user","createdAt":"2020-01-01T00:00:00.000Z","updatedAt":"2020-01-01T00:00:00.000Z","expiresAt":"2090-01-01T00:00:00.000Z"}"#).unwrap()).unwrap();
    let mut metadata = json::parse_value(r#"{"\ud800":"\udfff","nested":{"iso":"2020-01-01T00:00:00.123Z"},"alibi::JsValue/v1":"literal","$serde_json::private::Number":"literal","null":null}"#).unwrap();
    let values = metadata.as_object_mut().unwrap();
    _ = values.insert("undefined".into(), JsValue::Undefined);
    _ = values.insert(
        "date".into(),
        JsValue::Date(chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap()),
    );
    _ = values.insert(
        "array".into(),
        JsValue::Array(vec![JsValue::Undefined, JsValue::Null]),
    );
    _ = user
        .extension_fields
        .insert("metadata".into(), metadata.clone());
    _ = session
        .extension_fields
        .insert("metadata".into(), metadata.clone());
    let now = Utc::now().timestamp_millis();
    let expected = json::parse_adapter_value(&json::to_string(&metadata).unwrap());
    let compact = encode_compact(&user, &session, "1", now, 300.0, false, "native-cache").unwrap();
    let jwt = jwt::encode(
        jwt::payload(&user, &session, "1", now).unwrap(),
        "native-cache",
        300.0,
    )
    .unwrap();
    let jwe = crate::utils::jwe::encode(
        "native-cache",
        "better-auth-session",
        &jwt::payload(&user, &session, "1", now).unwrap(),
        300.0,
    )
    .unwrap();
    for cached in [
        decode_compact(&compact, "native-cache").unwrap(),
        jwt::decode(&jwt, "native-cache").unwrap(),
        jwt::decode_payload(
            &crate::utils::jwe::decode_native("native-cache", "better-auth-session", &jwe).unwrap(),
            15.0,
        )
        .unwrap(),
    ] {
        assert_eq!(cached.user.extension_fields["metadata"], expected);
        assert_eq!(cached.session.extension_fields["metadata"], expected);
        assert!(matches!(
            cached.user.extension_fields["metadata"]["date"],
            JsValue::Date(_)
        ));
        assert!(matches!(
            cached.user.extension_fields["metadata"]["nested"]["iso"],
            JsValue::Date(_)
        ));
    }
    // The pinned compact verifier revives before rebuilding its MAC input.
    // Noncanonical fractional ISO text therefore misses instead of changing that order.
    user.extension_fields["metadata"].as_object_mut().unwrap()["nested"]
        .as_object_mut()
        .unwrap()["iso"] = JsValue::String("2020-01-01T00:00:00.123456Z".into());
    let compact = encode_compact(&user, &session, "1", now, 300.0, false, "native-cache").unwrap();
    assert!(decode_compact(&compact, "native-cache").is_none());
}
