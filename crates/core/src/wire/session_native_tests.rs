use crate::{AuthSession, SessionView};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

fn snapshot() -> Value {
    json!({
        "id": "session-physical",
        "token": "issued-token",
        "userId": "user-physical",
        "expiresAt": "2030-04-05T06:07:08.901Z",
        "createdAt": "2026-01-02T03:04:05.678Z",
        "updatedAt": "2026-02-03T04:05:06.789Z",
        "ipAddress": null,
        "userAgent": "native-agent",
        "activeOrganizationId": "org-physical",
        "custom": {"nested": [null, false, 42, "value"]},
        "nullable": null
    })
}

#[test]
fn session_secondary_codec_round_trips_physical_camel_case_fields() {
    let physical = snapshot();
    let session = SessionView::from_secondary_snapshot(physical.clone()).unwrap();
    assert_eq!(session.id(), "session-physical");
    assert_eq!(session.token(), "issued-token");
    assert_eq!(session.user_id(), "user-physical");
    assert_eq!(session.created_at().timestamp_millis(), 1_767_323_045_678);
    assert_eq!(session.active_organization_id(), Some("org-physical"));
    assert_eq!(session.secondary_snapshot().unwrap(), physical);
    assert_eq!(session.additional_fields()["custom"], physical["custom"]);
    assert_eq!(SessionView::from(&session), session);
}

#[test]
fn session_secondary_codec_distinguishes_optional_absence_and_null() {
    for name in [
        "ipAddress",
        "userAgent",
        "impersonatedBy",
        "activeOrganizationId",
        "activeTeamId",
        "nullable",
    ] {
        let mut absent = snapshot();
        absent.as_object_mut().unwrap().remove(name);
        let session = SessionView::from_secondary_snapshot(absent.clone()).unwrap();
        assert_eq!(
            session.secondary_snapshot().unwrap(),
            absent,
            "{name} absent"
        );
        assert_eq!(
            serde_json::to_value(SessionView::from(&session)).unwrap(),
            absent
        );

        let mut null = absent;
        null[name] = Value::Null;
        let session = SessionView::from_secondary_snapshot(null.clone()).unwrap();
        assert_eq!(session.secondary_snapshot().unwrap(), null, "{name} null");
        assert_eq!(
            serde_json::to_value(SessionView::from(&session)).unwrap(),
            null
        );
    }
}

#[test]
fn session_secondary_creation_clock_correction_does_not_mutate_model() {
    let physical = snapshot();
    let session = SessionView::from_secondary_snapshot(physical.clone()).unwrap();
    let corrected = session
        .secondary_snapshot_for_creation(Utc.timestamp_millis_opt(1_767_323_045_999).unwrap())
        .unwrap();
    let mut expected = physical.clone();
    expected["createdAt"] = json!("2026-01-02T03:04:05.999Z");
    assert_eq!(corrected, expected);
    assert_eq!(session.secondary_snapshot().unwrap(), physical);
}

#[test]
fn session_secondary_codec_rejects_unrepresentable_required_values_without_fabrication() {
    for name in ["id", "token", "userId"] {
        for invalid in [None, Some(Value::Null), Some(json!({})), Some(json!(42))] {
            let mut physical = snapshot();
            match invalid {
                Some(value) => physical[name] = value,
                None => {
                    physical.as_object_mut().unwrap().remove(name);
                }
            }
            assert!(
                SessionView::from_secondary_snapshot(physical).is_err(),
                "{name}"
            );
        }
    }
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        for invalid in [
            None,
            Some(json!("invalid date")),
            Some(json!({})),
            Some(json!(8_640_000_000_000_000_i64)),
            Some(json!(-8_640_000_000_000_000_i64)),
            Some(json!(1e20)),
        ] {
            let mut physical = snapshot();
            match invalid {
                Some(value) => physical[name] = value,
                None => {
                    physical.as_object_mut().unwrap().remove(name);
                }
            }
            assert!(
                SessionView::from_secondary_snapshot(physical).is_err(),
                "{name}"
            );
        }
    }
}

#[test]
fn session_secondary_codec_revives_representable_javascript_dates() {
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        for (input, expected) in [
            (json!(null), "1970-01-01T00:00:00.000Z"),
            (json!(false), "1970-01-01T00:00:00.000Z"),
            (json!(true), "1970-01-01T00:00:00.001Z"),
            (json!(1.9), "1970-01-01T00:00:00.001Z"),
            (json!(-1.9), "1969-12-31T23:59:59.999Z"),
            (json!(-0.5), "1970-01-01T00:00:00.000Z"),
            (json!(1767323045678_i64), "2026-01-02T03:04:05.678Z"),
            (
                json!(["2026-01-02T03:04:05.678Z"]),
                "2026-01-02T03:04:05.678Z",
            ),
            (
                json!("2026-01-02T04:04:05.678+01:00"),
                "2026-01-02T03:04:05.678Z",
            ),
        ] {
            let mut physical = snapshot();
            physical[name] = input;
            let session = SessionView::from_secondary_snapshot(physical.clone()).unwrap();
            physical[name] = json!(expected);
            assert_eq!(session.secondary_snapshot().unwrap(), physical);
        }
    }
}

#[test]
fn session_secondary_codec_retains_configured_scope_extension_values() {
    let mut session = SessionView::from_secondary_snapshot(snapshot()).unwrap();
    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        session
            .extension_fields
            .insert(name.into(), json!("configured-scope"));
    }
    let encoded = session.secondary_snapshot().unwrap();
    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        assert_eq!(encoded[name], "configured-scope");
    }
}

#[test]
fn session_secondary_creation_clock_replaces_raw_shadow_without_mutation() {
    let mut session = SessionView::from_secondary_snapshot(snapshot()).unwrap();
    session
        .extension_fields
        .insert("createdAt".into(), json!("1999-01-01T00:00:00.000Z"));
    let before = session.clone();
    let corrected = session
        .secondary_snapshot_for_creation(Utc.timestamp_millis_opt(1_767_323_045_999).unwrap())
        .unwrap();
    assert_eq!(corrected["createdAt"], "2026-01-02T03:04:05.999Z");
    assert_eq!(session, before);
    assert_eq!(
        session.secondary_snapshot().unwrap()["createdAt"],
        "1999-01-01T00:00:00.000Z"
    );
}

#[test]
fn session_native_output_overlay_keeps_null_undefined_extras_and_original_creation_clock() {
    let session = SessionView::from_secondary_snapshot(snapshot()).unwrap();
    let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
    let mut native = crate::AdapterOutput::default();
    native.insert("custom".into(), Some(serde_json::Value::Null));
    native.insert("ipAddress".into(), None);
    native.insert(
        "unknownTrustedObject".into(),
        Some(serde_json::json!({"nested":[true,null]})),
    );
    native.insert(
        "createdAt".into(),
        Some(serde_json::json!("2001-01-01T00:00:00.000Z")),
    );
    let projected = session
        .secondary_snapshot_with_native_output(&native)
        .unwrap();
    assert_eq!(projected["custom"], serde_json::Value::Null);
    assert!(projected.get("ipAddress").is_none());
    assert_eq!(
        projected["unknownTrustedObject"],
        serde_json::json!({"nested":[true,null]})
    );
    assert_eq!(projected["createdAt"], "2001-01-01T00:00:00.000Z");
    let creation = session
        .secondary_snapshot_for_creation_with_native_output(clock, &native)
        .unwrap();
    assert_eq!(
        creation["createdAt"],
        crate::utils::datetime::json_date_millis(clock.timestamp_millis())
    );
    native.insert("createdAt".into(), None);
    assert_eq!(
        session
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap()["createdAt"],
        creation["createdAt"]
    );
    assert_ne!(session.created_at(), clock);
    assert_ne!(
        session.secondary_snapshot().unwrap()["custom"],
        serde_json::Value::Null
    );
}
