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
    for name in [
        "id",
        "token",
        "userId",
        "expiresAt",
        "createdAt",
        "updatedAt",
    ] {
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
        let mut physical = snapshot();
        physical[name] = json!("invalid date");
        assert!(
            SessionView::from_secondary_snapshot(physical).is_err(),
            "{name}"
        );
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
