use super::*;
use serde_json::Value;

pub(super) async fn exercise<S: AuthSchema>(
    raw: &Raw,
    store: &dyn AuthStore<S>,
    naive: bool,
) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/user-timestamp-parameters.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if raw.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let profile = profiles
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap();
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("timestamp@example.com"),
        )
        .await?;
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let mut input = UpdateUser {
            banned: Some(action != "unban"),
            ..Default::default()
        };
        match action {
            "date" => input.ban_expires = Some(Some(case["input"].as_str().unwrap().parse()?)),
            "string" => {
                _ = input.adapter_native_fields.insert(
                    "banExpires".into(),
                    alibi::utils::json::JsValue::from(case["input"].clone()),
                );
            }
            "unban" => {}
            "clear" => input.ban_expires = Some(None),
            _ => panic!("unknown source timestamp action: {action}"),
        }
        let updated = store.update_user(user.id().as_ref(), input).await?;
        let expected: Option<DateTime<Utc>> =
            case["output"].as_str().map(str::parse).transpose()?;
        assert_eq!(updated.id(), user.id(), "{backend}/{action}");
        assert_eq!(updated.ban_expires(), expected, "{backend}/{action}");
        assert_eq!(
            serde_json::json!(updated.banned()),
            case["banned"],
            "{backend}/{action}"
        );
        let readback = store
            .get_user_by_id(user.id().as_ref())
            .await?
            .ok_or("timestamp user missing")?;
        assert_eq!(
            readback.ban_expires(),
            expected,
            "{backend}/{action} readback"
        );
        assert_eq!(
            stored_date(raw, "user", "banExpires", user.id().as_ref(), naive).await?,
            expected,
            "{backend}/{action} physical timestamp"
        );
    }
    Ok(())
}
