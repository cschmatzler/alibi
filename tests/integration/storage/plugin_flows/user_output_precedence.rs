use super::*;
use alibi::utils::json as native;

backend_tests!(plugin_user_output_metadata_overrides_configured_visibility);

fn config(case: &native::JsValue) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"string"}));
    field.returned = false;
    _ = config
        .user
        .additional_fields
        .insert(case["field"].as_str().unwrap().into(), field);
    config
}

async fn check_precedence<S: AuthSchema>(auth: &Alibi<S>, case: &native::JsValue) -> TestResult {
    _ = auth
        .store()
        .create_user(alibi::CreateUser {
            id: Some("owner".into()),
            name: Some("Owner".into()),
            email: Some("owner@example.com".into()),
            username: Some("owner".into()),
            display_username: Some("Owner".into()),
            created_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
            updated_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
            ..Default::default()
        })
        .await?;
    let record = auth.store().get_user_by_id_record("owner").await?.unwrap();
    assert_eq!(
        native::parse_value(&native::to_string(&record)?)?,
        case["trusted"]
    );
    let public = auth.context().user_view(&record)?;
    assert_eq!(
        native::parse_value(&native::to_string(&public)?)?,
        case["output"],
        "plugin={}/{}",
        case["plugin"].as_bool().unwrap(),
        case["field"].as_str().unwrap()
    );
    auth.store().delete_user("owner").await?;
    Ok(())
}

async fn plugin_user_output_metadata_overrides_configured_visibility<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/user_output_precedence_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for case in cases {
        let config = config(case);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(EmailPasswordPlugin::new().enable_username(case["plugin"].as_bool().unwrap()))
            .build()
            .await?;
        check_precedence(&auth, case).await?;
    }
    B::close(connection).await
}

#[tokio::test]
async fn memory_plugin_user_output_metadata_overrides_configured_visibility() -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/user_output_precedence_cases.json"
    ))?;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let auth = AuthBuilder::without_database(config(case))
            .plugin(EmailPasswordPlugin::new().enable_username(case["plugin"].as_bool().unwrap()))
            .build()
            .await?;
        check_precedence(&auth, case).await?;
    }
    Ok(())
}
