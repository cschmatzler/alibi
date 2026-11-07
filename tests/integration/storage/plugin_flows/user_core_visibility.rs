use super::*;
use alibi::utils::json as native;

backend_tests!(core_user_output_visibility_matches_actual_projection);

fn visibility_config(case: &native::JsValue) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let mut field =
        alibi::field_policy::FieldConfig::new(json!({"type":case["type"].as_str().unwrap()}));
    field.returned = false;
    _ = config
        .user
        .additional_fields
        .insert(case["field"].as_str().unwrap().into(), field);
    config
}

async fn check_visibility<S: AuthSchema>(auth: &Alibi<S>, case: &native::JsValue) -> TestResult {
    let field = case["field"].as_str().unwrap();
    _ = auth
        .store()
        .create_user(alibi::CreateUser {
            id: Some("owner".into()),
            name: Some("Owner".into()),
            email: Some("owner@example.com".into()),
            created_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
            updated_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
            ..Default::default()
        })
        .await?;
    let record = auth.store().get_user_by_id_record("owner").await?.unwrap();
    assert_eq!(
        native::parse_value(&native::to_string(&record)?)?,
        case["trusted"],
        "{field}: retained authority"
    );
    let public = auth.context().user_view(&record)?;
    let public = native::parse_value(&native::to_string(&public)?)?;
    assert_eq!(public, case["output"], "{field}: public projection");
    assert!(public.get(field).is_none());
    assert_eq!(
        native::parse_value(&native::to_string(
            &auth.context().trusted_user_view(&record)?
        )?)?,
        case["trusted"]
    );
    auth.store().delete_user("owner").await?;
    Ok(())
}

async fn core_user_output_visibility_matches_actual_projection<B: Backend>(db: Db) -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/user_core_visibility_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for case in cases {
        let config = visibility_config(case);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .build()
            .await?;
        check_visibility(&auth, case).await?;
    }
    B::close(connection).await
}

#[tokio::test]
async fn memory_core_user_output_visibility_matches_actual_projection() -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/user_core_visibility_cases.json"
    ))?;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let auth = AuthBuilder::without_database(visibility_config(case))
            .build()
            .await?;
        check_visibility(&auth, case).await?;
    }
    Ok(())
}
