use super::*;
use alibi::store::UserStore;
use alibi::utils::json as native;

backend_tests!(initialized_user_output_omits_disabled_plugin_columns);

async fn initialized_user_output_omits_disabled_plugin_columns<B: Backend>(db: Db) -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/user_disabled_plugin_output_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let mode = case["mode"].as_str().unwrap();
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        if mode == "declared-banned" {
            _ = config.user.additional_fields.insert(
                "banned".into(),
                alibi::field_policy::FieldConfig::new(json!({"type":"boolean"})),
            );
        }
        let physical = B::store(Arc::new(config.clone()), &connection);
        _ = physical
            .create_user(alibi::CreateUser {
                id: Some("owner".into()),
                name: Some("Owner".into()),
                email: Some("owner@example.com".into()),
                created_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                updated_at: Some(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                ..Default::default()
            })
            .await?;
        let mut builder = AuthBuilder::new(config)
            .store(physical)
            .plugin(EmailPasswordPlugin::new().enable_username(mode == "username"));
        if mode == "admin" {
            builder = builder.plugin(alibi::plugins::AdminPlugin::new());
        }
        let auth = builder.build().await?;
        let record = auth.store().get_user_by_id_record("owner").await?.unwrap();
        let expected = &case["output"];
        let wire = native::to_string(&record)?;
        assert_eq!(
            native::parse_value(&wire)?,
            *expected,
            "{mode}: initialized adapter record"
        );
        let view = auth.context().user_view(&record)?;
        let projected = native::parse_value(&native::to_string(&view)?)?;
        assert_eq!(projected, *expected, "{mode}: public user projection");
        auth.store().delete_user("owner").await?;
        B::close(connection).await?;
    }
    Ok(())
}
