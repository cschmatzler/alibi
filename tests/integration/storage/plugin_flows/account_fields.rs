//! Configured account field policies decide which physical columns reach public account views.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::*;
use alibi::field_policy::FieldConfig;
use alibi::plugins::AccountManagementPlugin;

backend_tests!(account_views_follow_configured_field_visibility);
postgres_tests!(account_views_follow_configured_field_visibility);

async fn account_views_follow_configured_field_visibility<B: Backend>(db: Db) -> TestResult {
    for hidden in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let field = FieldConfig::new(json!({"type":"string"}));
        drop(
            config
                .account
                .additional_fields
                .insert("scope".into(), if hidden { field.hidden() } else { field }),
        );
        drop(config.account.additional_fields.insert(
            "grants".into(),
            FieldConfig::new(json!({"type":"string"})).field_name("scope"),
        ));
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .build()
            .await?;
        let owner = signup(&auth, "fields@example.test").await;
        assert_eq!(
            db.execute("UPDATE accounts SET scope = 'read, write'", &[])
                .await?,
            1
        );
        let listed = call(
            &auth,
            request("/list-accounts", None, &cookies(&owner)),
            200,
        )
        .await;
        let expected = if hidden {
            json!([])
        } else {
            json!(["read", "write"])
        };
        assert_eq!(body(&listed)[0]["scopes"], expected, "hidden={hidden}");
        assert_eq!(body(&listed)[0]["grants"], "read, write");
    }
    Ok(())
}
