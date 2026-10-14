//! Application storage configuration binds real SSO operations to owned names.
pub(crate) fn configure(config: &mut alibi::AuthConfig) {
    config.advanced.database.sso_provider = Some(alibi::config::SsoProviderDatabaseConfig {
        table_name: "application_sso_provider".into(),
        columns: [
            ("issuer", "application_issuer"),
            ("domain", "application_domain"),
            ("provider_id", "application_provider"),
            ("user_id", "application_owner"),
            ("organization_id", "application_org"),
            ("oidc_config", "application_oidc"),
            ("saml_config", "application_saml"),
            ("domain_verified", "application_verified"),
        ]
        .into_iter()
        .map(|(name, column)| (name.into(), column.into()))
        .collect(),
    });
}

pub(crate) fn configure_swapped(config: &mut alibi::AuthConfig) {
    configure(config);
    let mapping = config.advanced.database.sso_provider.as_mut().unwrap();
    _ = mapping.columns.insert("issuer".into(), "oidcConfig".into());
    _ = mapping
        .columns
        .insert("oidc_config".into(), "issuer".into());
}
