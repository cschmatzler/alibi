//! Shared real provider configuration for logical OAuth operation owners.
use super::Provider;
use alibi::plugins::oauth::GenericOAuthConfig;
pub(super) fn generic_provider(peer: &Provider) -> Result<GenericOAuthConfig, url::ParseError> {
    let mut provider = GenericOAuthConfig::new("native-client", "native-secret");
    provider.provider.scopes = vec!["profile".into()];
    provider.authorization_url = Some(peer.url.join("authorize")?.into());
    provider.token_url = Some(peer.url.join("token")?.into());
    provider.user_info_url = Some(peer.url.join("profile")?.into());
    Ok(provider)
}
