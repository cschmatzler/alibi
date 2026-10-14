//! Actual application configuration shared by native and HTTP fixture hosts.
use alibi::plugins::{SsoDefaultProvider, SsoPrivateKey};
use serde_json::json;
pub(crate) fn providers(base: &str) -> Vec<SsoDefaultProvider> {
    vec![
        SsoDefaultProvider {
            provider_id: "configured-oidc".into(),
            domain: "oidc.company.test".into(),
            oidc_config: Some(
                json!({"issuer":base,"clientId":"enterprise-client","clientSecret":"stored-secret","pkce":true,"authorizationEndpoint":format!("{base}/authorize"),"tokenEndpoint":format!("{base}/token"),"jwksEndpoint":format!("{base}/jwks"),"userInfoEndpoint":format!("{base}/userinfo"),"tokenEndpointAuthentication":"client_secret_basic"}),
            ),
            saml_config: None,
            private_key: None,
        },
        SsoDefaultProvider {
            private_key: None,
            provider_id: "configured-saml".into(),
            domain: "saml.company.test".into(),
            oidc_config: None,
            saml_config: Some(
                json!({"issuer":"https://sp.example.test/entity","entryPoint":"https://idp.example.test/sso","cert":include_str!("../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true}),
            ),
        },
    ]
}

pub(crate) fn changed_providers(base: &str) -> Vec<SsoDefaultProvider> {
    let mut configured = providers(base);
    for provider in &mut configured {
        provider.domain = format!("changed.{}", provider.domain);
    }
    configured
}

pub(crate) fn jwt_provider(base: &str, key: bool) -> Vec<SsoDefaultProvider> {
    vec![SsoDefaultProvider {
        provider_id: "configured-jwt".into(),
        domain: "jwt.company.test".into(),
        saml_config: None,
        oidc_config: Some(
            json!({"issuer":base,"clientId":"enterprise-client","pkce":true,"authorizationEndpoint":format!("{base}/authorize"),"tokenEndpoint":format!("{base}/token-jwt"),"jwksEndpoint":format!("{base}/jwks"),"userInfoEndpoint":format!("{base}/userinfo"),"tokenEndpointAuthentication":"private_key_jwt","privateKeyId":"sso-key","privateKeyAlgorithm":"RS256"}),
        ),
        private_key: key.then(|| SsoPrivateKey {
            private_key_pem: Some(
                include_str!("../compat/fixtures/salesforce-transport/key.pem").into(),
            ),
            ..Default::default()
        }),
    }]
}
