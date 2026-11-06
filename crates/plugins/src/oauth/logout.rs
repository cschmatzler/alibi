//! RP-initiated provider logout after local session revocation.
use super::OAuthConfig;
use crate::session_management::SignOutRequest;
use alibi_core::{AuthContext, AuthSchema, entity::AuthAccount};
use std::collections::HashSet;

pub(crate) async fn provider_logout_url<S: AuthSchema>(
    user_id: &str,
    body: &SignOutRequest,
    ctx: &AuthContext<S>,
) -> Option<String> {
    let config = ctx.extensions.get::<OAuthConfig>()?;
    let mut accounts = ctx.database.get_user_accounts_record(user_id).await.ok()?;
    accounts.sort_by_key(|account| std::cmp::Reverse(account.updated_at()));
    let base = url::Url::parse(&crate::helpers::auth_base_url(&ctx.config)).ok()?;
    let mut seen = HashSet::new();
    for account in accounts {
        let Some(provider) = config.provider(account.provider_id()) else {
            continue;
        };
        let Some(logout) = provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.end_session.as_ref())
        else {
            continue;
        };
        if !seen.insert(account.provider_id().to_owned()) {
            continue;
        }
        let Ok(mut url) = url::Url::parse(&logout.endpoint) else {
            continue;
        };
        let Ok(redirect) = body
            .callback_url
            .as_deref()
            .or(logout.post_logout_redirect_uri.as_deref())
            .filter(|value| !value.is_empty())
            .map(|value| base.join(value))
            .transpose()
        else {
            continue;
        };
        let id_token = account.id_token().filter(|value| !value.is_empty());
        // URLSearchParams.set replaces existing values while retaining unrelated parameters.
        let mut parameters: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let mut set = |name: &str, value: &str| {
            if let Some((_, previous)) = parameters.iter_mut().find(|(key, _)| key == name) {
                value.clone_into(previous);
                let mut first = true;
                parameters.retain(|(key, _)| {
                    if key != name {
                        return true;
                    }
                    let keep = first;
                    first = false;
                    keep
                });
            } else {
                parameters.push((name.into(), value.into()));
            }
        };
        if let Some(token) = id_token {
            set("id_token_hint", token);
        }
        if let Some(redirect) = redirect {
            set("post_logout_redirect_uri", redirect.as_str());
            set("client_id", &provider.client_id);
            if let Some(state) = body.state.as_deref().filter(|value| !value.is_empty()) {
                set("state", state);
            }
        } else if id_token.is_none() {
            set("client_id", &provider.client_id);
        }
        if !parameters.is_empty() {
            let mut query = url.query_pairs_mut();
            _ = query.clear().extend_pairs(parameters);
        }
        return Some(url.into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{GenericOAuthConfig, OAuthConfig};
    use alibi_core::{CreateAccount, CreateUser};

    #[tokio::test]
    async fn explicit_empty_logout_callback_suppresses_configured_redirect() {
        let mut ctx = crate::test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("logout@example.com"))
            .await
            .unwrap();
        ctx.database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: user.id.clone(),
                account_id: "subject".into(),
                provider_id: "generic".into(),
                access_token: None,
                refresh_token: None,
                id_token: Some("id-token".into()),
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: None,
            })
            .await
            .unwrap();
        let mut generic = GenericOAuthConfig::new("client", "secret");
        generic.end_session_endpoint = Some("https://idp.example/logout".into());
        generic.post_logout_redirect_uri = Some("https://app.example/configured".into());
        let provider = generic.resolve().await.unwrap().unwrap().provider;
        let mut config = OAuthConfig::default();
        config.providers.insert("generic".into(), provider);
        ctx.extensions.insert(config);
        for (callback_url, expected) in [
            (None, Some("https://app.example/configured")),
            (Some(String::new()), None),
            (
                Some("https://app.example/explicit".into()),
                Some("https://app.example/explicit"),
            ),
        ] {
            let body = SignOutRequest {
                callback_url,
                state: Some("state".into()),
                ..Default::default()
            };
            let url = url::Url::parse(&provider_logout_url(&user.id, &body, &ctx).await.unwrap())
                .unwrap();
            let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(
                query.get("id_token_hint").map(String::as_str),
                Some("id-token")
            );
            assert_eq!(
                query.get("post_logout_redirect_uri").map(String::as_str),
                expected
            );
            assert_eq!(
                query.get("state").map(String::as_str),
                expected.map(|_| "state")
            );
        }
    }
}
