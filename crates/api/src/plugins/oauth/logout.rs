//! RP-initiated provider logout after local session revocation.
use super::OAuthConfig;
use crate::plugins::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use alibi_core::{AuthContext, AuthSchema, entity::AuthAccount};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct SignOutRequest {
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub disable_redirect: Option<bool>,
    pub state: Option<String>,
}
impl RequestBody for SignOutRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("callbackURL", false),
        JsonField {
            name: "disableRedirect",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
        JsonField::string("state", false),
    ];
}

pub(in crate::plugins) async fn provider_logout_url<S: AuthSchema>(
    user_id: &str,
    body: &SignOutRequest,
    ctx: &AuthContext<S>,
) -> Option<String> {
    let config = ctx.extensions.get::<OAuthConfig>()?;
    let mut accounts = ctx.database.get_user_accounts_record(user_id).await.ok()?;
    accounts.sort_by_key(|account| std::cmp::Reverse(account.updated_at()));
    let base = url::Url::parse(&crate::plugins::helpers::auth_base_url(&ctx.config)).ok()?;
    let callback = body
        .callback_url
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| base.join(value))
        .transpose()
        .ok()?;
    let mut seen = HashSet::new();
    for account in accounts {
        let Some(provider) = config.providers.get(account.provider_id()) else {
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
        let redirect = match callback
            .clone()
            .map(Ok)
            .or_else(|| {
                logout
                    .post_logout_redirect_uri
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .map(|value| base.join(value))
            })
            .transpose()
        {
            Ok(value) => value,
            Err(_) => continue,
        };
        let id_token = account.id_token().filter(|value| !value.is_empty());
        // URLSearchParams.set replaces existing values while retaining unrelated parameters.
        let mut parameters: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let mut set = |name: &str, value: &str| {
            if let Some((_, previous)) = parameters.iter_mut().find(|(key, _)| key == name) {
                *previous = value.to_owned();
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
            let _serializer = query.clear().extend_pairs(parameters);
        }
        return Some(url.into());
    }
    None
}
