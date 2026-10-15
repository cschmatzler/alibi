//! Refresh grants bind retained authority to its client and atomically rotate it.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointResponse;
use alibi_core::session::SessionRequest;
use alibi_core::store::{CreateOAuthToken, OAuthTokenKind};
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use serde_json::{Value, json};
impl OAuthProviderPlugin {
    pub(super) async fn refresh_grant<S: AuthSchema>(
        &self,
        body: &Value,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let credentials = match super::credentials::extract(body, req, ctx, self, "token").await? {
            Ok(credentials) => credentials,
            Err(response) => return Ok(no_store(response)),
        };
        if credentials.client_id.is_empty() {
            return error("invalid_request", "Missing required client_id");
        }
        let token = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if token.is_empty() {
            return error(
                "invalid_request",
                "Missing a required refresh_token for refresh_token grant",
            );
        }
        let protected = self.hash_token(token, "refresh_token").await?;
        let Some(original) = ctx
            .database
            .get_oauth_token(OAuthTokenKind::Refresh, &protected)
            .await?
        else {
            return error("invalid_grant", "session not found");
        };
        if original.client_id != credentials.client_id || original.expires_at < chrono::Utc::now() {
            return error("invalid_grant", "invalid refresh token");
        }
        let requested_resources = super::resource_policy::resource_list(body.get("resource"))
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let original_resources =
            super::resource_policy::resource_list(original.metadata.get("resources"));
        if !requested_resources.is_empty()
            && original
                .metadata
                .get("resources")
                .is_some_and(|value| !value.is_null())
            && requested_resources
                .iter()
                .any(|resource| !original_resources.contains(resource))
        {
            return error("invalid_target", "requested resource invalid");
        }
        let requested_resource_value =
            (!requested_resources.is_empty()).then(|| json!(requested_resources));
        let original_scopes = original
            .metadata
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let scopes = body.get("scope").and_then(Value::as_str).map_or_else(
            || original_scopes.clone(),
            |value| value.split(' ').collect(),
        );
        for scope in &scopes {
            if !original_scopes.contains(scope) {
                return error("invalid_scope", &format!("unable to issue scope {scope}"));
            }
        }
        let client = match credentials.authenticate(ctx, self).await? {
            Ok(client) => client,
            Err(response) => return Ok(no_store(response)),
        };
        let ceiling = client
            .metadata
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split(' ')
            .collect::<Vec<_>>();
        let invalid = scopes
            .iter()
            .filter(|scope| !ceiling.contains(scope))
            .copied()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return error(
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        if !super::authentication::client_allows_grant(&client, "refresh_token") {
            return error(
                "unauthorized_client",
                "client is not authorized to use grant type refresh_token",
            );
        }
        if original
            .metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
        {
            let within = original
                .metadata
                .get("rotatedAt")
                .is_some_and(|value| !value.is_null())
                && original
                    .metadata
                    .get("rotationReplayExpiresAt")
                    .and_then(Value::as_str)
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .is_some_and(|deadline| deadline >= chrono::Utc::now());
            if within {
                let resource = requested_resource_value
                    .as_ref()
                    .or_else(|| original.metadata.get("resources"));
                let policy = match self
                    .admit_resources(ctx, &original.client_id, &scopes, resource)
                    .await
                {
                    Ok(policy) => policy,
                    Err(error) => {
                        let mut response = EndpointResponse::error(error.error);
                        if let Some(body) = error.body {
                            response = response.with_error_body(*body);
                        }
                        return Ok(no_store(response));
                    }
                };
                let scopes = policy.scopes.iter().map(String::as_str).collect::<Vec<_>>();

                if let Some(ciphertext) = original
                    .metadata
                    .get("rotationReplayResponse")
                    .and_then(Value::as_str)
                {
                    let decoded = crate::token_crypto::decrypt_with_config(ciphertext, &ctx.config)
                        .and_then(|plain| {
                            serde_json::from_str::<Value>(&plain)
                                .map_err(alibi_core::AuthError::from)
                        });
                    if let Ok(replay) = decoded
                        && replay.get("request")
                            == Some(&replay_request(
                                &scopes,
                                body,
                                original.metadata.get("resources"),
                                original.metadata.get("confirmation"),
                            ))
                        && let Some(mut response) = replay
                            .get("response")
                            .filter(|value| valid_replay_response(value))
                            .and_then(Value::as_object)
                            .cloned()
                        && let Some(expires) = response.get("expires_at").and_then(Value::as_f64)
                    {
                        let now =
                            json!(chrono::Utc::now().timestamp())
                                .as_f64()
                                .ok_or_else(|| {
                                    alibi_core::AuthError::internal("Invalid refresh replay time")
                                })?;
                        _ = response.insert("expires_in".into(), json!((expires - now).max(0.0)));
                        return Ok(no_store(EndpointResponse::json(&response)?));
                    }
                }
                return error("invalid_grant", "invalid refresh token");
            }
            if let Some(user) = &original.user_id {
                ctx.database
                    .delete_oauth_refresh_family(&original.client_id, user)
                    .await?;
            }
            return error("invalid_grant", "invalid refresh token");
        }
        let Some(user_id) = original.user_id.as_deref() else {
            return error("invalid_request", "user not found");
        };
        let Some(user) = ctx.database.get_user_by_id(user_id).await? else {
            return error("invalid_request", "user not found");
        };
        let requested_scopes = scopes.clone();
        let resource = requested_resource_value
            .as_ref()
            .or_else(|| original.metadata.get("resources"));
        let admission = match self
            .admit_resources(ctx, &original.client_id, &scopes, resource)
            .await
        {
            Ok(policy) => policy,
            Err(error) => {
                let mut response = EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                return Ok(no_store(response));
            }
        };
        let scopes = admission
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut params =
            super::OAuthTokenIssueParams::new(client.clone(), admission.scopes.clone());
        params.user = Some(ctx.trusted_user_view(&user));
        params.session_id = original.session_id.clone();
        params.authorization_code_id = original.authorization_code_id.clone();
        params.reference_id = original
            .metadata
            .get("referenceId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        params.confirmation = original
            .metadata
            .get("confirmation")
            .filter(|value| !value.is_null())
            .cloned();
        params.requested_user_info_claims = original
            .metadata
            .get("requestedUserInfoClaims")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            });
        let resources = super::resource_policy::resource_list(resource);
        params.resources = (!resources.is_empty()).then_some(resources);
        let issued = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| alibi_core::AuthError::internal("Invalid token issuance time"))?;
        let random = || {
            rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
                .map(char::from)
                .filter(char::is_ascii_alphabetic)
                .take(32)
                .collect::<String>()
        };
        let rotate =
            original_scopes.contains(&"offline_access") || scopes.contains(&"offline_access");
        let next_refresh = if rotate {
            if !ctx
                .database
                .claim_oauth_refresh_rotation(
                    &protected,
                    issued,
                    replay_deadline(issued, self.config.refresh_token_reuse_interval)?,
                )
                .await?
            {
                return error("invalid_grant", "invalid refresh token");
            }
            let token = random();
            let mut metadata = original.metadata.as_object().cloned().unwrap_or_default();
            for key in [
                "revoked",
                "rotatedAt",
                "rotationReplayResponse",
                "rotationReplayExpiresAt",
            ] {
                _ = metadata.remove(key);
            }
            _ = metadata.insert("scopes".into(), json!(scopes));
            if metadata.get("resources").is_none_or(Value::is_null) {
                _ = metadata.insert("resources".into(), json!(params.resources));
            }
            let row = ctx
                .database
                .create_oauth_token(
                    OAuthTokenKind::Refresh,
                    CreateOAuthToken {
                        token: self.hash_token(&token, "refresh_token").await?,
                        client_id: original.client_id.clone(),
                        user_id: original.user_id.clone(),
                        session_id: original.session_id.clone(),
                        authorization_code_id: original.authorization_code_id.clone(),
                        metadata: Value::Object(metadata),
                        created_at: issued,
                        expires_at: super::issuance::expiration_date(
                            &super::issuance::expiration(
                                issued.timestamp(),
                                self.config.refresh_token_expires_in,
                            )?,
                        )?,
                    },
                )
                .await?;
            Some((row.id, token))
        } else {
            None
        };
        let expires_claim = self.access_expiration(issued.timestamp(), true, &requested_scopes)?;
        let access = match self
            .create_access_token(
                ctx,
                req,
                super::issuance::AccessTokenIssuance {
                    params: &params,
                    issued,
                    expires: &expires_claim,
                    audiences: &admission.audiences,
                    refresh_id: next_refresh.as_ref().map(|(id, _)| id.as_str()),
                },
            )
            .await
        {
            Ok(token) => token,
            Err(error) => {
                let mut response = EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                return Ok(no_store(response));
            }
        };
        let mut response = serde_json::Map::from_iter([
            ("access_token".into(), json!(access)),
            (
                "expires_in".into(),
                super::issuance::remaining(issued.timestamp(), &expires_claim)?,
            ),
            ("expires_at".into(), expires_claim),
            (
                "token_type".into(),
                json!(if params
                    .confirmation
                    .as_ref()
                    .and_then(|value| value.get("jkt"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                {
                    "DPoP"
                } else {
                    "Bearer"
                }),
            ),
            ("scope".into(), json!(scopes.join(" "))),
        ]);
        if let Some((_, token)) = next_refresh {
            _ = response.insert("refresh_token".into(), json!(token));
        }
        if scopes.contains(&"openid") {
            let auth_time = original
                .metadata
                .get("authTime")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.timestamp_millis());
            let proof = json!({"userId":user_id,"sessionId":original.session_id,"authTime":auth_time,"query":{}});
            match Box::pin(self.issue_id_token(&client, &proof, &access, req, ctx)).await? {
                Ok(Some(token)) => {
                    _ = response.insert("id_token".into(), json!(token));
                }
                Ok(None) => {}
                Err(response) => return Ok(no_store(response)),
            }
        }
        if rotate && self.config.refresh_token_reuse_interval > 0.0 {
            let replay = json!({"request":replay_request(&scopes,body,original.metadata.get("resources"),original.metadata.get("confirmation")),"response":response});
            let saved = crate::token_crypto::encrypt_with_config(
                &serde_json::to_string(&replay)?,
                &ctx.config,
            );
            match saved {
                Ok(ciphertext) => {
                    if let Err(error) = ctx
                        .database
                        .store_oauth_refresh_replay(&original.id, &ciphertext)
                        .await
                    {
                        tracing::error!(%error,"Unable to store refresh rotation replay");
                    }
                }
                Err(error) => {
                    tracing::error!(%error,"Unable to encrypt refresh rotation replay");
                }
            }
        }
        Ok(no_store(EndpointResponse::json(&response)?))
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("cache-control", "no-store")
        .with_header("pragma", "no-cache")
}
fn error(code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(400, code, description).map(no_store)
}

fn replay_request(
    scopes: &[&str],
    body: &Value,
    original_resources: Option<&Value>,
    confirmation: Option<&Value>,
) -> Value {
    let mut scopes = scopes.to_vec();
    scopes.sort_unstable();
    scopes.dedup();
    let mut request = serde_json::Map::from_iter([("effectiveScopes".into(), json!(scopes))]);
    let resources = body.get("resource").or(original_resources);
    let values = resources.and_then(|value| {
        value
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .or_else(|| value.as_str().map(|value| vec![value]))
    });
    if let Some(mut values) = values {
        values.sort_unstable();
        values.dedup();
        _ = request.insert("requestedResources".into(), json!(values));
    }
    if let Some(value) = confirmation.filter(|value| !value.is_null()) {
        _ = request.insert("confirmation".into(), value.clone());
    }
    Value::Object(request)
}
fn replay_deadline(
    issued: chrono::DateTime<chrono::Utc>,
    interval: f64,
) -> AuthResult<Option<chrono::DateTime<chrono::Utc>>> {
    if interval <= 0.0 {
        return Ok(None);
    }
    let seconds = json!(issued.timestamp())
        .as_f64()
        .ok_or_else(|| alibi_core::AuthError::internal("Invalid rotation timestamp"))?;
    let milliseconds = ((seconds + interval) * 1000.0)
        .trunc()
        .to_string()
        .parse::<i64>()
        .map_err(|_| alibi_core::AuthError::internal("Invalid refresh reuse interval"))?;
    chrono::DateTime::from_timestamp_millis(milliseconds)
        .map(Some)
        .ok_or_else(|| alibi_core::AuthError::internal("Invalid refresh reuse deadline"))
}

fn valid_replay_response(value: &Value) -> bool {
    value.is_object()
        && ["access_token", "scope"]
            .iter()
            .all(|field| value.get(*field).is_some_and(Value::is_string))
        && ["expires_in", "expires_at"]
            .iter()
            .all(|field| value.get(*field).is_some_and(Value::is_number))
        && value
            .get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "Bearer" | "DPoP"))
        && ["refresh_token", "id_token"]
            .iter()
            .all(|field| value.get(*field).is_none_or(Value::is_string))
}
