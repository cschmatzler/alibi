//! User consent over a provider-issued authorization request.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use serde_json::{Value, json};
#[derive(serde::Deserialize)]
pub(super) struct ConsentInput {
    accept: bool,
    scope: Option<String>,
    oauth_query: Option<String>,
    claims: Option<Value>,
}
pub(super) fn validate(body: Option<&JsValue>) -> AuthResult<JsValue> {
    let mut output = crate::endpoint::validate_fields(
        body,
        "body",
        &[
            crate::authentication_helpers::JsonField {
                name: "accept",
                required: true,
                kind: crate::authentication_helpers::JsonFieldKind::Boolean,
            },
            crate::authentication_helpers::JsonField::string("scope", false),
            crate::authentication_helpers::JsonField::string("oauth_query", false),
        ],
    )?;
    if let Some(claims) = body.and_then(|value| value.get("claims")) {
        if !claims.is_string() && !claims.is_object() {
            return Err(crate::endpoint::validation("[body.claims] Invalid input"));
        }
        let value = claims.to_json_value()?;
        if super::claims_request::parse(&value).is_none() {
            return Err(crate::endpoint::validation(
                "[body.claims] claims must be a valid Claims request object",
            ));
        }
        if let JsValue::Object(object) = &mut output {
            _ = object.insert("claims".into(), claims.clone());
        }
    }
    Ok(output)
}
impl OAuthProviderPlugin {
    /// Accept or deny a provider-issued authorization request as the current user.
    pub fn oauth2_consent_endpoint(
        accept: bool,
        scope: Option<&str>,
        oauth_query: Option<&str>,
    ) -> AuthResult<ServerEndpoint<Value>> {
        let mut body = serde_json::Map::from_iter([("accept".into(), json!(accept))]);
        if let Some(scope) = scope {
            _ = body.insert("scope".into(), json!(scope));
        }
        if let Some(query) = oauth_query {
            _ = body.insert("oauth_query".into(), json!(query));
        }
        ServerEndpoint::new("oauth-provider", "oauth2Consent").with_body(&body)
    }
    pub(super) async fn consent<S: AuthSchema>(
        &self,
        input: ConsentInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let supplied = input.oauth_query.as_deref().unwrap_or("");
        if !supplied.is_empty()
            && !super::authorization::verify_authorization_query(
                supplied,
                ctx.config.current_secret(),
            )?
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 400,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"invalid_signature"}"#,
            )?));
        }
        let (user, session) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        if supplied.is_empty() {
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                "missing oauth query",
            );
        }
        let mut query = super::continuation::interaction_query(supplied);
        let client_id = query
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if client_id.is_empty() {
            return super::clients::status_protocol_error(
                400,
                "invalid_client",
                "client_id is required",
            );
        }
        let scopes = query
            .get("scope")
            .and_then(Value::as_str)
            .map(|scope| scope.split(' ').map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_default();
        let accepted = input.scope.as_deref().map_or_else(
            || scopes.clone(),
            |scope| scope.split(' ').map(str::to_owned).collect::<Vec<_>>(),
        );
        if !accepted.iter().all(|scope| scopes.contains(scope)) {
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                "Scope not originally requested",
            );
        }
        let supported = self.supported_claims();
        let requested_claims = query
            .get("claims")
            .and_then(super::claims_request::parse)
            .map(|request| {
                request
                    .user_info
                    .into_iter()
                    .filter(|name| supported.contains(name))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let accepted_claims = input
            .claims
            .as_ref()
            .and_then(super::claims_request::parse)
            .map_or_else(
                || requested_claims.clone(),
                |request| {
                    request
                        .user_info
                        .into_iter()
                        .filter(|name| supported.contains(name))
                        .collect::<Vec<_>>()
                },
            );
        if !accepted_claims
            .iter()
            .all(|name| requested_claims.contains(name))
        {
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                "Claim not originally requested",
            );
        }
        if !input.accept {
            let redirect = query
                .get("redirect_uri")
                .and_then(Value::as_str)
                .unwrap_or("");
            let state = query.get("state").and_then(Value::as_str);
            let issuer = self
                .metadata(ctx)?
                .get("issuer")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let mut pairs = url::form_urlencoded::Serializer::new(String::new());
            _ = pairs
                .append_pair("error", "access_denied")
                .append_pair("error_description", "User denied access");
            if let Some(state) = state {
                _ = pairs.append_pair("state", state);
            }
            _ = pairs.append_pair("iss", &issuer);
            return EndpointResponse::json(
                &json!({"redirect":true,"url":format!("{redirect}{}{}",if redirect.contains('?'){"&"}else{"?"},pairs.finish())}),
            );
        }
        let prompt = query
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let issued = url::form_urlencoded::parse(supplied.as_bytes())
            .find(|(name, _)| name == "ba_iat")
            .and_then(|(_, value)| value.parse::<i64>().ok());
        let login_satisfied =
            issued.is_some_and(|issued| session.created_at.timestamp_millis() >= issued);
        if prompt.split(' ').any(|prompt| prompt == "login") && !login_satisfied {
            return Box::pin(self.resume_authorization(
                query,
                req,
                ctx,
                super::continuation::post_login_clearance(supplied),
                false,
            ))
            .await;
        }
        let reference_id = self
            .consent_reference_id(&ctx.user_view(&user), &session, &accepted)
            .await?;
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid consent timestamp"))?;
        let resource = query.get("resource").cloned().map_or(Value::Null, |value| {
            if value.is_array() {
                value
            } else {
                json!([value])
            }
        });
        let metadata = json!({"scopes":accepted,"requestedUserInfoClaims":accepted_claims,"resources":resource,"referenceId":reference_id});
        let existing = ctx
            .database
            .list_oauth_consents_by_user(user.id().as_ref())
            .await?
            .into_iter()
            .find(|consent| {
                consent.client_id == client_id
                    && super::post_login::consent_matches_reference(
                        &consent.metadata,
                        reference_id.as_deref(),
                    )
            });
        if let Some(existing) = existing {
            let mut updated = existing
                .metadata
                .as_object()
                .cloned()
                .ok_or_else(|| AuthError::internal("Invalid consent metadata"))?;
            _ = updated.insert("scopes".into(), json!(accepted));
            _ = updated.insert("requestedUserInfoClaims".into(), json!(accepted_claims));
            // An absent resources value is filtered out of the pinned adapter
            // update; likewise an update never replaces the selected row's reference.
            if !resource.is_null() {
                _ = updated.insert("resources".into(), resource);
            }
            _ = ctx
                .database
                .update_oauth_consent_metadata(&existing.id, Value::Object(updated), now)
                .await?;
        } else {
            _ = ctx
                .database
                .create_oauth_consent(alibi_core::store::CreateOAuthConsent {
                    client_id,
                    user_id: Some(user.id().as_ref().to_owned()),
                    metadata,
                    created_at: now,
                })
                .await?;
        }
        if input.claims.is_some()
            && let Some(original) = query.get("claims")
        {
            if let Some(filtered) =
                super::claims_request::filter_user_info(original, &accepted_claims)
            {
                _ = query.insert("claims".into(), json!(serde_json::to_string(&filtered)?));
            } else {
                _ = query.remove("claims");
            }
        }
        if input.scope.is_some() {
            _ = query.insert("scope".into(), json!(accepted.join(" ")));
        }
        let remaining = prompt
            .split(' ')
            .filter(|prompt| *prompt != "consent" && (!login_satisfied || *prompt != "login"))
            .collect::<Vec<_>>()
            .join(" ");
        if remaining.is_empty() {
            _ = query.remove("prompt");
        } else {
            _ = query.insert("prompt".into(), json!(remaining));
        }
        if login_satisfied {
            _ = query.remove("max_age");
        }
        Box::pin(self.resume_authorization(
            query,
            req,
            ctx,
            super::continuation::post_login_clearance(supplied),
            false,
        ))
        .await
    }
    pub(super) async fn resume_authorization<S: AuthSchema>(
        &self,
        query: serde_json::Map<String, Value>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        post_login_cleared_for_session: Option<String>,
        post_login_continuation: bool,
    ) -> AuthResult<EndpointResponse> {
        let Some(mut request) = req.physical_request().cloned() else {
            return super::clients::status_protocol_error(
                401,
                "invalid_request",
                "request not found",
            );
        };
        request.headers = req.session_headers().clone();
        _ = request
            .headers
            .insert("accept".into(), "application/json".into());
        let input = Some(alibi_core::utils::json::parse_value(
            &serde_json::to_string(&query)?,
        )?);
        let settings = super::authorization::AuthorizationSettings {
            initial: false,
            post_login_cleared_for_session,
            post_login_continuation,
        };
        // Preserve the original physical callback headers while changing only
        // the continuation's logical response negotiation/session credentials.
        if let Some(call) = req.endpoint_call() {
            let mut call = call.clone();
            call.replace_headers(request.headers);
            return Box::pin(self.authorize_flow(input, &call, ctx, settings)).await;
        }
        Box::pin(self.authorize_flow(input, &request, ctx, settings)).await
    }
}

impl OAuthProviderPlugin {
    /// List durable OAuth grants belonging to the current authenticated user.
    #[must_use]
    pub fn get_oauth_consents_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "getOAuthConsents")
    }
    pub(super) async fn list_consents<S: AuthSchema>(
        &self,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        let rows = ctx
            .database
            .list_oauth_consents_by_user(user.id().as_ref())
            .await?;
        let values = rows
            .into_iter()
            .map(consent_value)
            .collect::<AuthResult<Vec<_>>>()?;
        EndpointResponse::json(&values)
    }
}
fn consent_value(row: alibi_core::store::OAuthConsent) -> AuthResult<Value> {
    let mut value: serde_json::Map<String, Value> = serde_json::from_value(row.metadata)?;
    _ = value.insert("id".into(), json!(row.id));
    _ = value.insert("clientId".into(), json!(row.client_id));
    _ = value.insert("userId".into(), json!(row.user_id));
    _ = value.insert("createdAt".into(), json!(row.created_at));
    _ = value.insert("updatedAt".into(), json!(row.updated_at));
    Ok(Value::Object(value))
}

#[derive(serde::Deserialize)]
pub(super) struct ConsentId {
    id: String,
}
pub(super) fn validate_id(input: Option<&JsValue>, location: &str) -> AuthResult<JsValue> {
    crate::endpoint::validate_fields(
        input,
        location,
        &[crate::authentication_helpers::JsonField::string("id", true)],
    )
}
impl OAuthProviderPlugin {
    /// Return the current user's durable consent identified by its stored grant ID.
    pub fn get_oauth_consent_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "getOAuthConsent").with_query(&json!({"id":id}))
    }
    pub(super) async fn read_consent<S: AuthSchema>(
        &self,
        input: ConsentId,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let row = match Box::pin(self.owned_consent(&input.id, req, ctx)).await? {
            Ok(row) => row,
            Err(response) => return Ok(response),
        };
        EndpointResponse::json(&consent_value(row)?)
    }
}

#[derive(serde::Deserialize)]
pub(super) struct ConsentUpdateInput {
    id: String,
    update: ConsentScopeUpdate,
}
#[derive(serde::Deserialize)]
struct ConsentScopeUpdate {
    scopes: Vec<String>,
}
pub(super) fn validate_update(input: Option<&JsValue>) -> AuthResult<JsValue> {
    let mut output = validate_id(input, "body")?;
    let update = input.and_then(|value| value.get("update"));
    let Some(object) = update.and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[body.update] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(update)
        )));
    };
    let scopes = object.get("scopes");
    let Some(values) = scopes.and_then(JsValue::as_array) else {
        return Err(crate::endpoint::validation(format!(
            "[body.update.scopes] Invalid input: expected array, received {}",
            crate::authentication_helpers::json_type(scopes)
        )));
    };
    let issues = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            crate::authentication_helpers::field_issue(
                crate::authentication_helpers::JsonFieldKind::String,
                Some(value),
                crate::authentication_helpers::json_type(Some(value)),
            )
            .map(|issue| format!("[body.update.scopes.{index}] {issue}"))
        })
        .collect::<Vec<_>>();
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    if let JsValue::Object(object) = &mut output {
        _ = object.insert(
            "update".into(),
            JsValue::Object(
                [("scopes".into(), JsValue::Array(values.to_vec()))]
                    .into_iter()
                    .collect(),
            ),
        );
    }
    Ok(output)
}
impl OAuthProviderPlugin {
    /// Replace the current user's granted scopes with a subset allowed by the client.
    pub fn update_oauth_consent_endpoint(
        id: &str,
        scopes: &[String],
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "updateOAuthConsent")
            .with_body(&json!({"id":id,"update":{"scopes":scopes}}))
    }
    async fn owned_consent<S: AuthSchema>(
        &self,
        id: &str,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Result<alibi_core::store::OAuthConsent, EndpointResponse>> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        if id.is_empty() {
            return Ok(Err(super::clients::status_protocol_error(
                404,
                "not_found",
                "missing id parameter",
            )?));
        }
        let Some(row) = ctx.database.get_oauth_consent(id).await? else {
            return Ok(Err(super::clients::status_protocol_error(
                404,
                "not_found",
                "no consent",
            )?));
        };
        if row.user_id.as_deref() != Some(user.id().as_ref()) {
            return Ok(Err(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json")));
        }
        Ok(Ok(row))
    }
    pub(super) async fn update_consent<S: AuthSchema>(
        &self,
        input: ConsentUpdateInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let row = match Box::pin(self.owned_consent(&input.id, req, ctx)).await? {
            Ok(row) => row,
            Err(response) => return Ok(response),
        };
        let Some(client) = super::discovery::resolve(ctx, &row.client_id).await? else {
            return super::clients::status_protocol_error(404, "not_found", "client not found");
        };
        let allowed = client
            .metadata
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(
                || self.config.scopes.clone(),
                |scope| scope.split(' ').map(str::to_owned).collect::<Vec<_>>(),
            );
        if !input
            .update
            .scopes
            .iter()
            .all(|scope| allowed.contains(scope))
        {
            let owner = client
                .metadata
                .get("reference_id")
                .and_then(Value::as_str)
                .or(client.user_id.as_deref())
                .unwrap_or("undefined");
            return super::clients::status_protocol_error(
                400,
                "invalid_request",
                &format!("unable to provide scopes to {owner}"),
            );
        }
        let mut metadata = row
            .metadata
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("Invalid consent metadata"))?;
        _ = metadata.insert("scopes".into(), json!(input.update.scopes));
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid consent timestamp"))?;
        let updated = ctx
            .database
            .update_oauth_consent_metadata(&input.id, Value::Object(metadata), now)
            .await?;
        EndpointResponse::json(&updated.map(consent_value).transpose()?)
    }
}

impl OAuthProviderPlugin {
    /// Delete the current user's stored OAuth grant.
    pub fn delete_oauth_consent_endpoint(id: &str) -> AuthResult<ServerEndpoint<()>> {
        ServerEndpoint::new("oauth-provider", "deleteOAuthConsent").with_body(&json!({"id":id}))
    }
    pub(super) async fn delete_consent<S: AuthSchema>(
        &self,
        input: ConsentId,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let row = match Box::pin(self.owned_consent(&input.id, req, ctx)).await? {
            Ok(row) => row,
            Err(response) => return Ok(response),
        };
        ctx.database.delete_oauth_consent(&row.id).await?;
        Ok(EndpointResponse::empty().with_header("Content-Type", "application/json"))
    }
}
