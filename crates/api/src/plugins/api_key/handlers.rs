use super::ApiKeyPlugin;
use super::types::{
    ApiKeyView, CreateKeyRequest, CreateKeyResponse, DeleteKeyRequest, ListKeysQuery,
    ListKeysResponse, UpdateKeyRequest,
};
use crate::plugins::helpers;
use better_auth_core::{ApiKey, AuthContext, AuthResult, CreateApiKey, UpdateApiKey};

// ---------------------------------------------------------------------------
// Core functions -- framework-agnostic business logic
// ---------------------------------------------------------------------------

impl ApiKeyPlugin {
    /// Create a key on behalf of `body.user_id` from trusted server code.
    /// Organization configurations still require the user's organization permission.
    ///
    /// # Errors
    ///
    /// Returns errors from input validation, permission checks, or API-key storage.
    pub async fn create_key(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        body: &CreateKeyRequest,
    ) -> AuthResult<CreateKeyResponse> {
        use validator::Validate as _;
        body.validate()
            .map_err(|error| better_auth_core::AuthError::Validation(error.to_string()))?;
        let user_id = body
            .user_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))?;
        create_key_for_user(body, user_id, self, ctx, None).await
    }

    /// Update a key on behalf of `body.user_id` from trusted server code.
    /// The caller must authorize access before invoking this server-only method.
    ///
    /// # Errors
    ///
    /// Returns errors from input validation, permission checks, or API-key storage.
    pub async fn update_key(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        body: &UpdateKeyRequest,
    ) -> AuthResult<ApiKeyView> {
        use validator::Validate as _;
        body.validate()
            .map_err(|error| better_auth_core::AuthError::Validation(error.to_string()))?;
        let user_id = body
            .user_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))?;
        update_key_for_user(body, user_id, self, ctx).await
    }
}

// ---------------------------------------------------------------------------
// Permissions verification helper (RBAC)
// ---------------------------------------------------------------------------

/// Check whether `key_permissions` (JSON object mapping role->actions) covers
/// all of the `required_permissions`.
///
/// Mirrors the TypeScript `role(apiKeyPermissions).authorize(permissions)`
/// implementation. Required actions must be a subset of the API key's actions
/// for each resource/role.
pub(super) fn check_permissions(
    key_permissions_json: &str,
    required: &serde_json::Value,
) -> AuthResult<bool> {
    use better_auth_core::utils::json::{JsValue, parse_value};
    let Some(required_map) = required.as_object().filter(|map| !map.is_empty()) else {
        return Ok(false);
    };
    let Ok(permitted) = parse_value(key_permissions_json) else {
        return Ok(false);
    };
    if !json_truthy(&permitted) {
        return Ok(false);
    }
    for (resource, requested) in required_map {
        let allowed = permitted.get(resource).or_else(|| {
            let index = resource.parse::<usize>().ok()?;
            (index.to_string() == *resource)
                .then(|| permitted.as_array()?.get(index))
                .flatten()
        });
        let Some(allowed) = allowed.filter(|value| json_truthy(value)) else {
            return Ok(false);
        };
        let (actions, any) = if let Some(actions) = requested.as_array() {
            (actions.as_slice(), false)
        } else if let Some(request) = requested.as_object() {
            let Some(actions) = request.get("actions").and_then(serde_json::Value::as_array) else {
                return Ok(false);
            };
            (
                actions.as_slice(),
                request.get("connector").and_then(serde_json::Value::as_str) == Some("OR"),
            )
        } else {
            return Err(better_auth_core::AuthError::internal(
                "Invalid access control request",
            ));
        };
        if actions.is_empty() {
            return Ok(false);
        }
        let mut authorized = false;
        for action in actions {
            let admitted = if let Some(action) = action.as_str() {
                match allowed {
                    JsValue::Array(values) => values.iter().any(|value| {
                        value
                            .as_str()
                            .is_some_and(|value| value == action && !revived_permission_date(value))
                    }),
                    JsValue::String(value) if !revived_permission_date(value) => {
                        value.contains(action)
                    }
                    JsValue::Null
                    | JsValue::Bool(_)
                    | JsValue::Number(_)
                    | JsValue::Object(_)
                    | JsValue::String(_) => {
                        return Err(better_auth_core::AuthError::internal(
                            "Stored permission actions do not support includes",
                        ));
                    }
                }
            } else {
                false
            };
            if any && admitted {
                authorized = true;
                break;
            }
            if !any && !admitted {
                return Ok(false);
            }
            authorized |= admitted;
        }
        if !authorized {
            return Ok(false);
        }
    }
    Ok(true)
}

// safeJSONParse revives this exact ISO-shaped string into a Date before role
// authorization. A Date does not provide String.includes and is not equal to a
// requested string when nested inside an action array.
fn revived_permission_date(value: &str) -> bool {
    better_auth_core::utils::datetime::normalize_json_date(value).is_some()
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn create_key_core(
    body: &CreateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&better_auth_core::AuthRequest>,
) -> AuthResult<CreateKeyResponse> {
    let _ignored_as_deref = plugin.resolve_configuration(body.config_id.as_deref())?;
    if body.refill_amount.is_some()
        || body.refill_interval.is_some()
        || body.rate_limit_max.is_some()
        || body.rate_limit_time_window.is_some()
        || body.rate_limit_enabled.is_some()
        || body.permissions.is_some()
        || body.remaining.is_some()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::ServerOnlyProperty,
        ));
    }
    if body.user_id.is_some() {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::UnauthorizedSession,
        ));
    }
    create_key_for_user(body, user_id.as_ref(), plugin, ctx, request).await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep key policy checks, hook callbacks, and persistence in their observable request order"
)]
pub(super) async fn create_key_for_user(
    body: &CreateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&better_auth_core::AuthRequest>,
) -> AuthResult<CreateKeyResponse> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let reference_id = match config.references {
        super::ApiKeyReferences::User => user_id.to_owned(),
        super::ApiKeyReferences::Organization => {
            let organization_id = body
                .organization_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    super::api_key_error(super::ApiKeyErrorCode::OrganizationIdRequired)
                })?;
            helpers::require_org_api_key_permission(ctx, user_id, organization_id, "create")
                .await?;
            organization_id.to_owned()
        }
    };

    ApiKeyPlugin::validate_metadata(config, body.metadata.as_ref())?;
    ApiKeyPlugin::validate_refill(
        body.refill_interval.filter(|value| *value != 0.0),
        body.refill_amount.filter(|value| *value != 0.0),
    )?;
    let effective_expires_in = ApiKeyPlugin::validate_expires_in(config, body.expires_in)?;
    ApiKeyPlugin::validate_prefix(config, body.prefix.as_deref())?;
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), true)?;

    plugin.maybe_delete_expired(ctx).await?;
    let (full_key, hash, start) = if let Some(generator) = &config.custom_key_generator {
        let full_key = generator
            .generate_key(&super::ApiKeyGenerationOptions {
                length: config.key_length,
                prefix: body
                    .prefix
                    .as_deref()
                    .filter(|prefix| !prefix.is_empty())
                    .or(config.prefix.as_deref()),
            })
            .await?;
        let hash = if config.disable_key_hashing {
            full_key.clone()
        } else {
            ApiKeyPlugin::hash_key(&full_key)
        };
        let start = ApiKeyPlugin::starting_characters(&full_key, config.starting_characters_length);
        (full_key, hash, start)
    } else {
        ApiKeyPlugin::generate_key(config, body.prefix.as_deref())?
    };
    let dynamic_permissions = match &config.default_permissions_callback {
        Some(callback) => Some(
            callback
                .default_permissions(
                    &reference_id,
                    &super::ApiKeyCallbackContext::new(request, ctx, &config.config_id),
                )
                .await?,
        ),
        None => None,
    };
    let input = CreateApiKey {
        reference_id,
        config_id: config.config_id.clone(),
        name: body.name.clone(),
        prefix: body.prefix.clone().or_else(|| config.prefix.clone()),
        key_hash: hash,
        start: config.store_starting_characters.then_some(start),
        expires_at: expiration_date(effective_expires_in)?,
        remaining: body.remaining,
        rate_limit_enabled: body.rate_limit_enabled.unwrap_or(config.rate_limit.enabled),
        rate_limit_time_window: body
            .rate_limit_time_window
            .or(Some(config.rate_limit.time_window)),
        rate_limit_max: body.rate_limit_max.or(Some(config.rate_limit.max_requests)),
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .or(dynamic_permissions.as_ref())
            .or(config.default_permissions.as_ref())
            .map(better_auth_core::utils::json::to_string)
            .transpose()?,
        // Source supplies explicit JSON null to its JSON-column adapter when
        // metadata is absent or falsy, preserving "null" rather than SQL NULL.
        metadata: Some(better_auth_core::utils::json::to_string(
            body.metadata
                .as_ref()
                .filter(|value| json_truthy(value))
                .unwrap_or(&better_auth_core::utils::json::JsValue::Null),
        )?),
        enabled: true,
    };
    let api_key = config.create_stored_key(ctx, input).await?;
    let mut api_key = ApiKeyView::from(&api_key);
    // Upstream returns supplied falsy metadata at creation, but stores null.
    api_key.metadata = body
        .metadata
        .as_ref()
        .map(better_auth_core::utils::json::JsValue::to_json_value)
        .transpose()?;
    Ok(CreateKeyResponse {
        key: full_key,
        api_key,
    })
}

fn json_truthy(value: &better_auth_core::utils::json::JsValue) -> bool {
    use better_auth_core::utils::json::JsValue;
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn expiration_date(seconds: Option<f64>) -> AuthResult<Option<String>> {
    let Some(seconds) = seconds.filter(|seconds| *seconds != 0.0 && !seconds.is_nan()) else {
        return Ok(None);
    };
    let milliseconds = chrono::Utc::now().timestamp_millis() as f64 + seconds * 1000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(better_auth_core::AuthError::internal("Invalid Date"));
    }
    let date = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or_else(|| better_auth_core::AuthError::internal("Invalid Date"))?;
    Ok(Some(
        date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    ))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn get_key_core(
    id: &str,
    config_id: Option<&str>,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let config = plugin.resolve_configuration(config_id)?;
    let api_key = helpers::get_owned_api_key(ctx, config, id, user_id.as_ref(), "read").await?;
    plugin.maybe_delete_expired(ctx).await?;
    Ok(ApiKeyView::from(&api_key))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_keys_core(
    user_id: impl AsRef<str>,
    query: &ListKeysQuery,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListKeysResponse> {
    let organization_id = query.organization_id.as_deref().filter(|id| !id.is_empty());
    if let Some(organization_id) = organization_id {
        helpers::require_org_api_key_permission(ctx, user_id.as_ref(), organization_id, "read")
            .await?;
    }
    let reference_id = query
        .organization_id
        .as_deref()
        .unwrap_or_else(|| user_id.as_ref());
    let references = if organization_id.is_some() {
        super::ApiKeyReferences::Organization
    } else {
        super::ApiKeyReferences::User
    };
    let config_id = query.config_id.as_deref().filter(|id| !id.is_empty());
    if config_id.is_some() {
        let _ignored_resolve_configuration = plugin.resolve_configuration(config_id)?;
    }

    let keys = if let Some(config_id) = config_id {
        plugin
            .resolve_configuration(Some(config_id))?
            .list_stored_keys(
                ctx,
                reference_id,
                query.sort_by.as_deref(),
                query.sort_direction.as_deref(),
            )
            .await?
    } else {
        plugin
            .list_storage_keys(
                ctx,
                reference_id,
                query.sort_by.as_deref(),
                query.sort_direction.as_deref(),
            )
            .await?
    };
    let mut views: Vec<ApiKeyView> = keys
        .iter()
        .filter(|key| {
            let key_references = plugin
                .configurations
                .iter()
                .find(|config| super::config_id_matches(&key.config_id, &config.config_id))
                .map(|config| config.references)
                .unwrap_or_default();
            key.reference_id == reference_id
                && key_references == references
                && config_id.is_none_or(|id| super::config_id_matches(&key.config_id, id))
        })
        .map(ApiKeyView::from)
        .collect();

    let total = views.len();
    if let Some(offset) = query.offset {
        views = views.split_off(offset.min(views.len()));
    }
    if let Some(limit) = query.limit {
        views.truncate(limit);
    }
    plugin.maybe_delete_expired(ctx).await?;
    Ok(ListKeysResponse {
        api_keys: views,
        total,
        limit: query.limit,
        offset: query.offset,
    })
}

fn compare_numbers(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.total_cmp(&right),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
    }
}

fn compare_strings(
    left: Option<&str>,
    right: Option<&str>,
    from_database: bool,
) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) if !from_database => {
            left.encode_utf16().cmp(right.encode_utf16())
        }
        _ => left.cmp(&right),
    }
}

fn compare_metadata(left: Option<&str>, right: Option<&str>) -> AuthResult<std::cmp::Ordering> {
    use better_auth_core::utils::{
        javascript::string_to_number,
        json::{JsValue, parse_value},
    };
    let left = left.map(parse_value).transpose()?.unwrap_or(JsValue::Null);
    let right = right.map(parse_value).transpose()?.unwrap_or(JsValue::Null);
    match (left.is_null(), right.is_null()) {
        (true, true) => return Ok(std::cmp::Ordering::Equal),
        (true, false) => return Ok(std::cmp::Ordering::Less),
        (false, true) => return Ok(std::cmp::Ordering::Greater),
        (false, false) => {}
    }
    let primitive = |value: JsValue| match value {
        JsValue::Array(_) | JsValue::Object(_) => value
            .coerce_string()
            .map(JsValue::String)
            .map_err(better_auth_core::AuthError::internal),
        value => Ok(value),
    };
    let left = primitive(left)?;
    let right = primitive(right)?;
    if let (JsValue::String(left), JsValue::String(right)) = (&left, &right) {
        return Ok(compare_strings(Some(left), Some(right), false));
    }
    let number = |value: &JsValue| match value {
        JsValue::Null => Some(0.0),
        JsValue::Bool(value) => Some(f64::from(*value)),
        JsValue::Number(value) => Some(*value),
        JsValue::String(value) => string_to_number(value),
        JsValue::Array(_) | JsValue::Object(_) => None,
    };
    Ok(number(&left)
        .zip(number(&right))
        .and_then(|(left, right)| left.partial_cmp(&right))
        .unwrap_or(std::cmp::Ordering::Equal))
}

pub(super) fn sort_keys(
    keys: &mut [ApiKey],
    sort_by: &str,
    direction: Option<&str>,
    from_database: bool,
) -> AuthResult<()> {
    if sort_by == "metadata" && !from_database {
        // Source-authored boxed primitives can make relational comparison
        // cyclic. Slice sorting requires a total order and can panic; stable
        // merging only needs the observed pairwise result and propagates
        // actual coercion errors without mutating the stored rows.
        let mut source = keys.to_vec();
        let mut target = source.clone();
        let mut width = 1;
        while width < keys.len() {
            for start in (0..keys.len()).step_by(width.saturating_mul(2)) {
                let middle = start.saturating_add(width).min(keys.len());
                let end = middle.saturating_add(width).min(keys.len());
                let mut left = start;
                let mut right = middle;
                let run = target.get_mut(start..end).ok_or_else(|| {
                    better_auth_core::AuthError::internal("Invalid metadata sort run")
                })?;
                for slot in run {
                    let take_left = if left == middle {
                        false
                    } else if right == end {
                        true
                    } else {
                        let ordering = compare_metadata(
                            source
                                .get(left)
                                .ok_or_else(|| {
                                    better_auth_core::AuthError::internal(
                                        "Invalid metadata sort index",
                                    )
                                })?
                                .metadata
                                .as_deref(),
                            source
                                .get(right)
                                .ok_or_else(|| {
                                    better_auth_core::AuthError::internal(
                                        "Invalid metadata sort index",
                                    )
                                })?
                                .metadata
                                .as_deref(),
                        )?;
                        let ordering = if direction == Some("desc") {
                            ordering.reverse()
                        } else {
                            ordering
                        };
                        ordering != std::cmp::Ordering::Greater
                    };
                    let index = if take_left {
                        let index = left;
                        left += 1;
                        index
                    } else {
                        let index = right;
                        right += 1;
                        index
                    };
                    slot.clone_from(source.get(index).ok_or_else(|| {
                        better_auth_core::AuthError::internal("Invalid metadata sort index")
                    })?);
                }
            }
            std::mem::swap(&mut source, &mut target);
            width = width.saturating_mul(2);
        }
        keys.clone_from_slice(&source);
        return Ok(());
    }
    keys.sort_by(|left, right| {
        let a = ApiKeyView::from(left);
        let b = ApiKeyView::from(right);
        let strings = |left, right| compare_strings(left, right, from_database);
        let ordering = match sort_by {
            "key" => strings(Some(&left.key_hash), Some(&right.key_hash)),
            "id" => strings(Some(&a.id), Some(&b.id)),
            "name" => strings(a.name.as_deref(), b.name.as_deref()),
            "start" => strings(a.start.as_deref(), b.start.as_deref()),
            "prefix" => strings(a.prefix.as_deref(), b.prefix.as_deref()),
            "referenceId" => strings(Some(&a.reference_id), Some(&b.reference_id)),
            "configId" => strings(Some(&a.config_id), Some(&b.config_id)),
            "permissions" => strings(left.permissions.as_deref(), right.permissions.as_deref()),
            "metadata" => strings(left.metadata.as_deref(), right.metadata.as_deref()),
            "enabled" => a.enabled.cmp(&b.enabled),
            "rateLimitEnabled" => a.rate_limit_enabled.cmp(&b.rate_limit_enabled),
            "createdAt" => a.created_at.cmp(&b.created_at),
            "updatedAt" => a.updated_at.cmp(&b.updated_at),
            "expiresAt" => a.expires_at.cmp(&b.expires_at),
            "lastRequest" => a.last_request.cmp(&b.last_request),
            "lastRefillAt" => a.last_refill_at.cmp(&b.last_refill_at),
            "remaining" => compare_numbers(a.remaining, b.remaining),
            "requestCount" => compare_numbers(a.request_count, b.request_count),
            "rateLimitMax" => compare_numbers(a.rate_limit_max, b.rate_limit_max),
            "rateLimitTimeWindow" => {
                compare_numbers(a.rate_limit_time_window, b.rate_limit_time_window)
            }
            "refillAmount" => compare_numbers(a.refill_amount, b.refill_amount),
            "refillInterval" => compare_numbers(a.refill_interval, b.refill_interval),
            _ => std::cmp::Ordering::Equal,
        };
        if direction == Some("desc") {
            ordering.reverse()
        } else {
            ordering
        }
    });
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn update_key_core(
    body: &UpdateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    if body
        .user_id
        .as_deref()
        .is_some_and(|id| !id.is_empty() && id != user_id.as_ref())
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::UnauthorizedSession,
        ));
    }
    if body.refill_amount.is_some()
        || body.refill_interval.is_some()
        || body.rate_limit_max.is_some()
        || body.rate_limit_time_window.is_some()
        || body.rate_limit_enabled.is_some()
        || body.remaining.is_some()
        || body.permissions.is_some()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::ServerOnlyProperty,
        ));
    }
    update_key_for_user(body, user_id.as_ref(), plugin, ctx).await
}

pub(super) async fn update_key_for_user(
    body: &UpdateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    drop(helpers::get_owned_api_key(ctx, config, &body.key_id, user_id, "update").await?);
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), false)?;

    let expires_at = match body.expires_in {
        None => None,
        Some(_) if config.key_expiration.disable_custom_expires_time => {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::KeyDisabledExpiration,
            ));
        }
        Some(None) => Some(None),
        Some(Some(seconds)) => {
            let validated = ApiKeyPlugin::validate_expires_in(config, Some(seconds))?;
            Some(expiration_date(validated)?)
        }
    };
    let metadata = body.metadata.as_ref().filter(|_| config.enable_metadata);
    if let Some(metadata) = metadata
        && !(metadata.is_null() || metadata.is_object() || metadata.is_array())
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::InvalidMetadataType,
        ));
    }
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;
    if body.name.is_none()
        && body.enabled.is_none()
        && expires_at.is_none()
        && metadata.is_none()
        && body.remaining.is_none()
        && body.refill_amount.is_none()
        && body.refill_interval.is_none()
        && body.rate_limit_enabled.is_none()
        && body.rate_limit_time_window.is_none()
        && body.rate_limit_max.is_none()
        && body.permissions.is_none()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::NoValuesToUpdate,
        ));
    }
    let update = UpdateApiKey {
        name: body.name.clone(),
        enabled: body.enabled,
        remaining: body.remaining,
        rate_limit_enabled: body.rate_limit_enabled,
        rate_limit_time_window: body.rate_limit_time_window,
        rate_limit_max: body.rate_limit_max,
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .map(better_auth_core::utils::json::to_string)
            .transpose()?,
        metadata: metadata
            .map(better_auth_core::utils::json::to_string)
            .transpose()?,
        expires_at,
        ..Default::default()
    };
    let updated = config.update_stored_key(ctx, &body.key_id, update).await?;
    plugin.maybe_delete_expired(ctx).await?;
    Ok(ApiKeyView::from(&updated))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn delete_key_core(
    body: &DeleteKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<serde_json::Value> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let key =
        helpers::get_owned_api_key(ctx, config, &body.key_id, user_id.as_ref(), "delete").await?;
    config.remove_key(ctx, &key).await?;
    plugin.maybe_delete_expired(ctx).await?;
    Ok(serde_json::json!({ "success": true }))
}
