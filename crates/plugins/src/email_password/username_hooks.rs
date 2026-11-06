use super::{UsernameConfig, UsernameValidationOrder};
use alibi_core::store::UserCreateHook;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthTransaction, CreateUser};
use async_trait::async_trait;

pub(super) struct UsernameCreateHook(pub UsernameConfig);

fn candidate(data: &CreateUser, name: &str) -> Option<JsValue> {
    data.adapter_native_fields
        .get(name)
        .cloned()
        .map(JsValue::from)
        .or_else(|| {
            match name {
                "username" => data.username.clone(),
                "displayUsername" => data.display_username.clone(),
                _ => None,
            }
            .map(|value| JsValue::String(value.into()))
        })
        .or_else(|| data.additional_fields.get(name).cloned())
}

fn stage(data: &mut CreateUser, name: &str, value: JsValue) {
    data.adapter_native_fields.remove(name);
    let text = value.as_str().map(str::to_owned);
    match name {
        "username" => data.username = text,
        "displayUsername" => data.display_username = text,
        _ => unreachable!(),
    }
    _ = data.additional_fields.insert(name.into(), value);
}

fn normalize_display(policy: &UsernameConfig, value: &JsValue) -> AuthResult<JsValue> {
    if let JsValue::String(value) = value {
        return policy
            .normalize_display(value.require_str()?)
            .map(|value| JsValue::String(value.into()));
    }
    if policy.display_normalizer.is_none() {
        return Ok(value.clone());
    }
    Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
        "Configured display normalization requires a string",
    ))))
}

async fn validate_display(policy: &UsernameConfig, value: &JsValue) -> AuthResult<()> {
    let Some(validator) = &policy.display_validator else {
        return Ok(());
    };
    let normalized;
    let value =
        if policy.display_validation_order == Some(UsernameValidationOrder::PostNormalization) {
            normalized = normalize_display(policy, value)?;
            &normalized
        } else {
            value
        };
    let text = value.as_str().ok_or_else(|| {
        AuthError::CallbackFailure(Box::new(AuthError::internal(
            "Configured display validation requires a string",
        )))
    })?;
    if !validator
        .validate(text)
        .await
        .map_err(|error| match error {
            AuthError::Api { .. } | AuthError::Upstream { .. } | AuthError::CallbackFailure(_) => {
                error
            }
            error => AuthError::CallbackFailure(Box::new(error)),
        })?
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_DISPLAY_USERNAME",
            message: "Display username is invalid",
        });
    }
    Ok(())
}

#[async_trait]
impl<S: AuthSchema> UserCreateHook<S> for UsernameCreateHook {
    async fn before_create(
        &self,
        mut data: CreateUser,
        context: &AuthContext<S>,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<CreateUser> {
        let policy = &self.0;
        let username = candidate(&data, "username").filter(JsValue::is_truthy);
        let display = candidate(&data, "displayUsername").filter(JsValue::is_truthy);
        let path = alibi_core::endpoint::current_endpoint_call_context()
            .and_then(|call| call.path().map(str::to_owned))
            .or_else(|| {
                alibi_core::hooks::current_request_hook_context().map(|request| request.path)
            });
        let skip_validation = matches!(path.as_deref(), Some("/sign-up/email" | "/update-user"));
        if let Some(username) = username {
            if !skip_validation {
                policy.validate_raw_hook_value(&username).await?;
                let normalized = policy.normalize_raw_hook_value(&username)?;
                let existing = if let Some(transaction) = transaction {
                    transaction.get_user_by_username_value(&normalized).await?
                } else {
                    context
                        .database
                        .get_user_by_username_value(&normalized)
                        .await?
                };
                if existing.is_some() {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "USERNAME_IS_ALREADY_TAKEN",
                        message: "Username is already taken. Please try another.",
                    });
                }
                if let Some(display) = &display {
                    validate_display(policy, display).await?;
                }
            }
            stage(
                &mut data,
                "username",
                policy.normalize_raw_hook_value(&username)?,
            );
            if policy.include_display_username {
                let display = match display {
                    Some(display) => normalize_display(policy, &display)?,
                    None => username,
                };
                stage(&mut data, "displayUsername", display);
            }
        } else if policy.include_display_username
            && let Some(display) = display
        {
            stage(
                &mut data,
                "displayUsername",
                normalize_display(policy, &display)?,
            );
        }
        if !policy.include_display_username {
            data.display_username = None;
            data.adapter_native_fields.remove("displayUsername");
            data.additional_fields.shift_remove("displayUsername");
        }
        Ok(data)
    }
}
