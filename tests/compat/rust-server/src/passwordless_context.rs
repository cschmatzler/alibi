//! Capture actual native callback input and live proof state at the delivery boundary.
use crate::TestSchema;
use better_auth_core::{AuthResult, CallbackContext};
use serde_json::{Value, json};

pub(super) async fn snapshot(
    context: &CallbackContext,
    identifier: &str,
) -> AuthResult<Option<Value>> {
    let Some(request) = context.request.as_ref().filter(|request| {
        request
            .headers
            .get("x-callback-probe")
            .is_some_and(|value| value == "issue207")
    }) else {
        return Ok(None);
    };
    let auth = context
        .context::<TestSchema>()
        .ok_or_else(|| better_auth_core::AuthError::internal("wrong callback schema"))?;
    let body = request.body_as_json::<Value>()?;
    Ok(Some(json!({
        "method": format!("{:?}", request.method()).to_uppercase(),
        "path": request.url().map(|url| url.path()),
        "marker": request.headers.get("x-callback-probe"),
        "body": body,
        "basePath": auth.config.base_path,
        "proofExists": auth.database.get_verification_by_identifier(identifier).await?.is_some(),
    })))
}
