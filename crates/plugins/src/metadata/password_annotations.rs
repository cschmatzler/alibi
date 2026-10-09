//! Core password endpoint DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Value, json};

fn response(schema: &Value) -> Value {
    json!({"description":"Success","content":{"application/json":{"schema":schema}}})
}
fn body(schema: &Value) -> Value {
    json!({"required":true,"content":{"application/json":{"schema":schema}}})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    let status = json!({"type":"object","properties":{"status":{"type":"boolean"}}});
    match path {
        "/request-password-reset" => {
            metadata.operation_id = Some("requestPasswordReset".into());
            metadata.description = Some("Send a password reset email to the user".into());
            metadata.request_body = Some(body(
                &(json!({"type":"object","properties":{
    "email":{"type":"string","description":"The email address of the user to send a password reset email to"},
    "redirectTo":{"type":"string","description":"The URL to redirect the user to reset their password. If the token isn't valid or expired, it'll be redirected with a query parameter `?error=INVALID_TOKEN`. If the token is valid, it'll be redirected with a query parameter `?token=VALID_TOKEN"}
   },"required":["email"]})),
            ));
            _ = metadata.responses.insert("200".into(),response(&(json!({"type":"object","properties":{"status":{"type":"boolean"},"message":{"type":"string"}}}))));
        }
        "/reset-password/:token" | "/reset-password/{token}" => {
            metadata.document_path = Some("/reset-password/:token".into());
            metadata.operation_id = Some("resetPasswordCallback".into());
            metadata.description =
                Some("Redirects the user to the callback URL with the token".into());
            metadata.parameters = vec![
                json!({"name":"token","in":"path","required":true,"description":"The token to reset the password","schema":{"type":"string"}}),
                json!({"name":"callbackURL","in":"query","required":true,"description":"The URL to redirect the user to reset their password","schema":{"type":"string"}}),
            ];
            _ = metadata.responses.insert(
                "200".into(),
                response(&(json!({"type":"object","properties":{"token":{"type":"string"}}}))),
            );
        }
        "/reset-password" => {
            metadata.operation_id = Some("resetPassword".into());
            metadata.description = Some("Reset the password for a user".into());
            metadata.request_body = Some(body(
                &(json!({"type":"object","properties":{"newPassword":{"type":"string","description":"The new password to set"},"token":{"type":"string","description":"The token to reset the password"}},"required":["newPassword"]})),
            ));
            _ = metadata.responses.insert("200".into(), response(&(status)));
        }
        "/verify-password" => {
            metadata.operation_id = Some("verifyPassword".into());
            metadata.description = Some("Verify the current user's password".into());
            metadata.request_body = Some(body(
                &(json!({"type":"object","properties":{"password":{"type":"string","description":"The password to verify"}},"required":["password"]})),
            ));
            _ = metadata.responses.insert("200".into(), response(&(status)));
        }
        _ => return None,
    }
    Some(metadata)
}
