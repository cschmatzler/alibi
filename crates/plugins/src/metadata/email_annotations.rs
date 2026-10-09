//! Core email-verification endpoint DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Value, json};
fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/send-verification-email" => {
            metadata.operation_id = Some("sendVerificationEmail".into());
            metadata.description = Some("Send a verification email to the user".into());
            metadata.request_body = Some(
                json!({"content":{"application/json":{"schema":{"type":"object","properties":{
    "email":{"type":"string","description":"The email to send the verification email to","example":"user@example.com"},
    "callbackURL":{"type":"string","description":"The URL to use for email verification callback","example":"https://example.com/callback","nullable":true}
   },"required":["email"]}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":"object","properties":{"status":{"type":"boolean","description":"Indicates if the email was sent successfully","example":true}}}))));
            _ = metadata.responses.insert("400".into(),response("Bad Request",&(json!({"type":"object","properties":{"message":{"type":"string","description":"Error message","example":"Verification email isn't enabled"}}}))));
        }
        "/verify-email" => {
            metadata.description = Some("Verify the email of the user".into());
            metadata.parameters = vec![
                json!({"name":"token","in":"query","description":"The token to verify the email","required":true,"schema":{"type":"string"}}),
                json!({"name":"callbackURL","in":"query","description":"The URL to redirect to after email verification","required":false,"schema":{"type":"string"}}),
            ];
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":"object","properties":{"user":{"type":"object","$ref":"#/components/schemas/User"},"status":{"type":"boolean","description":"Indicates if the email was verified successfully"}},"required":["user","status"]}))));
        }
        _ => return None,
    }
    Some(metadata)
}
