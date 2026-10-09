//! Core email authentication DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Value, json};
fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/sign-in/email" => {
            metadata.operation_id = Some("signInEmail".into());
            metadata.description = Some("Sign in with email and password".into());
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{
    "email":{"type":"string","description":"Email of the user"},"password":{"type":"string","description":"Password of the user"},
    "callbackURL":{"type":"string","description":"Callback URL to use as a redirect for email verification"},"rememberMe":{"type":"boolean","description":"If this is false, the session will not be remembered. Default is `true`."}
   },"required":["email","password"]}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Success - Returns either session details or redirect URL",&(json!({"type":"object","description":"Session response when idToken is provided","properties":{"redirect":{"type":"boolean","enum":[false]},"token":{"type":"string","description":"Session token"},"url":{"type":"string","nullable":true},"user":{"type":"object","$ref":"#/components/schemas/User"}},"required":["redirect","token","user"]}))));
        }
        "/sign-up/email" => {
            metadata.operation_id = Some("signUpWithEmailAndPassword".into());
            metadata.description = Some("Sign up a user using email and password".into());
            metadata.request_body = Some(
                json!({"content":{"application/json":{"schema":{"type":"object","properties":{
    "name":{"type":"string","description":"The name of the user"},"email":{"type":"string","description":"The email of the user"},"password":{"type":"string","description":"The password of the user"},
    "image":{"type":"string","description":"The profile image URL of the user"},"callbackURL":{"type":"string","description":"The URL to use for email verification callback"},"rememberMe":{"type":"boolean","description":"If this is false, the session will not be remembered. Default is `true`."}
   },"required":["name","email","password"]}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Successfully created user",&(json!({"type":"object","properties":{"token":{"type":"string","nullable":true,"description":"Authentication token for the session"},"user":super::user_annotations::user()},"required":["user"]}))));
            _ = metadata.responses.insert(
                "422".into(),
                response(
                    "Unprocessable Entity. User already exists or failed to create user.",
                    &(json!({"type":"object","properties":{"message":{"type":"string"}}})),
                ),
            );
        }
        _ => return None,
    }
    Some(metadata)
}
