//! Source-declared core session endpoint schemas (Better Auth 1.7.6).
use super::OpenApiEndpoint;
use serde_json::{Value, json};
fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
fn body(schema: &Value) -> Value {
    json!({"content":{"application/json":{"schema":schema}}})
}
fn status(description: &str) -> Value {
    json!({"type":"object","properties":{"status":{"type":"boolean","description":description}},"required":["status"]})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/update-session" => {
            metadata.operation_id = Some("updateSession".into());
            metadata.description = Some("Update the current session".into());
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":{
                    "type":"object","propertyNames":{"type":"string","description":"Field name must be a string"},"additionalProperties":{}
                }}}}),
            );
            drop(metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(json!({"type":"object","properties":{
                        "session":{"type":"object","$ref":"#/components/schemas/Session"}
                    }})),
                ),
            ));
        }
        "/list-sessions" => {
            metadata.operation_id = Some("listUserSessions".into());
            metadata.description = Some("List all active sessions for the user".into());
            drop(metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(json!({"type":"array","items":{"$ref":"#/components/schemas/Session"}})),
                ),
            ));
        }
        "/sign-out" => {
            metadata.operation_id = Some("signOut".into());
            metadata.description = Some("Sign out the current user".into());
            metadata.request_body = Some(
                json!({"required":false,"content":{"application/json":{"schema":{"type":"object","properties":{
                 "callbackURL":{"type":"string","description":"The URL to redirect to after provider logout"},
                 "disableRedirect":{"type":"boolean","description":"Return the provider logout URL without redirecting"},
                 "state":{"type":"string","description":"State to pass to the provider logout endpoint"}
                }}}}}),
            );
            drop(metadata.responses.insert("200".into(),response("Success",&(json!({"type":"object","properties":{
    "success":{"type":"boolean"},"url":{"type":"string","description":"Provider logout URL when RP-initiated logout is available"},
    "redirect":{"type":"boolean","description":"Whether the client should redirect to the provider logout URL"}
   }})))));
        }
        "/revoke-session" => {
            metadata.description = Some("Revoke a single session".into());
            metadata.request_body = Some(body(
                &(json!({"type":"object","properties":{"token":{"type":"string","description":"The token to revoke"}},"required":["token"]})),
            ));
            drop(metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(status("Indicates if the session was revoked successfully")),
                ),
            ));
        }
        "/revoke-sessions" => {
            metadata.description = Some("Revoke all sessions for the user".into());
            drop(metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(status("Indicates if all sessions were revoked successfully")),
                ),
            ));
        }
        "/revoke-other-sessions" => {
            metadata.description =
                Some("Revoke all other sessions for the user except the current one".into());
            drop(metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(status("Indicates if all other sessions were revoked successfully")),
                ),
            ));
        }
        _ => return None,
    }
    Some(metadata)
}
