//! Core user-management DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Value, json};

fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
pub(super) fn user() -> Value {
    json!({"type":"object","properties":{
 "id":{"type":"string","description":"The unique identifier of the user"},
 "email":{"type":"string","format":"email","description":"The email address of the user"},
 "name":{"type":"string","description":"The name of the user"},
 "image":{"type":"string","format":"uri","nullable":true,"description":"The profile image URL of the user"},
 "emailVerified":{"type":"boolean","description":"Whether the email has been verified"},
 "createdAt":{"type":"string","format":"date-time","description":"When the user was created"},
 "updatedAt":{"type":"string","format":"date-time","description":"When the user was last updated"}
},"required":["id","email","name","emailVerified","createdAt","updatedAt"]})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/update-user" => {
            metadata.operation_id = Some("updateUser".into());
            metadata.description = Some("Update the current user".into());
            metadata.request_body = Some(
                json!({"content":{"application/json":{"schema":{"type":"object","properties":{"name":{"type":"string","description":"The name of the user"},"image":{"type":"string","description":"The image of the user","nullable":true}}}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":"object","properties":{"user":{"type":"object","$ref":"#/components/schemas/User"}}}))));
        }
        "/change-password" => {
            metadata.operation_id = Some("changePassword".into());
            metadata.description = Some("Change the password of the user".into());
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{
    "newPassword":{"type":"string","description":"The new password to set"},"currentPassword":{"type":"string","description":"The current password is required"},"revokeOtherSessions":{"type":"boolean","description":"Must be a boolean value"}
   },"required":["newPassword","currentPassword"]}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Password successfully changed",&(json!({"type":"object","properties":{"token":{"type":"string","nullable":true,"description":"New session token if other sessions were revoked"},"user":user()},"required":["user"]}))));
        }
        "/delete-user" => {
            metadata.operation_id = Some("deleteUser".into());
            metadata.description = Some("Delete the user".into());
            metadata.request_body = Some(
                json!({"content":{"application/json":{"schema":{"type":"object","properties":{
                 "callbackURL":{"type":"string","description":"The callback URL to redirect to after the user is deleted"},"password":{"type":"string","description":"The user's password. Required if session is not fresh"},"token":{"type":"string","description":"The deletion verification token"}
                }}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("User deletion processed successfully",&(json!({"type":"object","properties":{"success":{"type":"boolean","description":"Indicates if the operation was successful"},"message":{"type":"string","enum":["User deleted","Verification email sent"],"description":"Status message of the deletion process"}},"required":["success","message"]}))));
        }
        "/delete-user/callback" => {
            metadata.description =
                Some("Callback to complete user deletion with verification token".into());
            metadata.parameters = vec![
                json!({"name":"token","in":"query","schema":{"type":"string","description":"The token to verify the deletion request"}}),
                json!({"name":"callbackURL","in":"query","schema":{"type":"string","description":"The URL to redirect to after deletion"}}),
            ];
            _ = metadata.responses.insert("200".into(),response("User successfully deleted",&(json!({"type":"object","properties":{"success":{"type":"boolean","description":"Indicates if the deletion was successful"},"message":{"type":"string","enum":["User deleted"],"description":"Confirmation message"}},"required":["success","message"]}))));
        }
        "/change-email" => {
            metadata.operation_id = Some("changeEmail".into());
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"newEmail":{"type":"string","description":"The new email address to set must be a valid email address"},"callbackURL":{"type":"string","description":"The URL to redirect to after email verification"}},"required":["newEmail"]}}}}),
            );
            _ = metadata.responses.insert("200".into(),response("Email change request processed successfully",&(json!({"type":"object","properties":{"user":{"type":"object","$ref":"#/components/schemas/User"},"status":{"type":"boolean","description":"Indicates if the request was successful"},"message":{"type":"string","enum":["Email updated","Verification email sent"],"description":"Status message of the email change process","nullable":true}},"required":["status"]}))));
        }
        _ => return None,
    }
    Some(metadata)
}
