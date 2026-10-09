//! Core account endpoint DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Value, json};
fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
fn selection() -> Value {
    json!({"anyOf":[
     {"type":"object","properties":{"accountId":{"type":"string","description":"The Better Auth account ID"},"userId":{"type":"string","description":"The user ID associated with the account"}},"required":["accountId"]},
     {"type":"object","properties":{"useAccountCookie":{"enum":[true],"description":"Select the current OAuth account from its signed cookie"},"userId":{"type":"string","description":"The user ID associated with the account"}},"required":["useAccountCookie"]}
    ]})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/list-accounts" => {
            metadata.operation_id = Some("listUserAccounts".into());
            metadata.description = Some("List all accounts linked to the user".into());
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":"array","items":{"type":"object","properties":{
    "id":{"type":"string"},"providerId":{"type":"string"},"createdAt":{"type":"string","format":"date-time"},"updatedAt":{"type":"string","format":"date-time"},"accountId":{"type":"string"},"userId":{"type":"string"},"scopes":{"type":"array","items":{"type":"string"}}
   },"required":["id","providerId","createdAt","updatedAt","accountId","userId","scopes"]}}))));
        }
        "/unlink-account" => {
            metadata.description = Some("Unlink an account".into());
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"accountId":{"type":"string","description":"The Better Auth account ID to unlink"}},"required":["accountId"]}}}}),
            );
            _ = metadata.responses.insert(
                "200".into(),
                response(
                    "Success",
                    &(json!({"type":"object","properties":{"status":{"type":"boolean"}}})),
                ),
            );
        }
        "/get-access-token" | "/refresh-token" => {
            let refreshing = path == "/refresh-token";
            metadata.description = Some(
                if refreshing {
                    "Refresh the access token using a refresh token"
                } else {
                    "Get a valid access token, doing a refresh if needed"
                }
                .into(),
            );
            metadata.request_body = Some(
                json!({"required":true,"content":{"application/json":{"schema":selection()}}}),
            );
            let mut properties = serde_json::Map::new();
            for name in ["tokenType", "idToken", "accessToken"] {
                _ = properties.insert(name.into(), json!({"type":"string"}));
            }
            if refreshing {
                _ = properties.insert("refreshToken".into(), json!({"type":"string"}));
            }
            _ = properties.insert(
                "accessTokenExpiresAt".into(),
                json!({"type":"string","format":"date-time"}),
            );
            if refreshing {
                _ = properties.insert(
                    "refreshTokenExpiresAt".into(),
                    json!({"type":"string","format":"date-time"}),
                );
            }
            _ = metadata.responses.insert(
                "200".into(),
                response(
                    if refreshing {
                        "Access token refreshed successfully"
                    } else {
                        "A Valid access token"
                    },
                    &(json!({"type":"object","properties":properties})),
                ),
            );
            _ = metadata.responses.insert(
                "400".into(),
                json!({"description":"Invalid refresh token or provider configuration"}),
            );
        }
        "/account-info" => {
            metadata.description = Some("Get the account info provided by the provider".into());
            // The query is a union rather than a direct object; upstream reflects no query parameters.
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":"object","properties":{
    "user":{"type":"object","properties":{"name":{"type":"string"},"email":{"type":"string","nullable":true},"image":{"type":"string"},"emailVerified":{"type":"boolean"}},"required":["emailVerified"]},
    "account":{"type":"object","properties":{"id":{"type":"string"},"providerId":{"type":"string"},"accountId":{"type":"string"}},"required":["id","providerId","accountId"],"additionalProperties":false},
    "data":{"type":"object","properties":{},"additionalProperties":true}
   },"required":["user","data","account"],"additionalProperties":false}))));
        }
        _ => return None,
    }
    Some(metadata)
}
