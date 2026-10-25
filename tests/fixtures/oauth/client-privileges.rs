use alibi::plugins::{OAuthClientPrivilegeContext, OAuthClientPrivileges};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct ClientPrivileges {
    pub calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthClientPrivileges for ClientPrivileges {
    async fn allowed(&self, input: &OAuthClientPrivilegeContext) -> alibi::AuthResult<bool> {
        let decision = input.headers.get("x-client-decision").map(String::as_str);
        let mut call = json!({
            "action":input.action, "decision":decision,
            "caller":input.headers.get("x-policy-caller"),
            "user":{"id":input.user["id"],"email":input.user["email"]},
            "session":{"id":input.session["id"],"userId":input.session["userId"],"token":input.session["token"]},
        });
        if let Some(client_id) = &input.client_id {
            call["clientId"] = json!(client_id);
        }
        self.calls.lock().unwrap().push(call);
        match decision {
            Some("ordinary-error") => Err(alibi::AuthError::internal("client policy failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden("Client denied")),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("CLIENT_DENIED".into()),
                message: "Client denied".into(),
            }),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "CLIENT_UNAVAILABLE",
                message: "Client unavailable",
            }),
            Some("deny-scopes") => Ok(input.action != "configure-client-credentials-scopes"),
            _ => Ok(decision != Some("false")),
        }
    }
}
