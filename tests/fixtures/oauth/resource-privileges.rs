use alibi::plugins::{OAuthResourcePrivilegeContext, OAuthResourcePrivileges};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct ResourcePrivileges {
    pub calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthResourcePrivileges for ResourcePrivileges {
    async fn allowed(&self, input: &OAuthResourcePrivilegeContext) -> alibi::AuthResult<bool> {
        let decision = input.headers.get("x-resource-decision").map(String::as_str);
        self.calls.lock().unwrap().push(json!({
            "action":input.action, "decision":decision, "resourceId":input.resource_id,
            "caller":input.headers.get("x-policy-caller"),
            "user":{"id":input.user["id"],"email":input.user["email"]},
            "session":{"id":input.session["id"],"userId":input.session["userId"],"token":input.session["token"]},
        }));
        match decision {
            Some("ordinary-error") => Err(alibi::AuthError::internal("resource policy failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden("Resource denied")),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("RESOURCE_DENIED".into()),
                message: "Resource denied".into(),
            }),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "RESOURCE_UNAVAILABLE",
                message: "Resource unavailable",
            }),
            _ => Ok(decision != Some("false")),
        }
    }
}
