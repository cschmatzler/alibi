//! Actual native application hooks shared by the fast and compat error API owners.
use alibi::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointResponse,
};
use alibi::utils::json;
use alibi::{AuthContext, AuthResponse, AuthResult, AuthSchema};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
pub(super) struct Application {
    pub(super) mode: Arc<Mutex<String>>,
    pub(super) events: Arc<Mutex<Vec<Value>>>,
}
pub(super) fn response_snapshot(response: &AuthResponse) -> Value {
    json!({"kind":"http-response","status":response.status,
        "headers":response.headers.iter().filter(|(name,_)|!name.eq_ignore_ascii_case("set-cookie")).map(|(k,v)|(k.to_ascii_lowercase(),v.clone())).collect::<HashMap<_,_>>(),
        "cookies":response.headers.get_all("set-cookie").cloned().collect::<Vec<_>>(),
        "body":if response.body.is_empty(){Value::Null}else{json!(String::from_utf8(response.body.clone()).unwrap())}})
}
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for Application {
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        if let Some(url) = call
            .request()
            .and_then(|request| request.url())
            .filter(|url| url.path().starts_with("/__test/profiles/server-error-"))
        {
            *self.mode.lock().unwrap() = url
                .query_pairs()
                .find_map(|(name, value)| (name == "application_mode").then(|| value.into_owned()))
                .unwrap_or_else(|| "normal".into());
            self.events.lock().unwrap().clear();
        }
        self.events.lock().unwrap().push(json!({"stage":"before","path":call.path(),"request":call.request().is_some(),"query":call.query()}));
        call.set_response_header("x-before", "discarded");
        let mode = self.mode.lock().unwrap().clone();
        if mode == "before-return" {
            return Ok(Some(BeforeEndpointAction::Respond(
                EndpointResponse::from_http_response(
                    AuthResponse::text(209, "application early")
                        .with_header("content-type", "text/plain"),
                ),
            )));
        }
        if mode == "patch-query" {
            return Ok(Some(BeforeEndpointAction::Patch(Box::new(
                EndpointContextPatch {
                    query: Some(json::parse_value("{\"error\":\"PATCHED_LOGICAL\"}")?),
                    ..Default::default()
                },
            ))));
        }
        Ok(None)
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        self.events.lock().unwrap().push(json!({"stage":"after","path":call.path(),"request":call.request().is_some(),"query":call.query(),"sessionUserId":call.session().map(|(user,_)|user.id),
            "returned":response.http_response().map_or_else(||json!({"kind":"json","value":response.result().as_ref().unwrap()}),response_snapshot)}));
        let mode = self.mode.lock().unwrap().clone();
        if let Some(raw) = response
            .http_response_mut()
            .filter(|_| mode == "mutate-response")
        {
            drop(raw.headers.insert("x-response-mutated", "actual"));
            raw.headers.append("set-cookie", "raw_a=one; Path=/");
            raw.headers.append("set-cookie", "raw_b=two; Path=/");
        }
        call.set_response_header("x-after", "actual");
        call.set_response_header("authorization", "request-only-header");
        call.queue_response_header("set-cookie", "application_a=first; Path=/; HttpOnly");
        call.queue_response_header("set-cookie", "application_b=second; Path=/; HttpOnly");
        if mode == "replace-json" {
            response.replace(json::parse_value("{\"replacement\":true}")?);
        }
        Ok(response)
    }
}
