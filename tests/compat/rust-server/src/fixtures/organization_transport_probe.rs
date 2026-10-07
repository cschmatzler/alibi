//! Application middleware observes actual premature HTTP service-future drops.
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    middleware::Next,
    response::Response,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
#[derive(Clone, Default)]
pub(crate) struct Probe(Arc<Mutex<Receipts>>);
#[derive(Default)]
struct Receipts {
    aborted: HashSet<String>,
    completed: HashSet<String>,
}
struct DropReceipt {
    probe: Probe,
    marker: Option<String>,
    completed: bool,
}
impl Drop for DropReceipt {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(marker) = self.marker.take() {
                let _ = self.probe.0.lock().unwrap().aborted.insert(marker);
            }
        }
    }
}
pub(crate) async fn observe(State(probe): State<Probe>, request: Request, next: Next) -> Response {
    let marker = request
        .headers()
        .get("x-continuation-marker")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut receipt = DropReceipt {
        probe,
        marker,
        completed: false,
    };
    let response = next.run(request).await;
    receipt.completed = true;
    response
}
pub(crate) fn router(probe: Probe) -> Router {
    Router::new().route("/__test/organization-transport-reset",post(|State(probe):State<Probe>|async move{*probe.0.lock().unwrap()=Receipts::default();Json(json!({"reset":true}))}))
 .route("/__test/organization-transport-completion",get(|State(probe):State<Probe>,Query(query):Query<HashMap<String,String>>|async move{let marker=query.get("marker").cloned().unwrap_or_default();for _ in 0..200{if probe.0.lock().unwrap().completed.contains(&marker){break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}Json::<Value>(json!({"marker":marker,"completed":probe.0.lock().unwrap().completed.contains(&marker)}))}))
 .route("/__test/organization-transport-state",get(|State(probe):State<Probe>,Query(query):Query<HashMap<String,String>>|async move{let marker=query.get("marker").cloned().unwrap_or_default();for _ in 0..200{if probe.0.lock().unwrap().aborted.contains(&marker){break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}Json::<Value>(json!({"marker":marker,"aborted":probe.0.lock().unwrap().aborted.contains(&marker)}))})).with_state(probe)
}

#[async_trait::async_trait]
impl alibi_core::AuthPlugin<crate::TestSchema> for Probe {
    fn name(&self) -> &'static str {
        "organization-transport-observer"
    }
    fn routes(&self) -> Vec<alibi_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _request: &alibi_core::AuthRequest,
        _ctx: &alibi_core::AuthContext<crate::TestSchema>,
    ) -> alibi_core::AuthResult<Option<alibi_core::AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &alibi_core::AuthRequest,
        _ctx: &alibi_core::AuthContext<crate::TestSchema>,
        response: alibi_core::AuthResponse,
    ) -> alibi_core::AuthResult<alibi_core::AuthResponse> {
        if let Some(marker) = request.headers.get("x-continuation-marker") {
            let _ = self.0.lock().unwrap().completed.insert(marker.clone());
        }
        Ok(response)
    }
}
