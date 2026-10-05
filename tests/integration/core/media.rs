//! The public plugin SDK receives decoded fields plus untouched upload bytes.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "contract tests assert independently specified wire fields; setup errors propagate"
)]

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::types::{MultipartFiles, ParsedRequestBody};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Upload(Arc<AtomicUsize>);
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Upload {
    fn name(&self) -> &'static str {
        "native-upload"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/upload", "upload")]
    }
    fn allowed_media_types(&self, _: &AuthRoute) -> Vec<&'static str> {
        vec![
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/octet-stream",
        ]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        let parsed = request.extensions().get::<ParsedRequestBody>().unwrap();
        let value = match parsed.as_ref() {
            ParsedRequestBody::Value(value) => value.to_json_value()?,
            ParsedRequestBody::Opaque(kind) => json!({"kind":kind}),
        };
        let files = request.extensions().get::<MultipartFiles>();
        let uploaded = files
            .as_ref()
            .and_then(|files| files.0.get("file"))
            .map(|file| json!({"name":file.filename,"type":file.content_type,"bytes":file.bytes}));
        Ok(Some(AuthResponse::json(
            200,
            &json!({"parsed":value,"file":uploaded,"original":request.body}),
        )?))
    }
}
#[tokio::test]
async fn public_media_admission_decodes_fields_and_uploads_before_invoking_plugins()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let auth = AuthBuilder::without_database(
        AuthConfig::new("native-upload-secret-at-least-32-characters")
            .base_url("http://media.test"),
    )
    .plugin(Upload(calls.clone()))
    .build()
    .await?;
    let cases=[
        ("application/x-www-form-urlencoded",b"name=Ada+Lovelace&tag=first&tag=second&literal=%2B".to_vec(),json!({"name":"Ada Lovelace","tag":"second","literal":"+"}),Value::Null),
        ("application/json; charset=utf-8",br#"{"name":"Ada","nested":[1,true]}"#.to_vec(),json!({"name":"Ada","nested":[1,true]}),Value::Null),
        ("text/plain",b"\xef\xbb\xbfhello text".to_vec(),json!("hello text"),Value::Null),
        ("application/octet-stream",vec![0,255,1,254],json!({"kind":"ArrayBuffer"}),Value::Null),
        ("multipart/form-data; boundary=native-boundary",b"--native-boundary\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nAda\r\n--native-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"proof.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\0\xffbytes\r\n--native-boundary--\r\n".to_vec(),json!({"name":"Ada","file":{}}),json!({"name":"proof.bin","type":"application/octet-stream","bytes":[0,255,98,121,116,101,115]})),
    ];
    let request = |media: &str, body: Vec<u8>| {
        let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/upload");
        request.headers.extend([
            ("origin".into(), "http://media.test".into()),
            ("content-type".into(), media.into()),
        ]);
        request.body = Some(body);
        // Caller-supplied decoded state must not bypass media admission/parsing.
        request.extensions().insert(ParsedRequestBody::Value(
            better_auth_core::utils::json::parse_value(r#"{"forged":true}"#).unwrap(),
        ));
        request
    };
    for (media, bytes, parsed, file) in cases {
        let response = Box::pin(auth.handle_request(request(media, bytes.clone()))).await?;
        assert_eq!(
            response.status,
            200,
            "{media}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let output: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            output,
            json!({"parsed":parsed,"file":file,"original":bytes})
        );
    }
    let admitted = calls.load(Ordering::SeqCst);
    for (media, bytes, status) in [
        ("application/xml", b"<root/>".to_vec(), 415),
        ("application/json", b"{".to_vec(), 400),
        ("multipart/form-data", b"missing-boundary".to_vec(), 500),
    ] {
        let response = Box::pin(auth.handle_request(request(media, bytes))).await?;
        assert_eq!(response.status, status, "{media}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            admitted,
            "invalid media reached plugin"
        );
    }
    Ok(())
}
