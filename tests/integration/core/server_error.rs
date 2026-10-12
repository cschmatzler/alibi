//! A direct error call owns a real HTTP response instead of a JSON surrogate.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified response and hook receipts"
)]
use alibi::endpoint::EndpointOptions;
use alibi::{AuthBuilder, AuthConfig, AuthRequest, HttpMethod};
use serde_json::{Value, json};
#[path = "../../fixtures/server_error_application.rs"]
mod application;
use application::Application;

#[tokio::test]
async fn server_error_uses_physical_url_and_preserves_raw_response_and_hook_headers()
-> Result<(), Box<dyn std::error::Error>> {
    for profile in ["default", "html", "configured"] {
        let app = Application::default();
        let mut config = AuthConfig::new("logical-error-native-secret-at-least-32-chars")
            .base_url("http://logical-error.test");
        config.render_error_page = profile != "default";
        if profile == "configured" {
            config.api_error_url = Some("/problem?keep=a%2Bb#error-panel".into());
        }
        let auth = AuthBuilder::without_database(config)
            .endpoint_hook(app.clone())
            .build()
            .await?;
        let endpoint = || {
            alibi::plugins::user_management::error_endpoint().with_query(
                &json!({"error":"FORGED_LOGICAL","error_description":"forged description"}),
            )
        };
        let denied = auth
            .dispatch_endpoint(endpoint()?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 500);
        assert!(!alibi::endpoint::is_endpoint_api_error(&denied.error));
        assert!(denied.headers.is_none());
        assert_eq!(app.events.lock().unwrap().len(), 1);
        let description = r#"<b>space + & café</b> &lt; &#65; "quoted""#;
        for (query, code, detail) in [
            (String::new(), "UNKNOWN", None),
            (
                "error=FIRST_CODE&error=SECOND_CODE&error_description=".into(),
                "FIRST_CODE",
                None,
            ),
            (
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("error", "<script>alert(1)</script>")
                    .append_pair("error_description", description)
                    .finish(),
                "UNKNOWN",
                Some(description),
            ),
        ] {
            for forward in [false, true] {
                app.events.lock().unwrap().clear();
                let actual = AuthRequest::new(HttpMethod::Post, "/unrelated-actual-request")
                    .with_url(url::Url::parse(&format!(
                        "http://actual.test/unrelated?{query}"
                    ))?);
                let output = auth
                    .dispatch_endpoint(
                        endpoint()?
                            .with_body(&json!({"url":"https://forged.test/?error=FORGED_BODY"}))?,
                        EndpointOptions {
                            request: Some(actual),
                            headers: Some(
                                [("authorization".into(), "Bearer invalid.signature".into())]
                                    .into_iter()
                                    .collect(),
                            ),
                            ..Default::default()
                        },
                    )
                    .await?;
                assert!(output.status().is_none());
                assert!(output.http_response().is_some());
                assert_eq!(
                    output.headers().get("x-after").map(String::as_str),
                    Some("actual")
                );
                assert_eq!(output.headers().get_all("set-cookie").count(), 2);
                let returned = if forward {
                    output.into_response()?
                } else {
                    output.http_response().unwrap().clone()
                };
                assert!(!returned.headers.contains_key("x-before"));
                assert!(!returned.headers.contains_key("authorization"));
                assert_eq!(returned.headers.contains_key("x-after"), forward);
                assert_eq!(
                    returned.headers.get_all("set-cookie").count(),
                    if forward { 2 } else { 0 }
                );
                let events = app.events.lock().unwrap().clone();
                assert_eq!(events.len(), 2);
                assert_eq!(events[1]["sessionUserId"], Value::Null);
                assert_eq!(events[1]["returned"]["kind"], "http-response");
                if profile == "html" {
                    assert_eq!(returned.status, 200);
                    assert_eq!(
                        returned.headers.get("content-type").map(String::as_str),
                        Some("text/html")
                    );
                    let html = String::from_utf8(returned.body)?;
                    assert!(html.contains("<!DOCTYPE html>") && html.contains(code));
                    assert!(!html.contains("FORGED_LOGICAL") && !html.contains("SECOND_CODE"));
                    if detail.is_some() {
                        assert!(html.contains(
                            "&lt;b&gt;space + &amp; café&lt;/b&gt; &lt; &#65; &quot;quoted&quot;"
                        ));
                    }
                } else {
                    assert_eq!(returned.status, 302);
                    assert!(returned.body.is_empty());
                    assert!(!returned.headers.contains_key("content-type"));
                    let mut params = url::form_urlencoded::Serializer::new(String::new());
                    _ = params.append_pair("error", code);
                    if let Some(detail) = detail {
                        _ = params.append_pair("error_description", detail);
                    }
                    assert_eq!(
                        returned.headers.get("location").unwrap(),
                        &if profile == "configured" {
                            format!("/problem?keep=a%2Bb&{}#error-panel", params.finish())
                        } else {
                            format!("/?{}", params.finish())
                        }
                    );
                }
            }
        }
        for mode in ["normal", "patch-query", "mutate-response", "replace-json"] {
            *app.mode.lock().unwrap() = mode.into();
            app.events.lock().unwrap().clear();
            let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/error").with_url(
                url::Url::parse("http://logical-error.test/api/auth/error?error=ACTUAL_CODE")?,
            );
            request.set_query_pairs([("error", "ACTUAL_CODE")]);
            let response = auth.handle_request(request).await?;
            let events = app.events.lock().unwrap().clone();
            assert_eq!(events.len(), 2);
            assert_eq!(events[1]["returned"]["kind"], "http-response");
            assert_eq!(
                events[1]["returned"]["status"],
                if profile == "html" { 200 } else { 302 }
            );
            assert!(!response.headers.contains_key("x-before"));
            assert!(!response.headers.contains_key("authorization"));
            assert_eq!(
                response.headers.get("x-after").map(String::as_str),
                Some("actual")
            );
            if mode == "replace-json" {
                assert_eq!(response.status, 200);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body)?,
                    json!({"replacement":true})
                );
                assert!(!response.headers.contains_key("location"));
            } else if profile != "html" {
                assert_eq!(response.status, 302);
                assert_eq!(
                    response.headers.get("location").map(String::as_str),
                    Some(if profile == "configured" {
                        "/problem?keep=a%2Bb&error=ACTUAL_CODE#error-panel"
                    } else {
                        "/?error=ACTUAL_CODE"
                    })
                );
            }
            let mut expected = vec![
                "application_a=first; Path=/; HttpOnly",
                "application_b=second; Path=/; HttpOnly",
            ];
            if mode == "mutate-response" {
                drop(expected.splice(0..0, ["raw_a=one; Path=/", "raw_b=two; Path=/"]));
            }
            assert_eq!(
                response
                    .headers
                    .get_all("set-cookie")
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        if profile == "default" {
            for mode in [
                "patch-query",
                "mutate-response",
                "replace-json",
                "before-return",
            ] {
                for forward in [false, true] {
                    *app.mode.lock().unwrap() = mode.into();
                    app.events.lock().unwrap().clear();
                    let request = (mode != "before-return").then(|| {
                        AuthRequest::new(HttpMethod::Post, "/actual").with_url(
                            url::Url::parse("http://actual.test/any?error=ACTUAL_CODE").unwrap(),
                        )
                    });
                    let output = auth
                        .dispatch_endpoint(
                            endpoint()?,
                            EndpointOptions {
                                request,
                                ..Default::default()
                            },
                        )
                        .await?;
                    if mode == "replace-json" {
                        assert!(output.http_response().is_none());
                        assert_eq!(
                            serde_json::to_value(output.value())?,
                            json!({"replacement":true})
                        );
                        if forward {
                            let response = output.into_response()?;
                            assert_eq!(response.status, 200);
                            assert_eq!(
                                serde_json::from_slice::<Value>(&response.body)?,
                                json!({"replacement":true})
                            );
                        }
                    } else {
                        let response = if forward {
                            output.into_response()?
                        } else {
                            output.http_response().unwrap().clone()
                        };
                        if mode == "before-return" {
                            assert_eq!(response.status, 209);
                            assert_eq!(response.body, b"application early");
                            assert_eq!(response.headers.contains_key("x-before"), forward);
                            assert_eq!(app.events.lock().unwrap().len(), 1);
                        } else {
                            assert_eq!(
                                response.headers.get("location").map(String::as_str),
                                Some("/?error=ACTUAL_CODE")
                            );
                            if mode == "mutate-response" {
                                assert_eq!(
                                    response
                                        .headers
                                        .get("x-response-mutated")
                                        .map(String::as_str),
                                    Some("actual")
                                );
                                assert_eq!(
                                    response.headers.get_all("set-cookie").count(),
                                    if forward { 4 } else { 2 }
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
