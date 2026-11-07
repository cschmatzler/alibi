use super::{AuthError, AuthRequest, AuthResult};

pub(in crate::runtime) async fn parse_dispatch_body(
    req: &AuthRequest,
    allowed: &[&str],
) -> AuthResult<()> {
    let Some(body) = &req.body else {
        return Ok(());
    };
    let content_type = req
        .headers
        .iter()
        .find_map(|(key, value)| {
            key.eq_ignore_ascii_case("content-type")
                .then_some(value.as_str())
        })
        .unwrap_or("");
    let lower = content_type.to_ascii_lowercase();
    let base = lower.split(';').next().unwrap_or("").trim();
    if !allowed.is_empty()
        && !allowed
            .iter()
            .any(|allowed| base == allowed.to_ascii_lowercase().trim())
    {
        let message = if content_type.is_empty() {
            format!(
                "Content-Type is required. Allowed types: {}",
                allowed.join(", ")
            )
        } else {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: {}",
                allowed.join(", ")
            )
        };
        return Err(AuthError::Api {
            status: 415,
            code: Some("UNSUPPORTED_MEDIA_TYPE".into()),
            message,
        });
    }
    let string_form_values = lower.contains("application/x-www-form-urlencoded");
    let json_media = lower.strip_prefix("application/").is_some_and(|suffix| {
        suffix.starts_with("json")
            || suffix.match_indices("+json").any(|(index, _)| {
                suffix[..index].bytes().all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, b'.' | b'+' | b'-')
                })
            })
    });
    let parsed = if json_media {
        // Fetch decodes JSON as UTF-8, replacing malformed sequences and removing
        // only an initial BOM before applying the JSON grammar.
        let text = String::from_utf8_lossy(body);
        Some(
            alibi_core::utils::json::parse_value(text.strip_prefix('\u{feff}').unwrap_or(&text))
                .map_err(|_| AuthError::Upstream {
                    status: 400,
                    code: "BAD_REQUEST",
                    message: "Invalid JSON in request body",
                })?,
        )
    } else if base == "application/x-www-form-urlencoded" {
        Some(alibi_core::utils::json::JsValue::Object(
            url::form_urlencoded::parse(body)
                .filter(|(key, _)| key != "__proto__")
                .map(|(key, value)| {
                    (
                        key.into_owned().into(),
                        alibi_core::utils::json::JsValue::String(value.into_owned().into()),
                    )
                })
                .collect(),
        ))
    } else if string_form_values || lower.contains("multipart/form-data") {
        let boundary = multer::parse_boundary(content_type).map_err(|error| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
        })?;
        let mut multipart = multer::Multipart::with_reader(body.as_slice(), boundary);
        let mut fields = empty_object();
        let mut files = alibi_core::types::MultipartFiles::default();
        while let Some(field) = multipart.next_field().await.map_err(|error| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
        })? {
            let Some(name) = field.name().map(str::to_owned) else {
                continue;
            };
            let filename = field.file_name().map(str::to_owned);
            // File.type normalizes the raw header, not a parsed MIME value.
            let content_type = field.headers().get("content-type").map_or_else(
                || "text/plain".to_owned(),
                |header| {
                    let value = header.to_str().unwrap_or("").trim_matches([' ', '\t']);
                    if value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
                        value.to_ascii_lowercase()
                    } else {
                        String::new()
                    }
                },
            );
            let base64 = field
                .headers()
                .get("content-transfer-encoding")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.trim_matches([' ', '\t']) == "base64");
            let bytes = field.bytes().await.map_err(|error| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
            })?;
            let bytes = if base64 {
                decode_multipart_base64(&bytes)
            } else {
                bytes.to_vec()
            };
            let value = if string_form_values && filename.is_some() {
                alibi_core::utils::json::JsValue::String("[object File]".into())
            } else if let Some(filename) = filename {
                _ = files.0.insert(
                    name.clone(),
                    alibi_core::types::MultipartFile {
                        filename,
                        content_type: Some(content_type),
                        bytes,
                    },
                );
                empty_object()
            } else {
                _ = files.0.remove(&name);
                alibi_core::utils::json::JsValue::String(
                    String::from_utf8_lossy(&bytes).into_owned().into(),
                )
            };
            if name != "__proto__"
                && let alibi_core::utils::json::JsValue::Object(object) = &mut fields
            {
                _ = object.insert(name.into(), value);
            }
        }
        req.extensions().insert(files);
        Some(fields)
    } else {
        None
    };
    let decoded = if let Some(parsed) = parsed {
        alibi_core::types::ParsedRequestBody::Value(parsed)
    } else if lower.contains("text/plain") {
        let text = String::from_utf8_lossy(body);
        alibi_core::types::ParsedRequestBody::Value(alibi_core::utils::json::JsValue::String(
            text.strip_prefix('\u{feff}').unwrap_or(&text).into(),
        ))
    } else {
        let kind = if lower.contains("application/octet-stream") {
            "ArrayBuffer"
        } else if lower.contains("application/pdf")
            || lower.contains("image/")
            || lower.contains("video/")
        {
            "Blob"
        } else {
            "ReadableStream"
        };
        alibi_core::types::ParsedRequestBody::Opaque(kind)
    };
    req.extensions().insert(decoded);
    Ok(())
}

/// Fetch's multipart parser uses Buffer.from(body.toString(), "base64"),
/// including its forgiving alphabet, padding and low-byte UTF-16 behavior.
fn decode_multipart_base64(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let mut decoded = Vec::new();
    let mut buffer = 0_u16;
    let mut bits = 0;
    for unit in text.encode_utf16() {
        let byte = (unit & 0xff) as u8;
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        buffer = (buffer << 6) | u16::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    decoded
}

#[expect(
    clippy::default_trait_access,
    reason = "the `IndexMap` type is not a direct dependency of this crate"
)]
fn empty_object() -> alibi_core::utils::json::JsValue {
    alibi_core::utils::json::JsValue::Object(Default::default())
}

#[cfg(test)]
mod canonical_tests {
    use super::parse_dispatch_body;
    use alibi_core::utils::json;
    use alibi_core::{AuthRequest, HttpMethod};

    #[tokio::test]
    async fn canonical_body_decoding_matches_actual_better_call() {
        let fixture = json::parse_value(include_str!("body_canonical_cases.json")).unwrap();
        assert_eq!(fixture["better_auth"], "1.7.18");
        assert_eq!(fixture["better_call"], "1.4.5");
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 31);
        for case in cases {
            let mode = case["mode"].as_str().unwrap();
            let content_type = case["content_type"].as_str().unwrap();
            let bytes: Vec<u8> = case["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| u8::try_from(value.as_u64().unwrap()).unwrap())
                .collect();
            let mut request = AuthRequest::new(HttpMethod::Post, "/body");
            request
                .headers
                .insert("content-type".into(), content_type.into());
            request.body = Some(bytes.clone());
            parse_dispatch_body(&request, &[])
                .await
                .unwrap_or_else(|error| panic!("{mode}: {error}"));
            let parsed = request
                .extensions()
                .get::<alibi_core::types::ParsedRequestBody>()
                .unwrap();
            let alibi_core::types::ParsedRequestBody::Value(value) = parsed.as_ref() else {
                panic!("{mode}: expected a parsed canonical value");
            };
            assert_eq!(value, &case["expected"], "{mode}");
            assert_eq!(
                json::to_string(value).unwrap(),
                case["wire"].as_str().unwrap(),
                "{mode}"
            );
            assert_eq!(request.body, Some(bytes), "{mode}: mutated source bytes");
            let files = request
                .extensions()
                .get::<alibi_core::types::MultipartFiles>();
            let expected_files = case["files"].as_object().unwrap();
            assert_eq!(
                files.as_ref().map_or(0, |files| files.0.len()),
                expected_files.len(),
                "{mode}"
            );
            for (name, expected) in expected_files {
                let actual = &files.as_ref().unwrap().0[name.require_str().unwrap()];
                assert_eq!(
                    actual.filename,
                    expected["filename"].as_str().unwrap(),
                    "{mode}"
                );
                assert_eq!(
                    actual.content_type.as_deref(),
                    expected["content_type"].as_str(),
                    "{mode}"
                );
                assert_eq!(
                    actual.bytes,
                    expected["bytes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| u8::try_from(value.as_u64().unwrap()).unwrap())
                        .collect::<Vec<_>>(),
                    "{mode}"
                );
            }
        }
    }
}
