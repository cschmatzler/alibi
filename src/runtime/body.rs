use super::{AuthError, AuthPlugin, AuthRequest, AuthResult, Middleware};

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
            .any(|allowed| base.contains(allowed.to_ascii_lowercase().trim()))
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
        Some(
            alibi_core::utils::json::from_slice::<alibi_core::utils::json::JsValue>(body).map_err(
                |_| AuthError::Upstream {
                    status: 400,
                    code: "BAD_REQUEST",
                    message: "Invalid JSON in request body",
                },
            )?,
        )
    } else if lower.contains("application/x-www-form-urlencoded") {
        Some(alibi_core::utils::json::JsValue::Object(
            url::form_urlencoded::parse(body)
                .map(|(key, value)| {
                    (
                        key.into_owned(),
                        alibi_core::utils::json::JsValue::String(value.into_owned()),
                    )
                })
                .collect(),
        ))
    } else if lower.contains("multipart/form-data") {
        // Fetch parses form-data even when additional media text follows its subtype.
        // Keep the original header; normalize only the parser's MIME prefix.
        let parameters = content_type.split_once(';').map_or("", |(_, value)| value);
        let boundary = multer::parse_boundary(format!("multipart/form-data;{parameters}"))
            .map_err(|error| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
            })?;
        let mut multipart = multer::Multipart::with_reader(body.as_slice(), boundary);
        let mut fields = alibi_core::utils::json::JsValue::Object(Default::default());
        let mut files = alibi_core::types::MultipartFiles::default();
        while let Some(field) = multipart.next_field().await.map_err(|error| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
        })? {
            let Some(name) = field.name().map(str::to_owned) else {
                continue;
            };
            let filename = field.file_name().map(str::to_owned);
            let content_type = field.content_type().map(ToString::to_string);
            let bytes = field.bytes().await.map_err(|error| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
            })?;
            let value = if let Some(filename) = filename {
                drop(files.0.insert(
                    name.clone(),
                    alibi_core::types::MultipartFile {
                        filename,
                        content_type,
                        bytes: bytes.to_vec(),
                    },
                ));
                alibi_core::utils::json::JsValue::Object(Default::default())
            } else {
                drop(files.0.remove(&name));
                alibi_core::utils::json::JsValue::String(
                    String::from_utf8_lossy(&bytes).into_owned(),
                )
            };
            if let alibi_core::utils::json::JsValue::Object(object) = &mut fields {
                drop(object.insert(name, value));
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
            text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned(),
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
