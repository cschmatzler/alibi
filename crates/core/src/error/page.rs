//! Built-in error page rendering and redirects.

fn safe_error_code(input: &str) -> &str {
    if !input.is_empty()
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '\'')
    {
        input
    } else {
        "UNKNOWN"
    }
}

fn is_preserved_entity(input: &str) -> bool {
    input.starts_with("amp;")
        || input.starts_with("lt;")
        || input.starts_with("gt;")
        || input.starts_with("quot;")
        || input.starts_with("#39;")
        || input
            .strip_prefix("#x")
            .and_then(|rest| rest.split_once(';'))
            .is_some_and(|(hex, _)| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
        || input
            .strip_prefix('#')
            .and_then(|rest| rest.split_once(';'))
            .is_some_and(|(digits, _)| {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            })
}

fn sanitize_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());

    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '&' => {
                let rest = input.get(idx + ch.len_utf8()..).unwrap_or_default();
                if is_preserved_entity(rest) {
                    out.push('&');
                } else {
                    out.push_str("&amp;");
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn default_error_description(code: &str) -> String {
    format!(
        "We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find <a href='https://better-auth.com/docs/reference/errors/{code}' target='_blank' rel=\"noopener noreferrer\" style='color: var(--foreground); text-decoration: underline;'>more information about the error</a>."
    )
}

/// Build the HTML error page returned by `GET /error`.
///
/// Matches the current TS better-auth error page renderer.
#[must_use]
pub fn error_page_html(error_code: &str) -> String {
    error_page_html_with_description(error_code, None)
}

/// Build the HTML error page returned by `GET /error`, optionally
/// overriding the default description text.
pub fn error_page_html_with_description(
    error_code: &str,
    error_description: Option<&str>,
) -> String {
    let safe_code = safe_error_code(error_code);
    let description =
        error_description.map_or_else(|| default_error_description(safe_code), sanitize_html);
    let ask_ai_query = format!("What%20does%20the%20error%20code%20{safe_code}%20mean%3F");

    format!(
        include_str!("page.html"),
        safe_code = safe_code,
        description = description,
        ask_ai_query = ask_ai_query,
    )
}

/// Build the production error redirect with sanitized code and encoded description.
#[must_use]
pub fn error_page_redirect_location(error_code: &str, error_description: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    _ = query.append_pair("error", safe_error_code(error_code));
    if let Some(description) = error_description.filter(|value| !value.is_empty()) {
        _ = query.append_pair("error_description", description);
    }
    format!("/?{}", query.finish())
}
