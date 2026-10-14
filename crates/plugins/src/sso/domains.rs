//! Provider domain normalization for SSO authorization selection.
// Better Auth uses tldts hostname extraction rather than strict URL admission.
pub(super) fn matches(search: &str, domain_list: &str) -> bool {
    let search = search.trim().to_lowercase();
    if search.is_empty() {
        return false;
    }
    let mut matched = false;
    for entry in domain_list
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some(domain) = hostname(entry) else {
            return false;
        };
        matched |= search == domain || search.ends_with(&format!(".{domain}"));
    }
    matched
}

fn hostname(entry: &str) -> Option<String> {
    let cleaned: String = entry
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut input = cleaned.trim_matches(|c: char| c <= ' ');
    if input.starts_with("data:") {
        return None;
    }
    let mut special = false;
    if let Some(rest) = input.strip_prefix("//") {
        input = rest;
    } else if let Some((scheme, rest)) = input.split_once(":/") {
        let scheme = scheme.to_ascii_lowercase();
        special = matches!(
            scheme.as_str(),
            "http" | "https" | "ftp" | "ws" | "wss" | "file"
        );
        if scheme == "file" {
            input = rest.strip_prefix('/')?;
        } else if special {
            input = rest.trim_start_matches(['/', '\\']);
        } else {
            if scheme.is_empty()
                || !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            {
                return None;
            }
            input = rest.strip_prefix('/')?;
        }
    } else if !input.starts_with('[') {
        let authority = input.split(['/', '\\', '?', '#']).next()?;
        if let Some((scheme, rest)) = authority.split_once(':')
            && !authority.contains('@')
            && !rest.contains(':')
            && (rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()))
        {
            let scheme = scheme.to_ascii_lowercase();
            if !matches!(
                scheme.as_str(),
                "http" | "https" | "ftp" | "ws" | "wss" | "file"
            ) {
                return None;
            }
            special = true;
            input = input.split_once(':')?.1;
            input = if scheme == "file" {
                input
                    .strip_prefix("//")
                    .or_else(|| input.strip_prefix("\\\\"))?
            } else {
                input.trim_start_matches(['/', '\\'])
            };
        }
    }
    let authority = input
        .split(|c| matches!(c, '/' | '?' | '#') || (special && c == '\\'))
        .next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']')?.0
    } else if host.matches(':').count() == 1 {
        host.split_once(':')?.0
    } else {
        host
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host);
    }
    if host.is_empty() || host.encode_utf16().count() > 255 {
        return None;
    }
    for (index, label) in host.split('.').enumerate() {
        if (label.is_empty() && index != 0)
            || label.encode_utf16().count() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_') || !c.is_ascii())
        {
            return None;
        }
    }
    Some(host)
}

/// Canonical social identities must contain exactly one usable email domain.
pub(super) fn email_domain(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let mut parts = email.split('@');
    if parts.next()?.is_empty() {
        return None;
    }
    let domain = parts.next()?;
    if parts.next().is_some() || domain.contains(['/', '\\', ':']) {
        return None;
    }
    let mut domains = domain
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty());
    let domain = domains.next()?;
    if domains.next().is_some() {
        return None;
    }
    hostname(domain)
}
