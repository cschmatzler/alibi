//! Cookie serialization, JavaScript date parsing and error-page helpers.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::AuthConfig;
use alibi::config::{
    AdvancedConfig, CookieAttributes, CookieOverride, CrossSubDomainConfig, OAuthStateStrategy,
    SameSite,
};
use alibi::error::page::{error_page_html_with_description, error_page_redirect_location};
use alibi::utils::cookie_utils::{
    create_account_cookie_header, create_cookie, create_cookie_with_max_age, create_session_cookie,
    delete_session_cookie_headers, related_cookie_name,
};
use alibi::utils::datetime::parse_date_millis;
use chrono::{Duration, Utc};
use std::collections::HashMap;

fn config() -> AuthConfig {
    AuthConfig::new("utilities-secret-at-least-32-characters").base_url("https://app.example.test")
}

fn with_advanced(advanced: impl FnOnce(&mut AdvancedConfig)) -> AuthConfig {
    let mut config = config();
    advanced(&mut config.advanced);
    config
}

#[test]
fn cookie_attribute_order_and_flags() {
    let config = with_advanced(|advanced| {
        advanced.default_cookie_attributes = CookieAttributes {
            partitioned: Some(true),
            same_site: Some(SameSite::None),
            ..CookieAttributes::default()
        };
    });
    let cookie = create_cookie("custom", "value", 60, &config).unwrap();
    assert_eq!(
        cookie,
        "custom=value; Max-Age=60; Path=/; HttpOnly; Secure; SameSite=None; Partitioned"
    );

    let strict = with_advanced(|advanced| {
        advanced.default_cookie_attributes.same_site = Some(SameSite::Strict);
    });
    assert!(
        create_cookie("custom", "value", 60, &strict)
            .unwrap()
            .ends_with("; SameSite=Strict")
    );
}

#[test]
fn default_attributes_override_every_field_and_cookie_entries_win() {
    let expires = Utc::now() + Duration::days(1);
    let mut config = with_advanced(|advanced| {
        advanced.default_cookie_attributes = CookieAttributes {
            secure: Some(false),
            http_only: Some(false),
            same_site: Some(SameSite::Strict),
            path: Some("/auth".into()),
            domain: Some("default.example.test".into()),
            expires: Some(expires),
            partitioned: Some(true),
            max_age: Some(5.0),
        };
    });
    let cookie = create_cookie_with_max_age("plain", "v", None, &config).unwrap();
    assert!(
        cookie.starts_with("plain=v; Max-Age=5; Domain=default.example.test; Path=/auth; Expires=")
    );
    assert!(cookie.ends_with("; SameSite=Strict; Partitioned"));
    assert!(!cookie.contains("HttpOnly") && !cookie.contains("Secure"));

    drop(config.advanced.cookies.insert(
        "plain".into(),
        CookieOverride {
            name: None,
            attributes: CookieAttributes {
                max_age: Some(9.0),
                domain: Some("entry.example.test".into()),
                ..CookieAttributes::default()
            },
        },
    ));
    let overridden = create_cookie_with_max_age(
        &related_cookie_name(&config, "plain"),
        "v",
        Some(30.0),
        &config,
    )
    .unwrap();
    assert!(overridden.contains("Max-Age=9;"), "{overridden}");
    assert!(overridden.contains("Domain=entry.example.test"));
}

#[test]
fn cross_subdomain_domain_is_explicit_or_inferred_from_base_url() {
    let explicit = with_advanced(|advanced| {
        advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
            domain: ".example.test".into(),
        });
    });
    assert!(
        create_cookie("c", "v", 1, &explicit)
            .unwrap()
            .contains("; Domain=.example.test;")
    );

    let inferred = config().cross_sub_domain_cookies_from_base_url();
    assert!(
        create_cookie("c", "v", 1, &inferred)
            .unwrap()
            .contains("; Domain=app.example.test;")
    );
}

#[test]
fn host_prefixed_cookies_ignore_domain_and_path_overrides() {
    let config = with_advanced(|advanced| {
        advanced.default_cookie_attributes.domain = Some("example.test".into());
        advanced.default_cookie_attributes.path = Some("/x".into());
    });
    assert_eq!(
        create_cookie("__Host-token", "v", 1, &config).unwrap(),
        "__Host-token=v; Max-Age=1; Path=/; HttpOnly; Secure; SameSite=Lax"
    );
}

#[test]
fn serializer_rejects_excessive_max_age_and_expires() {
    let config = config();
    let error = create_cookie("c", "v", 34_560_001, &config).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Max-Age SHOULD NOT be greater than 400 days")
    );
    assert!(create_cookie("c", "v", 34_560_000, &config).is_ok());

    let too_far = with_advanced(|advanced| {
        advanced.default_cookie_attributes.expires = Some(Utc::now() + Duration::days(401));
    });
    let error = create_cookie_with_max_age("c", "v", None, &too_far).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Expires SHOULD NOT be greater than 400 days")
    );
}

#[test]
fn account_cookie_headers_use_numeric_age() {
    let config = config();
    assert_eq!(
        create_account_cookie_header(
            "better-auth.account_data.0",
            "better-auth.account_data",
            "chunk",
            600.9,
            &config,
        )
        .unwrap(),
        "better-auth.account_data.0=chunk; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax"
    );
}

#[test]
fn clear_headers_cover_account_and_oauth_state_cookies() {
    let mut config = config();
    config.account.store_account_cookie = true;
    config.account.store_state_strategy = OAuthStateStrategy::Cookie;
    let cleared = delete_session_cookie_headers(&config).unwrap();
    let names: Vec<_> = cleared
        .iter()
        .map(|header| header.split('=').next().unwrap().to_owned())
        .collect();
    let expected: Vec<_> = [
        "session_token",
        "session_data",
        "account_data",
        "oauth_state",
        "dont_remember",
    ]
    .iter()
    .map(|suffix| related_cookie_name(&config, suffix))
    .collect();
    assert_eq!(names, expected);
    assert!(cleared.iter().all(|header| header.contains("Max-Age=0")));
    assert!(
        create_session_cookie("token", &config)
            .unwrap()
            .starts_with("__Secure-better-auth.session_token=token.")
    );
}

#[test]
fn date_parse_iso_forms() {
    let cases: HashMap<&str, Option<i64>> = HashMap::from([
        ("2024-03-01", Some(1_709_251_200_000)),
        ("2024-03-01T10:20:30Z", Some(1_709_288_430_000)),
        ("2024-03-01t10:20:30.123456z", Some(1_709_288_430_123)),
        ("2024-03-01 10:20:30+02:00", Some(1_709_281_230_000)),
        ("2024-03-01T10:20:30-0130", Some(1_709_293_830_000)),
        ("2024-03-01T24:00:00Z", Some(1_709_337_600_000)),
        ("+002024-03-01T00:00:00Z", Some(1_709_251_200_000)),
        ("-000001-01-01T00:00:00Z", Some(-62_198_755_200_000)),
        ("+275760-09-13T00:00:00Z", Some(8_640_000_000_000_000)),
        ("+275760-09-13T00:00:00.001Z", None),
        ("-000000-01-01T00:00:00Z", None),
        ("2024-03-01T24:00:01Z", None),
        ("2024-03-01T10:20:30+24:00", None),
        ("2024-03-01T10:20:30+02:60", None),
        ("2024-03-01T10:20:30+02:00junk", None),
        ("2024-03-01T10:20:30*02:00", None),
        ("2024-03-01T10:20:30.Z", None),
        ("2024-03-01X10:20:30Z", None),
        ("2024-13-01", None),
        ("2024-03-32", None),
    ]);
    for (input, expected) in cases {
        assert_eq!(parse_date_millis(input), expected, "{input}");
    }
}

#[test]
fn date_parse_local_time_forms_agree_with_each_other() {
    let local = parse_date_millis("2024-03-01T10:20:30").unwrap();
    assert_eq!(parse_date_millis("Mar 1 2024 10:20:30"), Some(local));
    assert_eq!(parse_date_millis("1 March 2024 10:20:30"), Some(local));
    assert_eq!(parse_date_millis("03/01/2024 10:20:30"), Some(local));
    assert_eq!(parse_date_millis("2024/03/01 10:20:30"), Some(local));
    assert_eq!(parse_date_millis("Mar 1 2024 10:20:30 AM"), Some(local));
    assert_eq!(parse_date_millis("3/1/24"), parse_date_millis("Mar 1 2024"));
}

#[test]
fn date_parse_legacy_zones_and_two_digit_years() {
    assert_eq!(
        parse_date_millis("Fri, 01 Mar 2024 10:20:30 GMT"),
        Some(1_709_288_430_000)
    );
    assert_eq!(
        parse_date_millis("Mar 1 2024 10:20:30 PST"),
        Some(1_709_288_430_000 + 8 * 3_600_000)
    );
    assert_eq!(
        parse_date_millis("1 Mar 2024 10:20:30 GMT+0200"),
        Some(1_709_281_230_000)
    );
    assert_eq!(
        parse_date_millis("Fri Mar 01 2024 10:20:30 GMT+0000 (Coordinated Universal Time)"),
        Some(1_709_288_430_000)
    );
    assert_eq!(
        parse_date_millis("Mar 1 2024 10:20:30 UTC"),
        Some(1_709_288_430_000)
    );
    assert_eq!(parse_date_millis("Mar 1 2024 (unbalanced"), None);
    assert_eq!(parse_date_millis("Mar 1 2024) 10:20"), None);

    let early = parse_date_millis("1/2/05").unwrap();
    let late = parse_date_millis("1/2/95").unwrap();
    assert_eq!(early, parse_date_millis("1/2/2005").unwrap());
    assert_eq!(late, parse_date_millis("1/2/1995").unwrap());
}

#[test]
fn date_parse_bare_numbers_follow_javascript_month_and_year_rules() {
    assert_eq!(parse_date_millis("0"), Some(946_684_800_000));
    assert_eq!(parse_date_millis("12"), Some(1_007_164_800_000));
    assert_eq!(parse_date_millis("13"), None);
    assert_eq!(parse_date_millis("40"), Some(2_208_988_800_000));
    assert_eq!(parse_date_millis("75"), Some(157_766_400_000));
    assert_eq!(parse_date_millis("2000000"), None);
    assert_eq!(parse_date_millis(""), None);
}

#[test]
fn error_page_escapes_html_but_preserves_entities() {
    let html = error_page_html_with_description(
        "BAD_CODE",
        Some("a &#x41; b &#65; c &#xZZ; d &#; e &amp; <b>\"'</b> &unknown; & &#x41"),
    );
    assert!(html.contains("a &#x41; b &#65; c &amp;#xZZ; d &amp;#; e &amp; &lt;b&gt;&quot;&#39;&lt;/b&gt; &amp;unknown; &amp; &amp;#x41"));
}

#[test]
fn error_redirect_location_encodes_code_and_description() {
    let location = error_page_redirect_location("invalid code!", Some("why not"));
    assert!(location.starts_with("/?error=UNKNOWN"), "{location}");
    assert!(location.contains("error_description="), "{location}");
}

#[test]
fn origin_checks_can_be_skipped_for_literal_paths_and_their_descendants() {
    let config = with_advanced(|advanced| {
        advanced.disable_origin_check_paths = vec!["/skip/".into(), "/exact".into()];
    });
    for (path, skipped) in [
        ("/api/auth/skip", true),
        ("/api/auth/skip/deep/", true),
        ("/api/auth/exact", true),
        ("/skip/direct", true),
        ("/api/auth/skipped", false),
        ("/api/auth/exact-not", false),
        ("/api/auth/other", false),
    ] {
        assert_eq!(config.origin_check_disabled_for(path), skipped, "{path}");
    }
}

#[test]
fn error_url_builder_stores_the_target() {
    assert_eq!(
        config().api_error_url("/oops").api_error_url.as_deref(),
        Some("/oops")
    );
}

#[test]
fn database_id_strategies_generate_reject_or_defer() {
    use alibi::AuthError;
    use alibi::config::{AdvancedDatabaseConfig, DatabaseIdStrategy};
    use std::sync::Arc;

    let with = |strategy: Option<DatabaseIdStrategy>| AdvancedDatabaseConfig {
        generate_id: strategy,
        ..Default::default()
    };
    let uuid = with(Some(DatabaseIdStrategy::Uuid))
        .generated_id("user")
        .unwrap();
    assert_eq!(uuid.unwrap().len(), 36);
    assert_eq!(with(None).generated_id("user").unwrap(), None);
    assert_eq!(
        with(Some(DatabaseIdStrategy::Serial))
            .generated_id("user")
            .unwrap(),
        None
    );

    let custom = |reply: fn(&str) -> Result<Option<String>, AuthError>| {
        with(Some(DatabaseIdStrategy::Custom(Arc::new(
            move |model: &str, size: Option<usize>| {
                assert_eq!(size, None);
                reply(model)
            },
        ))))
    };
    assert_eq!(
        custom(|model| Ok(Some(format!("{model}_1"))))
            .generated_id("session")
            .unwrap()
            .as_deref(),
        Some("session_1")
    );
    assert!(matches!(
        custom(|_| Ok(None)).generated_id("user").unwrap_err(),
        AuthError::CallbackFailure(_)
    ));
    assert!(matches!(
        custom(|_| Err(AuthError::internal("boom")))
            .generated_id("user")
            .unwrap_err(),
        AuthError::CallbackFailure(_)
    ));
    assert!(matches!(
        custom(|_| Err(AuthError::forbidden("no")))
            .generated_id("user")
            .unwrap_err(),
        AuthError::Forbidden(_) | AuthError::Api { .. }
    ));
}

#[test]
fn api_key_start_text_is_wtf8_only_for_unpaired_surrogates() {
    use alibi::{ApiKeyStartText, ApiKeyStartingCharacters};

    let plain = ApiKeyStartingCharacters::from_utf16("ab".encode_utf16().collect());
    assert!(matches!(plain.storage_text(), ApiKeyStartText::Utf8(text) if text == "ab"));
    let broken = ApiKeyStartingCharacters::from_utf16(vec![0x61, 0xd800, 0x62, 0xdc01]);
    assert_eq!(broken.as_utf16().len(), 4);
    assert!(matches!(
        broken.storage_text(),
        ApiKeyStartText::Wtf8(bytes)
            if bytes == [0x61, 0xed, 0xa0, 0x80, 0x62, 0xed, 0xb0, 0x81]
    ));
}

#[test]
fn client_ip_resolution_handles_mapped_ipv4_prefixes_and_proxy_networks() {
    use alibi::config::IpAddressConfig;

    let resolve = |proxies: &[&str], subnet: f64, header: &str| {
        IpAddressConfig {
            headers: vec!["x-ip".into()],
            trusted_proxies: proxies.iter().map(|proxy| (*proxy).to_owned()).collect(),
            ipv6_subnet: subnet,
            localhost_fallback: false,
            ..Default::default()
        }
        .resolve_ip(&HashMap::from([("X-IP".to_owned(), header.to_owned())]))
    };
    assert_eq!(
        resolve(&[], 64.0, "::ffff:1.2.3.4").as_deref(),
        Some("1.2.3.4")
    );
    assert_eq!(
        resolve(&[], 64.0, "::ffff:102:304").as_deref(),
        Some("1.2.3.4")
    );
    assert_eq!(
        resolve(&[], 128.0, "2001:DB8::1").as_deref(),
        Some("2001:0db8:0000:0000:0000:0000:0000:0001")
    );
    assert_eq!(
        resolve(&[], f64::NAN, "2001:DB8::1").as_deref(),
        Some("2001:0db8:0000:0000:0000:0000:0000:0001")
    );
    assert_eq!(
        resolve(&[], 32.0, "2001:db8:abcd::1").as_deref(),
        Some("2001:0db8:0000:0000:0000:0000:0000:0000")
    );
    assert_eq!(
        resolve(&["10.0.0.0/8"], 64.0, "2001:db8::1, 10.0.0.1").as_deref(),
        Some("2001:0db8:0000:0000:0000:0000:0000:0000")
    );
    assert_eq!(
        resolve(&["10.0.0.1"], 64.0, "198.51.100.7, 10.0.0.1").as_deref(),
        Some("198.51.100.7")
    );
    for invalid in ["10.0.0.0/", "10.0.0.0/x", "10.0.0.0/33"] {
        assert_eq!(
            resolve(&[invalid], 64.0, "198.51.100.7, 10.0.0.1"),
            None,
            "{invalid}"
        );
    }
}

#[test]
fn chunked_cookie_reader_orders_chunks_and_skips_invalid_pairs() {
    use alibi::session::cookie_cache::runtime::chunked_cookie_value;

    let read = |cookie: &str, name: &str| {
        chunked_cookie_value(
            &HashMap::from([("cookie".to_owned(), cookie.to_owned())]),
            name,
        )
    };
    assert_eq!(
        read("n.1=b; n.0=a; n.10=c; bad name=1; n=\"", "n").as_deref(),
        Some("abc")
    );
    assert_eq!(read("n=\"whole\"; n.0=x", "n").as_deref(), Some("whole"));
    assert_eq!(read("n=; n.0=x", "n").as_deref(), Some("x"));
    assert_eq!(read("n.01=x; n.-1=y", "n"), None);
    assert_eq!(read("", "n"), None);
}

#[test]
fn session_cleanup_expires_incoming_account_and_cache_chunks() {
    use alibi::session::cookie_cache::runtime::session_cleanup_headers;

    let mut config = config().base_url("http://app.example.test");
    config.account.store_account_cookie = true;
    config.account.store_state_strategy = OAuthStateStrategy::Cookie;
    let account = related_cookie_name(&config, "account_data");
    let cache = related_cookie_name(&config, "session_data");
    let headers = HashMap::from([(
        "cookie".to_owned(),
        format!("{account}.0=a; {cache}.0=b; other=1"),
    )]);
    let names = |skip_remember: bool| -> Vec<String> {
        session_cleanup_headers(&config, &headers, skip_remember)
            .unwrap()
            .iter()
            .map(|header| header.split('=').next().unwrap().to_owned())
            .collect()
    };
    let remember = related_cookie_name(&config, "dont_remember");
    let cleared = names(false);
    for expected in [
        config.session.cookie_name.clone(),
        cache.clone(),
        account.clone(),
        format!("{account}.0"),
        related_cookie_name(&config, "oauth_state"),
        format!("{cache}.0"),
        remember.clone(),
    ] {
        assert!(cleared.contains(&expected), "{expected} in {cleared:?}");
    }
    assert!(!names(true).contains(&remember));
}

#[test]
fn json_dates_normalize_overflowing_midnight_and_reject_invalid_ones() {
    use alibi::utils::datetime::normalize_json_date;

    assert_eq!(
        normalize_json_date("9999-12-31T24:00:00.000Z").as_deref(),
        Some("+010000-01-01T00:00:00.000Z")
    );
    assert_eq!(normalize_json_date("2024-03-01T24:00:01.000Z"), None);
    assert_eq!(normalize_json_date("2024-03-01T24:00:00.001Z"), None);
    assert_eq!(
        normalize_json_date("2024-03-01T10:20:30Z").as_deref(),
        Some("2024-03-01T10:20:30.000Z")
    );
    assert_eq!(normalize_json_date("2024-03-01T10:20:30.Z"), None);
}

#[test]
fn javascript_values_coerce_like_primitives_and_parsers_reject_truncation() {
    use alibi::utils::json::{JsValue, parse_value};

    let object = parse_value(r#"{"toString":1}"#).unwrap();
    assert_eq!(
        object.coerce_string().unwrap_err(),
        "Cannot convert object to primitive value"
    );
    assert_eq!(
        parse_value("[1,[2]]").unwrap().coerce_string().unwrap(),
        "1,2"
    );
    assert_eq!(JsValue::Null.as_str(), None);
    assert_eq!(JsValue::Null.as_bool(), None);
    assert_eq!(JsValue::Null.get("x"), None);
    assert!(parse_value("\"unterminated").is_err());
    assert!(parse_value("{\"a\":\"b").is_err());
}
