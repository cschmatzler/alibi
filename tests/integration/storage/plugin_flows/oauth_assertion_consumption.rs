//! Public assertion hygiene is usable by independently verified authentication strategies.
use super::*;
use alibi::plugins::oauth_provider::consume_client_assertion;
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use alibi::utils::json::JsValue;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(oauth_public_assertion_consumption_checks_claims_and_namespaces_durable_replay);
postgres_tests!(oauth_public_assertion_consumption_checks_claims_and_namespaces_durable_replay);
async fn oauth_public_assertion_consumption_checks_claims_and_namespaces_durable_replay<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let other = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let cfg = OAuthProviderConfig::default();
    let audience = "https://resource.fixture.test/token";
    let now = chrono::Utc::now().timestamp();
    for (name, field, value, detail) in [
        (
            "audience",
            "aud",
            Some(json!("other")),
            Some("client assertion aud does not match the endpoint"),
        ),
        (
            "missing-exp",
            "exp",
            None,
            Some("client assertion must include exp claim"),
        ),
        (
            "expired",
            "exp",
            Some(json!(now - 60)),
            Some("client assertion has expired"),
        ),
        (
            "long-exp",
            "exp",
            Some(json!(now + 600)),
            Some("client assertion exp is too far in the future (max 300s)"),
        ),
        (
            "old-iat",
            "iat",
            Some(json!(now - 600)),
            Some("client assertion iat is too far in the past (max 300s)"),
        ),
        (
            "missing-jti",
            "jti",
            None,
            Some("client assertion must include jti claim"),
        ),
        (
            "empty-jti",
            "jti",
            Some(json!("")),
            Some("client assertion must include jti claim"),
        ),
        ("ignored-iat-type", "iat", Some(json!("old")), None),
        ("future-iat", "iat", Some(json!(now + 600)), None),
        (
            "mixed-audiences",
            "aud",
            Some(json!([false, audience])),
            None,
        ),
        ("whitespace-jti", "jti", Some(json!(" \t ")), None),
    ] {
        let namespace = format!("extension:{name}");
        let original = json!({"aud":audience,"exp":now+90,"iat":now,"jti":"proof"});
        let mut payload = original.clone();
        if let Some(value) = value {
            payload[field] = value;
        } else {
            _ = payload.as_object_mut().unwrap().remove(field);
        }
        let before = db
            .tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let result = consume_client_assertion(
            auth.context(),
            &cfg,
            &namespace,
            &JsValue::from(payload),
            audience,
        )
        .await;
        if let Some(detail) = detail {
            let error = result.unwrap_err();
            assert_eq!(error.error.status_code(), 400, "{name}");
            assert_eq!(
                error.body.unwrap().to_json_value()?,
                json!({"error":"invalid_client","error_description":detail})
            );
            assert_eq!(
                db.tables(&[
                    "oauthClientAssertion",
                    "oauthClient",
                    "oauthAccessToken",
                    "oauthRefreshToken"
                ])
                .await?,
                before
            );
            consume_client_assertion(
                other.context(),
                &cfg,
                &namespace,
                &JsValue::from(original),
                audience,
            )
            .await?;
        } else {
            result?;
        }
    }
    let payload = JsValue::from(json!({"aud":audience,"exp":now+90,"iat":now,"jti":"shared"}));
    for namespace in [
        "extension:client",
        "other-method:client",
        "extension:other-client",
    ] {
        consume_client_assertion(auth.context(), &cfg, namespace, &payload, audience).await?;
        let digest = sha2::Sha256::digest(format!("{namespace}:shared"));
        let id = URL_SAFE_NO_PAD.encode(&digest[..24]);
        let rows: Vec<Value> = serde_json::from_str(&db.table("oauthClientAssertion").await?)?;
        let row = rows.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(row["expiresAt"].as_str().unwrap())?.timestamp(),
            now + 90
        );
    }
    let before = db
        .tables(&[
            "oauthClientAssertion",
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken",
        ])
        .await?;
    let replay = consume_client_assertion(
        other.context(),
        &cfg,
        "extension:client",
        &payload,
        audience,
    )
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
    );
    assert_eq!(
        db.tables(&[
            "oauthClientAssertion",
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken"
        ])
        .await?,
        before
    );
    let contested = JsValue::from(json!({"aud":audience,"exp":now+90,"iat":now,"jti":"contested"}));
    let (first, second) = tokio::join!(
        consume_client_assertion(auth.context(), &cfg, "extension:race", &contested, audience),
        consume_client_assertion(
            other.context(),
            &cfg,
            "extension:race",
            &contested,
            audience
        )
    );
    let outcomes = [first, second];
    let mut statuses = outcomes
        .iter()
        .map(|result| {
            result
                .as_ref()
                .map_or_else(|error| error.error.status_code(), |()| 200)
        })
        .collect::<Vec<_>>();
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 400]);
    for error in outcomes.into_iter().filter_map(Result::err) {
        assert_eq!(
            error.body.unwrap().to_json_value()?,
            json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
        );
    }
    let id = URL_SAFE_NO_PAD.encode(&sha2::Sha256::digest("extension:race:contested")[..24]);
    let rows: Vec<Value> = serde_json::from_str(&db.table("oauthClientAssertion").await?)?;
    assert_eq!(rows.iter().filter(|row| row["id"] == id).count(), 1);
    B::close(connection).await
}
