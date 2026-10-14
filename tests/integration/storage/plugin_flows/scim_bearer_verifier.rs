//! External verification resolves immutable connections over the real application store.
use super::scim_group_read::read;
use super::*;
use alibi::AuthUser;
use alibi::plugins::scim::{
    ScimBearerTokenVerificationInput, ScimBearerTokenVerifier, ScimConnectionOptions,
    ScimCredential, ScimPlugin,
};
use alibi::store::AuthStore;
use alibi::utils::json::JsValue;
backend_tests!(scim_external_verifier_resolves_connections_and_preserves_precedence);
postgres_tests!(scim_external_verifier_resolves_connections_and_preserves_precedence);
struct Verifier {
    observed: Arc<Mutex<Vec<String>>>,
    claims: Arc<Mutex<Option<JsValue>>>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimBearerTokenVerifier<S> for Verifier {
    async fn verify_bearer_token(
        &self,
        input: &ScimBearerTokenVerificationInput,
        database: &dyn AuthStore<S>,
    ) -> alibi::AuthResult<Option<JsValue>> {
        assert_eq!(input.method, HttpMethod::Get);
        assert_eq!(input.path, "/scim/v2/Groups/:groupId");
        assert_eq!(
            input.headers.get("authorization"),
            Some(&format!("Bearer {}", input.token))
        );
        self.observed.lock().unwrap().push(input.token.clone());
        let owner = database
            .get_user_by_email("verifier-owner@example.com")
            .await?
            .ok_or_else(|| alibi::AuthError::internal("owner missing"))?;
        _ = database
            .update_user(
                owner.id().as_ref(),
                alibi::UpdateUser {
                    name: Some("Verified remote".into()),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(claims) = self.claims.lock().unwrap().clone() {
            return Ok(Some(claims));
        }
        let claims = if input.token == "oauth-dynamic" {
            json!({"connection":{"id":"dynamic","provisioningDomainId":"tenant-dynamic"},"credentialId":"remote","scopes":["scim.groups.read"]})
        } else {
            json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.groups.read"]})
        };
        Ok(Some(JsValue::from(claims)))
    }
}
async fn scim_external_verifier_resolves_connections_and_preserves_precedence<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let claims = Arc::new(Mutex::new(None));
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(vec![ScimConnectionOptions {
                    id: "declared".into(),
                    provisioning_domain_id: Some("tenant-declared".into()),
                    credentials: vec![ScimCredential::new("static", "static-token")],
                }])
                .authentication::<B::Schema>(Arc::new(Verifier {
                    observed: observed.clone(),
                    claims: claims.clone(),
                })),
        )
        .build()
        .await?;
    _ = signup(&auth, "verifier-owner@example.com").await;
    for (cid, domain) in [
        ("declared", "tenant-declared"),
        ("dynamic", "tenant-dynamic"),
    ] {
        _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$1,$2,0,'Verified Group',$1,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[cid,domain]).await?;
    }
    assert_eq!(
        read(&auth, "declared", &json!({}), Some("static-token"))
            .await?
            .status,
        200
    );
    assert!(observed.lock().unwrap().is_empty());
    assert_eq!(
        read(
            &auth,
            "declared",
            &json!({}),
            Some("ba_scim_credential_invalid")
        )
        .await?
        .status,
        401
    );
    assert!(observed.lock().unwrap().is_empty());
    let declared = read(&auth, "declared", &json!({}), Some("oauth-declared")).await?;
    assert_eq!(declared.status, 200);
    assert_eq!(body(&declared)["id"], "declared");
    let dynamic = read(&auth, "dynamic", &json!({}), Some("oauth-dynamic")).await?;
    assert_eq!(dynamic.status, 200);
    assert_eq!(body(&dynamic)["id"], "dynamic");
    assert_eq!(
        *observed.lock().unwrap(),
        vec!["oauth-declared", "oauth-dynamic"]
    );
    let rows: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(rows[0]["name"], "Verified remote");
    let valid =
        json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.groups.read"]});
    for invalid in [
        Value::Null,
        json!({"connectionId":"unknown","credentialId":"remote","scopes":["scim.groups.read"]}),
        json!({"connectionId":"declared","connection":null,"credentialId":"remote","scopes":["scim.groups.read"]}),
        json!({"connection":{"id":"declared","provisioningDomainId":"tenant-declared"},"credentialId":"remote","scopes":["scim.groups.read"]}),
        json!({"connection":{"id":"ba_scim_connection_reserved","provisioningDomainId":"tenant-dynamic"},"credentialId":"remote","scopes":["scim.groups.read"]}),
        json!({"connectionId":"declared","credentialId":" remote ","scopes":["scim.groups.read"]}),
        json!({"connectionId":"declared","credentialId":"remote","scopes":[]}),
        json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.groups.read","scim.groups.read"]}),
        json!({"connectionId":"declared","credentialId":"remote","scopes":["unsupported"]}),
        json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.groups.read"],"expiresAt":"2035-01-02T03:04:05.000Z"}),
    ] {
        *claims.lock().unwrap() = Some(JsValue::from(invalid));
        assert_eq!(
            read(&auth, "declared", &json!({}), Some("oauth-test"))
                .await?
                .status,
            401
        );
    }
    *claims.lock().unwrap() = Some(JsValue::from(
        json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.users.read"]}),
    ));
    assert_eq!(
        read(&auth, "declared", &json!({}), Some("oauth-test"))
            .await?
            .status,
        403
    );
    for (expiry, expected) in [("2000-01-01T00:00:00Z", 401), ("2035-01-02T03:04:05Z", 200)] {
        let mut value = JsValue::from(valid.clone());
        if let JsValue::Object(fields) = &mut value {
            _ = fields.insert(
                "expiresAt".into(),
                JsValue::Date(
                    chrono::DateTime::parse_from_rfc3339(expiry)?.with_timezone(&chrono::Utc),
                ),
            );
        }
        *claims.lock().unwrap() = Some(value);
        assert_eq!(
            read(&auth, "declared", &json!({}), Some("oauth-test"))
                .await?
                .status,
            expected
        );
    }
    let mut req = request("/scim/v2/Groups/declared", None, "");
    _ = req
        .headers
        .insert("authorization".into(), "Bearer oauth-test".into());
    let http = call(&auth, req, 200).await;
    assert_eq!(body(&http)["id"], "declared");

    Ok(())
}
