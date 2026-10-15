//! Classic Entra markers are optional HTTP input tokens, never Group extensions.
use super::scim_http_admission::http;
use super::*;
use alibi::plugins::ScimPlugin;
use alibi::plugins::scim::{ScimCompatibilityOptions, ScimMicrosoftEntraCompatibilityOptions};
backend_tests!(scim_entra_group_compatibility_is_http_only_and_preserves_canonical_groups);
postgres_tests!(scim_entra_group_compatibility_is_http_only_and_preserves_canonical_groups);
const CORE: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LEGACY: &str = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
async fn scim_entra_group_compatibility_is_http_only_and_preserves_canonical_groups<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for enabled in [true, false] {
        let auth = builder::<B>(&connection)
            .plugin(
                ScimPlugin::new()
                    .connections(super::scim_group_read::connections())
                    .compatibility(ScimCompatibilityOptions {
                        microsoft_entra: Some(ScimMicrosoftEntraCompatibilityOptions {
                            accept_legacy_group_schema: enabled,
                        }),
                    }),
            )
            .build()
            .await?;
        let input = json!({"schemas":[CORE,LEGACY],"displayName":format!("Legacy-{enabled}")});
        let response = http(
            &auth,
            HttpMethod::Post,
            "Groups",
            Some("application/scim+json"),
            Some(&input.to_string()),
            Some("group-reader"),
        )
        .await;
        assert_eq!(response.status, if enabled { 201 } else { 400 });
        if enabled {
            assert_eq!(body(&response)["schemas"], json!([CORE]));
            assert!(body(&response).get(LEGACY).is_none());
        }
        let sdk = super::scim_group_create::create(&auth, &input, &json!({}), Some("group-reader"))
            .await?;
        assert_eq!(sdk.status, 400);
        assert_eq!(
            body(&sdk)["detail"],
            format!(
                "[body.schemas.1] Invalid input: expected \"{CORE}\"; [body.schemas] schemas must contain only the core SCIM Group schema"
            )
        );
        if enabled {
            for (schemas, detail) in [
                (
                    json!([CORE, LEGACY, LEGACY]),
                    "The Microsoft Entra Group compatibility schema must not be duplicated",
                ),
                (
                    json!([LEGACY]),
                    "[body.schemas] schemas must contain only the core SCIM Group schema",
                ),
            ] {
                let input = json!({"schemas":schemas,"displayName":"Rejected"});
                let rejected = http(
                    &auth,
                    HttpMethod::Post,
                    "Groups",
                    Some("application/json"),
                    Some(&input.to_string()),
                    Some("group-reader"),
                )
                .await;
                assert_eq!(rejected.status, 400);
                assert_eq!(body(&rejected)["detail"], detail);
            }
        }
        for (method, path) in [
            (HttpMethod::Post, "Groups"),
            (HttpMethod::Put, "Groups/missing"),
            (HttpMethod::Patch, "Groups/missing"),
        ] {
            let mut input = if method == HttpMethod::Patch {
                json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]})
            } else {
                json!({"schemas":[CORE],"displayName":"Attributes"})
            };
            input[LEGACY] = json!({});
            let rejected = http(
                &auth,
                method,
                path,
                Some("application/json"),
                Some(&input.to_string()),
                Some("group-reader"),
            )
            .await;
            assert_eq!(rejected.status, 400);
            assert_eq!(
                body(&rejected)["detail"],
                "The Microsoft Entra Group compatibility schema cannot contain attributes"
            );
        }
        let mut sdk_input =
            json!({"schemas":[CORE],"displayName":format!("SDK attributes-{enabled}")});
        sdk_input[LEGACY] = json!({});
        let sdk =
            super::scim_group_create::create(&auth, &sdk_input, &json!({}), Some("group-reader"))
                .await?;
        assert_eq!(sdk.status, 201);
        assert_eq!(body(&sdk)["schemas"], json!([CORE]));
        assert!(body(&sdk).get(LEGACY).is_none());
        let schemas = http(&auth, HttpMethod::Get, "Schemas", None, None, None).await;
        assert_eq!(schemas.status, 200);
        assert!(!String::from_utf8_lossy(&schemas.body).contains(LEGACY));
    }
    assert_eq!(db.count("scimGroup").await?, 3);
    Ok(())
}
