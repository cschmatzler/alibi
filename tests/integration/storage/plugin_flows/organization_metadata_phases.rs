use super::*;

backend_tests!(organization_metadata_creation_and_update_follow_source_parse_phases);
postgres_tests!(organization_metadata_creation_and_update_follow_source_parse_phases);

async fn organization_metadata_creation_and_update_follow_source_parse_phases<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "org-metadata@example.com").await;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/organization-metadata-phases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let (path, input) = if action == "update" {
            (
                "/organization/update",
                json!({"organizationId":id,"data":{"metadata":case["input"]}}),
            )
        } else {
            let mut input = json!({"name":"Metadata","slug":format!("metadata-{action}")});
            if let Some(metadata) = case.get("input") {
                input["metadata"] = metadata.clone();
            }
            ("/organization/create", input)
        };
        let response = call(&auth, request(path, Some(input), &cookies(&owner)), 200).await;
        let value = body(&response);
        id = value["id"].as_str().unwrap().to_owned();
        assert_eq!(
            json!(value.get("metadata").is_some()),
            case["own"],
            "{action}"
        );
        assert_eq!(value["metadata"], case["output"], "{action}");
        assert_eq!(
            json!(
                db.text(
                    "SELECT \"metadata\" FROM \"organization\" WHERE id=$1",
                    &[&id]
                )
                .await?
            ),
            case["stored"],
            "{action}"
        );
    }
    B::close(connection).await
}
