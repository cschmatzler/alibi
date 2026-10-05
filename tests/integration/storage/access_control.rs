//! Public operator decisions guard real writes after dynamic-role loading.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use better_auth::plugins::access::{
    ActionRequest, AuthorizeRequest, AuthorizeResponse, Connector, create_access_control, role,
};
use better_auth::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig,
    handlers::extension_common::{has_permissions, organization_roles},
};
use better_auth_core::store::{OrganizationRoleStore, OrganizationStore};
use better_auth_core::types::{CreateOrganizationRole, OrganizationPermissions};
use better_auth_core::{AuthConfig, AuthContext, CreateOrganization, CreateTeam};
use serde_json::{Value, json};
use std::sync::Arc;

backend_tests!(public_role_operators_guard_persisted_grants_and_physical_writes);
postgres_tests!(public_role_operators_guard_persisted_grants_and_physical_writes);

fn connector(value: &str) -> Connector {
    match value {
        "AND" => Connector::And,
        "OR" => Connector::Or,
        _ => panic!("fixture contains an unsupported connector"),
    }
}

fn request(value: &Value, order: Option<&Value>) -> AuthorizeRequest {
    let request: AuthorizeRequest = value
        .as_object()
        .unwrap()
        .iter()
        .map(|(resource, rule)| {
            let actions = rule
                .as_array()
                .or_else(|| rule["actions"].as_array())
                .unwrap()
                .iter()
                .map(|action| action.as_str().unwrap().to_owned())
                .collect();
            let rule = if rule.is_array() {
                ActionRequest::Actions(actions)
            } else {
                ActionRequest::Rule {
                    actions,
                    connector: connector(rule["connector"].as_str().unwrap()),
                }
            };
            (resource.clone(), rule)
        })
        .collect();
    match order {
        Some(order) => order
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| {
                let name = resource.as_str().unwrap();
                (name.to_owned(), request[name].clone())
            })
            .collect(),
        None => request,
    }
}

fn response(value: AuthorizeResponse) -> Value {
    match value {
        AuthorizeResponse::Success => json!({"success": true}),
        AuthorizeResponse::Denied(error) => json!({"success": false, "error": error}),
    }
}

async fn public_role_operators_guard_persisted_grants_and_physical_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/access/operators-1.7.6.json"))?;
    let literal = fixture["literal"].as_str().unwrap();
    let (connection, store) = db
        .migrated::<B>("public-role-operators-native-secret")
        .await?;
    let organization = store
        .create_organization(CreateOrganization::new("Operators", "operators"))
        .await?;
    let foreign = store
        .create_organization(CreateOrganization::new("Foreign", "foreign"))
        .await?;
    let stored = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: organization.id.clone(),
            role: "operator".into(),
            permission: OrganizationPermissions::new(),
        })
        .await?;
    assert_eq!(
        db.execute(
            "UPDATE organization_role SET permission = $1 WHERE id = $2",
            &[literal, &stored.id]
        )
        .await?,
        1
    );
    let config = OrganizationConfig {
        roles: Some(Default::default()),
        access_control: Some([("team".into(), vec!["create".into(), "delete".into()])].into()),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let ctx = AuthContext::new(
        Arc::new(AuthConfig::new("public-role-operators-native-secret")),
        Arc::new(store),
    );
    let loaded = organization_roles(&config, &ctx, &organization.id).await?;
    let grants = loaded
        .get("operator")
        .ok_or("dynamic grants disappeared")?
        .clone();
    let custom =
        create_access_control(config.access_control.clone().unwrap()).new_role(grants.clone());
    let direct = role(grants);
    assert!(
        organization_roles(&config, &ctx, &foreign.id)
            .await?
            .is_empty()
    );
    let permission_before = db
        .text(
            "SELECT permission FROM organization_role WHERE id = $1",
            &[&stored.id],
        )
        .await?;
    let count_before = db.count("team").await?;
    let mut effects = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let requested = request(&case["request"], case.get("insertionOrder"));
        let mode = connector(case["connector"].as_str().unwrap());
        let result = custom.authorize_with_connector(&requested, mode);
        assert_eq!(
            response(result.clone()),
            case["expected"],
            "{}",
            case["name"]
        );
        assert_eq!(direct.authorize_with_connector(&requested, mode), result);
        if mode == Connector::And {
            assert_eq!(custom.authorize(&requested), result);
        }
        let before = db.count("team").await?;
        let name = case["name"].as_str().unwrap();
        if result.success() {
            let team = ctx
                .database
                .create_team(CreateTeam {
                    name: name.into(),
                    organization_id: organization.id.clone(),
                    updated_at: None,
                })
                .await?;
            assert_eq!(
                db.text(
                    "SELECT name FROM team WHERE id = $1 AND organization_id = $2",
                    &[&team.id, &organization.id]
                )
                .await?
                .as_deref(),
                Some(name)
            );
            effects.push(name);
        }
        assert_eq!(
            db.count("team").await?,
            before + i64::from(result.success()),
            "{name}"
        );
        assert_eq!(
            db.text(
                "SELECT permission FROM organization_role WHERE id = $1",
                &[&stored.id]
            )
            .await?
            .as_deref(),
            Some(literal)
        );
    }
    assert_eq!(json!(effects), fixture["effects"]);
    let physical_rows: Value = serde_json::from_str(&db.table("team").await?)?;
    let mut physical_effects = physical_rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut expected_effects = fixture["effects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    physical_effects.sort();
    expected_effects.sort();
    assert_eq!(physical_effects, expected_effects);
    let physical = json!({
        "permissionBefore": permission_before,
        "permissionAfter": db.text("SELECT permission FROM organization_role WHERE id = $1", &[&stored.id]).await?,
        "teamCountBefore": count_before,
        "teamCountAfter": db.count("team").await?,
    });
    assert_eq!(physical, fixture["physical"]);
    println!(
        "{} physical={} effects={}",
        std::any::type_name::<B>(),
        physical,
        json!(physical_effects)
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM team WHERE organization_id = $1",
            &[&foreign.id]
        )
        .await?,
        0
    );

    // Internal organization requests retain AND and never union assigned roles.
    let other = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: organization.id.clone(),
            role: "deleter".into(),
            permission: [("team".into(), vec!["delete".into()])].into(),
        })
        .await?;
    let both: OrganizationPermissions =
        [("team".into(), vec!["create".into(), "delete".into()])].into();
    assert!(!has_permissions("operator,deleter", &both, &config, &ctx, &organization.id).await?);
    assert!(
        has_permissions(
            "operator,deleter",
            &[("team".into(), vec!["delete".into()])].into(),
            &config,
            &ctx,
            &organization.id
        )
        .await?
    );
    // A malformed stored role still aborts loading, including for the creator.
    assert_eq!(
        db.execute(
            "UPDATE organization_role SET permission = $1 WHERE id = $2",
            &["[]", &other.id]
        )
        .await?,
        1
    );
    assert!(
        organization_roles(&config, &ctx, &organization.id)
            .await
            .is_err()
    );
    assert!(
        has_permissions("owner", &both, &config, &ctx, &organization.id)
            .await
            .is_err()
    );
    drop(ctx);
    B::close(connection).await
}
