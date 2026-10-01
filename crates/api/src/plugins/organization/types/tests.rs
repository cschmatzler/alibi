
    use super::{
        CreateOrganizationRequest, GetFullOrganizationQuery, NullableStringField,
        SetActiveOrganizationRequest,
    };

    #[test]
    fn set_active_request_distinguishes_missing_from_null() {
        let missing: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({}))
            .expect("missing field should deserialize");
        let null: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": null
        }))
        .expect("null field should deserialize");
        let value: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": "org-123"
        }))
        .expect("string field should deserialize");

        assert!(matches!(
            missing.organization_id,
            NullableStringField::Missing
        ));
        assert!(matches!(null.organization_id, NullableStringField::Null));
        assert!(matches!(
            value.organization_id,
            NullableStringField::Value(ref organization_id) if organization_id == "org-123"
        ));
    }

    #[test]
    fn create_organization_request_deserializes_keep_current_active_organization() {
        let request: CreateOrganizationRequest = serde_json::from_value(serde_json::json!({
            "name": "Acme",
            "slug": "acme",
            "keepCurrentActiveOrganization": true
        }))
        .expect("request should deserialize");

        assert_eq!(request.keep_current_active_organization, Some(true));
    }

    #[test]
    fn get_full_organization_query_deserializes_members_limit_from_string_or_number() {
        let string_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": "1"
        }))
        .expect("string limit should deserialize");
        let number_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": 2
        }))
        .expect("number limit should deserialize");

        assert_eq!(string_limit.members_limit, Some(1.0));
        assert_eq!(number_limit.members_limit, Some(2.0));
    }
