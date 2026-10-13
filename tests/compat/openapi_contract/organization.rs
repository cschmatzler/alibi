//! Organization plugin endpoint validation tests.
//!
//! Tests the full Organization lifecycle: create, update, delete, members,
//! invitations, and permissions against the `OpenAPI` spec.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "organization compatibility tests intentionally use direct JSON assertions over generated fixtures"
)]

use crate::contract::helpers::*;
use crate::contract::schema::OpenApiProfile;
use crate::contract::shapes::check_camel_case_fields;
use crate::contract::validator::SpecValidator;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Test organization CRUD endpoints against the spec.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn test_organization_crud_endpoints() {
        let auth = create_test_auth().await;
        let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

        // Sign up a user to use as the org creator
        let (token, _) = signup_user(&auth, "org@example.com", "password123", "Org User").await;

        // --- POST /organization/create ---
        let (status, body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/create",
                serde_json::json!({
                    "name": "Test Org",
                    "slug": "test-org"
                }),
                &token,
            ),
        )
        .await;
        assert_eq!(status, 200, "create org failed: {body}");
        validator.validate_endpoint("/organization/create", "post", status, &body);

        // --- POST /organization/check-slug (taken) ---
        let (status_2, body_2) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/check-slug",
                serde_json::json!({ "slug": "test-org" }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_2, 400, "check-slug failed: {body_2}");

        // --- POST /organization/check-slug (available) ---
        let (status_avail, body_avail) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/check-slug",
                serde_json::json!({ "slug": "available-slug" }),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status_avail, 200,
            "check-slug available failed: {body_avail}"
        );

        // --- GET /organization/list ---
        let (status_3, body_3) =
            send_request(&auth, get_with_auth("/organization/list", &token)).await;
        assert_eq!(status_3, 200, "list orgs failed: {body_3}");
        // list returns an array
        if let Some(arr) = body_3.as_array() {
            assert!(!arr.is_empty(), "org list should not be empty after create");
            if let Some(first) = arr.first() {
                let violations = check_camel_case_fields(first, "organization[0]");
                assert!(
                    violations.is_empty(),
                    "camelCase violations in org list: {violations:?}"
                );
            }
        }

        // Get org ID from list for subsequent operations
        let org_id = body_3
            .as_array()
            .and_then(|a| a.first())
            .and_then(|o| o["id"].as_str())
            .expect("org should have id")
            .to_owned();

        // --- POST /organization/update ---
        let (status_4, body_4) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/update",
                serde_json::json!({
                    "organizationId": org_id,
                    "data": {
                        "name": "Updated Org Name"
                    }
                }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_4, 200, "update org failed: {body_4}");
        validator.validate_endpoint("/organization/update", "post", status_4, &body_4);

        // --- POST /organization/set-active ---
        let (status_5, body_5) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/set-active",
                serde_json::json!({ "organizationSlug": "test-org" }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_5, 200, "set-active failed: {body_5}");
        validator.validate_endpoint("/organization/set-active", "post", status_5, &body_5);

        // --- GET /organization/get-full-organization ---
        let (status_6, body_6) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/get-full-organization",
                &token,
                vec![("organizationSlug", "test-org")],
            ),
        )
        .await;
        assert_eq!(status_6, 200, "get-full-org failed: {body_6}");
        validator.validate_endpoint(
            "/organization/get-full-organization",
            "get",
            status_6,
            &body_6,
        );

        // --- GET /organization/get-active-member ---
        let (status_7, body_7) = send_request(
            &auth,
            get_with_auth("/organization/get-active-member", &token),
        )
        .await;
        assert_eq!(status_7, 200, "get-active-member failed: {body_7}");
        validator.validate_endpoint("/organization/get-active-member", "get", status_7, &body_7);

        // --- POST /organization/has-permission ---
        let (status_8, body_8) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/has-permission",
                serde_json::json!({
                    "permissions": { "member": ["create"] }
                }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_8, 200, "has-permission failed: {body_8}");
        validator.validate_endpoint("/organization/has-permission", "post", status_8, &body_8);

        // Print report
        let report = validator.report();
        drop(writeln!(std::io::stderr().lock(), "\n{report}\n"));

        assert!(
            validator.results.iter().all(|result| result.passed
                && !result.skipped
                && (200..300).contains(&result.status)),
            "Every schema-covered endpoint must pass without skips:\n{report}"
        );
    }

    /// Test organization invitation endpoints against the spec.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn test_organization_invitation_endpoints() {
        let auth = create_test_auth().await;
        let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

        // Set up: create user and org
        let (owner_token, _) =
            signup_user(&auth, "owner@example.com", "password123", "Owner").await;
        let (invitee_token, _) =
            signup_user(&auth, "invitee@example.com", "password123", "Invitee").await;

        let (status, _create_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/create",
                serde_json::json!({
                    "name": "Invite Org",
                    "slug": "invite-org"
                }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "create org for invite test failed");

        // Set active organization
        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/set-active",
                    serde_json::json!({ "organizationSlug": "invite-org" }),
                    &owner_token,
                ),
            )
            .await,
        );

        // --- POST /organization/invite-member ---
        let (status_2, body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "email": "invitee@example.com",
                    "role": "member"
                }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status_2, 200, "invite-member failed: {body}");
        validator.validate_endpoint("/organization/invite-member", "post", status_2, &body);

        // Extract invitation ID for subsequent tests
        let invitation_id = body["id"]
            .as_str()
            .expect("invitation should have id")
            .to_owned();

        // --- GET /organization/get-invitation ---
        let (status_3, body_2) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/get-invitation",
                &invitee_token,
                vec![("id", &invitation_id)],
            ),
        )
        .await;
        assert_eq!(status_3, 200, "get-invitation failed: {body_2}");
        validator.validate_endpoint("/organization/get-invitation", "get", status_3, &body_2);

        // --- GET /organization/list-invitations ---
        let (status_4, body_3) = send_request(
            &auth,
            get_with_auth("/organization/list-invitations", &owner_token),
        )
        .await;
        assert_eq!(status_4, 200, "list-invitations failed: {body_3}");

        // --- POST /organization/accept-invitation (invitee accepts) ---
        let (status_5, body_4) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/accept-invitation",
                serde_json::json!({ "invitationId": invitation_id }),
                &invitee_token,
            ),
        )
        .await;
        assert_eq!(status_5, 200, "accept-invitation failed: {body_4}");
        validator.validate_endpoint("/organization/accept-invitation", "post", status_5, &body_4);

        // --- Invite another user to test cancel and reject ---
        let (reject_token, _) =
            signup_user(&auth, "reject@example.com", "password123", "Rejecter").await;

        let (_, inv2_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "email": "reject@example.com",
                    "role": "member"
                }),
                &owner_token,
            ),
        )
        .await;
        let inv2_id = inv2_body["id"]
            .as_str()
            .expect("second invitation should have id")
            .to_owned();

        // --- POST /organization/reject-invitation ---
        let (status_6, body_5) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/reject-invitation",
                serde_json::json!({ "invitationId": inv2_id }),
                &reject_token,
            ),
        )
        .await;
        assert_eq!(status_6, 200, "reject-invitation failed: {body_5}");
        validator.validate_endpoint("/organization/reject-invitation", "post", status_6, &body_5);

        // --- Create a third invitation to test cancel ---
        drop(signup_user(&auth, "cancel@example.com", "password123", "Canceler").await);

        let (_, inv3_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "email": "cancel@example.com",
                    "role": "member"
                }),
                &owner_token,
            ),
        )
        .await;
        let inv3_id = inv3_body["id"]
            .as_str()
            .expect("third invitation should have id")
            .to_owned();

        // --- POST /organization/cancel-invitation ---
        let (status_7, body_6) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/cancel-invitation",
                serde_json::json!({ "invitationId": inv3_id }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status_7, 200, "cancel-invitation failed: {body_6}");
        // The generated upstream schema omits this response. Check the actual
        // cancellation contract against the invitation created above.
        let mut canceled = inv3_body.clone();
        canceled["status"] = serde_json::json!("canceled");
        assert_eq!(body_6, canceled);

        // Print report
        let report = validator.report();
        drop(writeln!(std::io::stderr().lock(), "\n{report}\n"));

        assert!(
            validator.results.iter().all(|result| result.passed
                && !result.skipped
                && (200..300).contains(&result.status)),
            "Every schema-covered endpoint must pass without skips:\n{report}"
        );
    }

    /// Test organization member management endpoints.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn test_organization_member_endpoints() {
        let auth = create_test_auth().await;
        let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

        // Set up: create owner, member, and org
        let (owner_token, _) =
            signup_user(&auth, "mem_owner@example.com", "password123", "Owner").await;
        let (member_token, _) =
            signup_user(&auth, "mem_user@example.com", "password123", "Member").await;

        // Create org
        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/create",
                    serde_json::json!({
                        "name": "Member Test Org",
                        "slug": "member-test-org"
                    }),
                    &owner_token,
                ),
            )
            .await,
        );

        // Set active org
        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/set-active",
                    serde_json::json!({ "organizationSlug": "member-test-org" }),
                    &owner_token,
                ),
            )
            .await,
        );

        // Invite and accept member
        let (_, inv_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "email": "mem_user@example.com",
                    "role": "member"
                }),
                &owner_token,
            ),
        )
        .await;
        let inv_id = inv_body["id"].as_str().expect("invitation id").to_owned();

        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/accept-invitation",
                    serde_json::json!({ "invitationId": inv_id }),
                    &member_token,
                ),
            )
            .await,
        );

        // --- POST /organization/update-member-role ---
        // Get the member's member_id first via get-full-organization
        let (_, full_body) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/get-full-organization",
                &owner_token,
                vec![("organizationSlug", "member-test-org")],
            ),
        )
        .await;
        let members = full_body["members"].as_array().expect("members array");
        let member_entry = members
            .iter()
            .find(|m| m["user"]["email"].as_str() == Some("mem_user@example.com"))
            .expect("should find member by user.email");
        let member_id = member_entry["id"].as_str().expect("member id").to_owned();

        let (status, body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/update-member-role",
                serde_json::json!({
                    "memberId": member_id,
                    "role": "admin"
                }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "update-member-role failed: {body}");

        // --- POST /organization/leave (member leaves) ---
        // Set active org for member first
        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/set-active",
                    serde_json::json!({ "organizationSlug": "member-test-org" }),
                    &member_token,
                ),
            )
            .await,
        );

        let (_, full_body2) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/get-full-organization",
                &owner_token,
                vec![("organizationSlug", "member-test-org")],
            ),
        )
        .await;
        // FullOrganizationResponse uses #[serde(flatten)] on organization,
        // so org fields are at the top level
        let org_id = full_body2["id"]
            .as_str()
            .expect("org id from flattened response")
            .to_owned();

        let (status_2, body_2) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/leave",
                serde_json::json!({ "organizationId": org_id }),
                &member_token,
            ),
        )
        .await;
        assert_eq!(status_2, 200, "leave org failed: {body_2}");
        // The upstream endpoint has no response schema; it returns the removed
        // member with the same joined user seen in the full organization.
        let expected_member = full_body2["members"]
            .as_array()
            .expect("organization members")
            .iter()
            .find(|member| member["id"] == member_id)
            .expect("member must exist before leaving");
        assert_eq!(&body_2, expected_member);

        // --- POST /organization/remove-member (owner removes an invited member) ---
        // Re-invite member for remove test
        let (evaluated_member2_token, _) =
            signup_user(&auth, "mem2@example.com", "password123", "Member2").await;

        let (_, evaluated_inv2_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "email": "mem2@example.com",
                    "role": "member"
                }),
                &owner_token,
            ),
        )
        .await;
        let evaluated_inv2_id = evaluated_inv2_body["id"]
            .as_str()
            .expect("invitation id")
            .to_owned();

        drop(
            send_request(
                &auth,
                post_json_with_auth(
                    "/organization/accept-invitation",
                    serde_json::json!({ "invitationId": evaluated_inv2_id }),
                    &evaluated_member2_token,
                ),
            )
            .await,
        );

        // Get member2's member_id
        let (_, full_body3) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/get-full-organization",
                &owner_token,
                vec![("organizationSlug", "member-test-org")],
            ),
        )
        .await;
        let members3 = full_body3["members"].as_array().expect("members array");
        let evaluated_member2_entry = members3
            .iter()
            .find(|m| m["user"]["email"].as_str() == Some("mem2@example.com"))
            .expect("should find member2 by user.email");
        let evaluated_member2_id = evaluated_member2_entry["id"]
            .as_str()
            .expect("member2 id")
            .to_owned();

        let (status_3, body_3) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/remove-member",
                serde_json::json!({ "memberIdOrEmail": evaluated_member2_id }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status_3, 200, "remove-member failed: {body_3}");
        validator.validate_endpoint("/organization/remove-member", "post", status_3, &body_3);

        // --- POST /organization/delete ---
        let (status_4, body_4) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/delete",
                serde_json::json!({ "organizationId": org_id }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status_4, 200, "delete org failed: {body_4}");
        validator.validate_endpoint("/organization/delete", "post", status_4, &body_4);

        // Print report
        let report = validator.report();
        drop(writeln!(std::io::stderr().lock(), "\n{report}\n"));

        assert!(
            validator.results.iter().all(|result| result.passed
                && !result.skipped
                && (200..300).contains(&result.status)),
            "Every schema-covered endpoint must pass without skips:\n{report}"
        );
    }

    #[tokio::test]
    async fn test_custom_creator_role_protection() {
        let auth = create_test_auth_with_options(TestAuthOptions {
            creator_role: Some("founder".to_owned()),
            ..Default::default()
        })
        .await;

        let (founder_token, _) =
            signup_user(&auth, "founder@example.com", "password123", "Founder").await;

        let (status, create_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/create",
                serde_json::json!({
                    "name": "Founder Org",
                    "slug": "founder-org"
                }),
                &founder_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "create org failed: {create_body}");

        let founder_member_id = create_body["members"][0]["id"]
            .as_str()
            .expect("founder member id")
            .to_owned();
        assert_eq!(
            create_body["members"][0]["role"].as_str(),
            Some("founder"),
            "creator role should use custom founder role",
        );

        let (status_2, remove_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/remove-member",
                serde_json::json!({
                    "memberIdOrEmail": founder_member_id,
                    "organizationId": create_body["id"].as_str().expect("org id"),
                }),
                &founder_token,
            ),
        )
        .await;
        assert_eq!(
            status_2, 400,
            "remove-member should reject removing last founder: {remove_body}"
        );

        let (status_3, leave_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/leave",
                serde_json::json!({
                    "organizationId": create_body["id"].as_str().expect("org id"),
                }),
                &founder_token,
            ),
        )
        .await;
        assert_eq!(
            status_3, 400,
            "leave should reject last founder: {leave_body}"
        );
    }

    #[tokio::test]
    async fn test_invite_member_accepts_empty_role_inputs() {
        let auth = create_test_auth().await;
        let (owner_token, owner) =
            signup_user(&auth, "role-owner@example.com", "password123", "Owner").await;
        let owner_id = owner["user"]["id"].as_str().expect("owner id");

        let (status, create_body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/create",
                serde_json::json!({
                    "name": "Role Org",
                    "slug": "role-org"
                }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "create org failed: {create_body}");
        let org_id = create_body["id"].as_str().expect("org id");

        // Published 1.7.6 admits both forms and persists an empty role string.
        // Separate recipients ensure each reaches creation, not duplicate denial.
        let mut invitations = Vec::new();
        for (role, email) in [
            (serde_json::json!(""), "empty-string@example.com"),
            (serde_json::json!([]), "empty-array@example.com"),
        ] {
            let (status, body) = send_request(
                &auth,
                post_json_with_auth(
                    "/organization/invite-member",
                    serde_json::json!({
                        "organizationId": org_id,
                        "email": email,
                        "role": role
                    }),
                    &owner_token,
                ),
            )
            .await;
            assert_eq!(status, 200, "empty role should be admitted: {body}");
            assert_eq!(body["role"], "");
            assert_eq!(body["email"], email);
            assert_eq!(body["organizationId"], org_id);
            assert_eq!(body["inviterId"], owner_id);
            assert_eq!(body["status"], "pending");
            let invitation_id = body["id"].as_str().expect("invitation id");
            let stored = auth
                .context()
                .database
                .get_invitation_by_id(invitation_id)
                .await
                .expect("invitation lookup should succeed")
                .expect("admitted invitation should be persisted");
            assert_eq!(stored.role.as_deref(), Some(""));
            assert_eq!(stored.email, email);
            assert_eq!(stored.organization_id, org_id);
            assert_eq!(stored.inviter_id, owner_id);
            invitations.push(body);
        }
        assert_ne!(invitations[0]["id"], invitations[1]["id"]);

        let (status, listed) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/list-invitations",
                &owner_token,
                vec![("organizationId", org_id)],
            ),
        )
        .await;
        assert_eq!(status, 200, "list invitations failed: {listed}");
        let listed = listed.as_array().expect("invitation list");
        assert_eq!(listed.len(), invitations.len());
        for invitation in invitations {
            assert!(
                listed.contains(&invitation),
                "persisted invitation: {invitation}"
            );
        }

        let (status, denied) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({
                    "organizationId": org_id,
                    "email": "unknown-role@example.com",
                    "role": "not-a-role"
                }),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, 400, "unknown role should be rejected: {denied}");
        assert_eq!(
            denied,
            serde_json::json!({ "message": "ROLE_NOT_FOUND: not-a-role" })
        );
        let (status, after_denial) = send_request(
            &auth,
            get_with_auth_and_query(
                "/organization/list-invitations",
                &owner_token,
                vec![("organizationId", org_id)],
            ),
        )
        .await;
        assert_eq!(status, 200, "list after denial failed: {after_denial}");
        assert_eq!(after_denial.as_array().expect("invitation list"), listed);
    }
}
