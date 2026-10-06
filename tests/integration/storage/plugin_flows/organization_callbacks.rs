//! Organization creation callbacks roll back together; other lifecycles retain their committed phases.
use super::*;
use async_trait::async_trait;
use better_auth::plugins::organization::*;
use better_auth_core::{AuthError, AuthResult};

backend_tests!(
    organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases,
    organization_invitation_and_member_callbacks_preserve_actor_and_commit_order
);
postgres_tests!(
    organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases,
    organization_invitation_and_member_callbacks_preserve_actor_and_commit_order
);

#[derive(Debug, Default)]
struct Lifecycle {
    failure: Mutex<&'static str>,
    events: Mutex<Vec<&'static str>>,
    actor: Mutex<String>,
    delete_requests: Mutex<Vec<bool>>,
    target: Mutex<String>,
    delivered: Mutex<Vec<Value>>,
    previous_role: Mutex<String>,
    removal_joins: Mutex<Vec<bool>>,
}
impl Lifecycle {
    fn phase(&self, name: &'static str) -> AuthResult<()> {
        self.events.lock().unwrap().push(name);
        if *self.failure.lock().unwrap() == name {
            return Err(AuthError::bad_request(format!("{name} veto")));
        }
        Ok(())
    }
    fn reset(&self, failure: &'static str) {
        *self.failure.lock().unwrap() = failure;
        self.events.lock().unwrap().clear();
    }
}
#[async_trait]
impl OrganizationCreationHooks for Lifecycle {
    async fn before_create(
        &self,
        ctx: &OrganizationDraftContext,
    ) -> AuthResult<Option<OrganizationCreatePatch>> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.organization.name, "Submitted");
        self.phase("before-create")?;
        Ok(Some(OrganizationCreatePatch {
            id: Some("hook-organization".into()),
            name: Some("Patched organization".into()),
            slug: Some("hook-slug".into()),
            logo: Some(None),
            metadata: Some(None),
        }))
    }
    async fn before_add_member(
        &self,
        ctx: &OrganizationMemberDraftContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        assert_eq!(ctx.organization.id, "hook-organization");
        assert_eq!(ctx.member.user_id, *self.actor.lock().unwrap());
        self.phase("before-member")?;
        Ok(Some(OrganizationMemberCreatePatch {
            role: Some("owner,admin".into()),
            ..Default::default()
        }))
    }
    async fn after_add_member_in_transaction(
        &self,
        ctx: &OrganizationCreatedContext,
        store: &dyn OrganizationCreationStore,
    ) -> AuthResult<()> {
        assert_eq!(ctx.member.role, "owner,admin");
        assert_eq!(ctx.member.organization_id, ctx.organization.id);
        drop(
            store
                .update_member_role(&ctx.member.id, "owner,admin,editor")
                .await?,
        );
        self.phase("after-member")
    }
    async fn after_create(&self, ctx: &OrganizationCreatedContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, ctx.member.user_id);
        self.phase("after-create")
    }
}
#[async_trait]
impl OrganizationUpdateHooks for Lifecycle {
    async fn before_update(
        &self,
        ctx: &OrganizationUpdateContext,
    ) -> AuthResult<Option<OrganizationUpdatePatch>> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.organization.name.as_deref(), Some("Submitted update"));
        self.phase("before-update")?;
        Ok(Some(OrganizationUpdatePatch {
            name: Some("Hook updated".into()),
            logo: Some(None),
            metadata: Some(None),
            ..Default::default()
        }))
    }
    async fn after_update(&self, ctx: &OrganizationUpdatedContext) -> AuthResult<()> {
        assert_eq!(ctx.organization.as_ref().unwrap().name, "Hook updated");
        assert_eq!(ctx.user.id, ctx.member.user_id);
        self.phase("after-update")
    }
}
#[async_trait]
impl OrganizationDeletionHooks for Lifecycle {
    async fn before_delete(&self, ctx: &OrganizationDeleteContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(
            ctx.session.active_organization_id.as_deref(),
            Some("hook-organization")
        );
        assert!(
            ctx.headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("cookie"))
        );
        self.delete_requests
            .lock()
            .unwrap()
            .push(ctx.request.is_some());
        self.phase("before-delete")
    }
    async fn after_delete(&self, ctx: &OrganizationDeleteContext) -> AuthResult<()> {
        assert_eq!(ctx.organization.id, "hook-organization");
        self.phase("after-delete")
    }
}

async fn organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    for failure in [
        "before-create",
        "before-member",
        "after-member",
        "after-create",
        "",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let callbacks = Arc::new(Lifecycle::default());
        callbacks.reset(failure);
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                teams: TeamsConfig {
                    enabled: true,
                    create_default_team: true,
                    default_team_factory: Some(callbacks.clone()),
                    ..Default::default()
                },
                creation_hooks: Some(callbacks.clone()),
                update_hooks: Some(callbacks.clone()),
                deletion_hooks: Some(callbacks.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "lifecycle@example.test").await;
        *callbacks.actor.lock().unwrap() = body(&owner)["user"]["id"].as_str().unwrap().into();
        let result = call(&auth, request("/organization/create", Some(json!({"name":"Submitted","slug":"submitted","logo":"https://image.test/original","metadata":{"input":true}})), &cookies(&owner)), if failure.is_empty() { 200 } else { 400 }).await;
        let stages = [
            "before-create",
            "before-member",
            "after-member",
            "after-create",
        ];
        let executed = stages
            .iter()
            .position(|phase| *phase == failure)
            .map_or(4, |position| position + 1);
        assert_eq!(*callbacks.events.lock().unwrap(), stages[..executed]);
        assert_eq!(
            db.count("organization").await?,
            i64::from(failure.is_empty())
        );
        assert_eq!(db.count("member").await?, i64::from(failure.is_empty()));
        assert_eq!(db.count("team").await?, i64::from(failure.is_empty()));
        assert_eq!(
            db.count("team_member").await?,
            i64::from(failure.is_empty())
        );
        let token = body(&owner)["token"].as_str().unwrap().to_owned();
        let active = db
            .text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token],
            )
            .await?;
        if !failure.is_empty() {
            assert!(active.is_none());
            B::close(connection).await?;
            continue;
        }
        assert_eq!(
            db.text("SELECT role FROM member", &[]).await?.as_deref(),
            Some("owner,admin,editor")
        );
        assert_eq!(active.as_deref(), Some("hook-organization"));
        assert_eq!(body(&result)["id"], "hook-organization");
        assert_eq!(body(&result)["name"], "Patched organization");
        assert_eq!(
            db.text("SELECT slug FROM organization", &[])
                .await?
                .as_deref(),
            Some("hook-slug")
        );
        assert!(
            db.text("SELECT logo FROM organization", &[])
                .await?
                .is_none()
        );
        assert!(
            db.text("SELECT CAST(metadata AS TEXT) FROM organization", &[])
                .await?
                .is_none(),
            "creation's null patch omits metadata"
        );
        for phase in ["before-update", "after-update", ""] {
            callbacks.reset(phase);
            let before = db.table("organization").await?;
            let _ = call(&auth, request("/organization/update", Some(json!({"organizationId":"hook-organization","data":{"name":"Submitted update","metadata":{"input":true}}})), &cookies(&owner)), if phase.is_empty() { 200 } else { 400 }).await;
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-update" {
                    vec!["before-update"]
                } else {
                    vec!["before-update", "after-update"]
                }
            );
            if phase == "before-update" {
                assert_eq!(db.table("organization").await?, before);
            } else {
                assert_eq!(
                    db.text("SELECT name FROM organization", &[])
                        .await?
                        .as_deref(),
                    Some("Hook updated")
                );
                assert_eq!(
                    db.text("SELECT CAST(metadata AS TEXT) FROM organization", &[])
                        .await?
                        .as_deref(),
                    Some("null"),
                    "update's null patch persists JSON null"
                );
            }
        }
        callbacks.reset("before-delete");
        let before = db.tables(&["organization", "member"]).await?;
        let _ = call(
            &auth,
            request(
                "/organization/delete",
                Some(json!({"organizationId":"hook-organization"})),
                &cookies(&owner),
            ),
            400,
        )
        .await;
        assert_eq!(db.tables(&["organization", "member"]).await?, before);
        assert!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token]
            )
            .await?
            .is_none(),
            "selection clearing precedes the veto"
        );
        assert_eq!(*callbacks.events.lock().unwrap(), vec!["before-delete"]);
        let _ = call(
            &auth,
            request(
                "/organization/set-active",
                Some(json!({"organizationId":"hook-organization"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        callbacks.reset("after-delete");
        let helper = OrganizationPlugin::with_config(OrganizationConfig {
            deletion_hooks: Some(callbacks.clone()),
            ..Default::default()
        });
        let headers = [("Cookie".into(), cookies(&owner))].into_iter().collect();
        let error = helper
            .delete_organization_with_headers(
                auth.context(),
                &headers,
                &better_auth::plugins::organization::types::DeleteOrganizationRequest {
                    organization_id: "hook-organization".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(
            *callbacks.events.lock().unwrap(),
            vec!["before-delete", "after-delete"]
        );
        assert_eq!(
            *callbacks.delete_requests.lock().unwrap(),
            vec![true, false]
        );
        assert_eq!(db.count("organization").await?, 0);
        assert_eq!(db.count("member").await?, 0);
        assert!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token]
            )
            .await?
            .is_none()
        );
        B::close(connection).await?;
    }
    Ok(())
}

#[async_trait]
impl OrganizationInvitationLimitResolver for Lifecycle {
    async fn invitation_limit(
        &self,
        ctx: &OrganizationInvitationLimitContext,
        _: &better_auth_core::CallbackContext,
    ) -> AuthResult<f64> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.member_user.id);
        assert_eq!(ctx.member_user.id, ctx.user.id);
        self.phase("limit")?;
        Ok(if *self.failure.lock().unwrap() == "limit-zero" {
            0.0
        } else {
            100.0
        })
    }
}
#[async_trait]
impl OrganizationInvitationHooks for Lifecycle {
    async fn before_create_invitation(
        &self,
        ctx: &OrganizationInvitationCreationContext,
    ) -> AuthResult<Option<OrganizationInvitationCreatePatch>> {
        assert_eq!(ctx.inviter.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("before-invite")?;
        Ok(Some(OrganizationInvitationCreatePatch {
            email: Some(
                if self.failure.lock().unwrap().is_empty() {
                    "target@example.test"
                } else {
                    "TARGET@EXAMPLE.TEST"
                }
                .into(),
            ),
            role: Some("admin".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..Default::default()
        }))
    }
    async fn after_create_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.invitation.role.as_deref(), Some("admin"));
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert!(!ctx.invitation.id.is_empty());
        self.phase("after-invite")
    }
    async fn before_reject_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("before-reject")
    }
    async fn after_reject_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("after-reject")
    }
    async fn before_cancel_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        self.phase("before-cancel")
    }
    async fn after_cancel_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        self.phase("after-cancel")
    }
}
#[async_trait]
impl OrganizationInvitationEmailSender for Lifecycle {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        _: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        assert_eq!(delivery.email(), "target@example.test");
        assert_eq!(delivery.user.id, *self.actor.lock().unwrap());
        assert_eq!(delivery.inviter.user_id, delivery.user.id);
        assert_eq!(
            delivery.organization.id,
            delivery.invitation.organization_id
        );
        self.delivered
            .lock()
            .unwrap()
            .push(serde_json::to_value(&delivery.invitation)?);
        self.phase("send")
    }
}
#[async_trait]
impl OrganizationInvitationAcceptanceHooks for Lifecycle {
    async fn before_accept_invitation(
        &self,
        ctx: &OrganizationInvitationAcceptanceContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.invitation.email, "target@example.test");
        assert_eq!(
            ctx.invitation.status,
            better_auth_core::InvitationStatus::Pending
        );
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("before-accept")
    }
    async fn after_accept_invitation(
        &self,
        ctx: &OrganizationInvitationAcceptedContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.user.id);
        assert_eq!(ctx.member.organization_id, ctx.organization.id);
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("after-accept")
    }
}
#[async_trait]
impl OrganizationMemberRoleHooks for Lifecycle {
    async fn before_update(
        &self,
        ctx: &OrganizationMemberRoleContext,
    ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.user.id);
        assert_eq!(ctx.new_role, "member");
        *self.previous_role.lock().unwrap() = ctx.member.role.clone();
        self.phase("before-role")?;
        Ok(Some(OrganizationMemberRolePatch {
            role: Some("admin".into()),
        }))
    }
    async fn after_update(&self, ctx: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.role, "admin");
        assert_eq!(ctx.previous_role, *self.previous_role.lock().unwrap());
        self.phase("after-role")
    }
}
#[async_trait]
impl OrganizationMemberRemovalHooks for Lifecycle {
    async fn before_remove(&self, ctx: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.member.user_id, ctx.user.id);
        self.removal_joins
            .lock()
            .unwrap()
            .push(ctx.member.user.is_some());
        self.phase("before-remove")
    }
    async fn after_remove(&self, ctx: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("after-remove")
    }
}
async fn organization_invitation_and_member_callbacks_preserve_actor_and_commit_order<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    for failure in ["before-invite", "send", "after-invite", ""] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let callbacks = Arc::new(Lifecycle::default());
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                invitation_hooks: Some(callbacks.clone()),
                invitation_acceptance_hooks: Some(callbacks.clone()),
                send_invitation_email: Some(callbacks.clone()),
                invitation_limit: Some(InvitationLimit::Resolver(callbacks.clone())),
                cancel_pending_invitations_on_reinvite: true,
                member_role_hooks: Some(callbacks.clone()),
                member_removal_hooks: Some(callbacks.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "inviter@example.test").await;
        let target = signup(&auth, "target@example.test").await;
        *callbacks.actor.lock().unwrap() = body(&owner)["user"]["id"].as_str().unwrap().into();
        let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
        *callbacks.target.lock().unwrap() = target_id.clone();
        drop(
            auth.store()
                .update_user(
                    &target_id,
                    better_auth_core::UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?,
        );
        let created = call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Invitations","slug":"invitations"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let org = body(&created)["id"].as_str().unwrap().to_owned();
        let invite = || {
            request(
                "/organization/invite-member",
                Some(json!({"organizationId":org,"email":"target@example.test","role":"member"})),
                &cookies(&owner),
            )
        };
        callbacks.reset(failure);
        let result = call(
            &auth,
            invite(),
            if matches!(failure, "before-invite" | "after-invite") {
                400
            } else {
                200
            },
        )
        .await;
        assert_eq!(
            *callbacks.events.lock().unwrap(),
            if failure == "before-invite" {
                vec!["limit", "before-invite"]
            } else {
                vec!["limit", "before-invite", "send", "after-invite"]
            }
        );
        assert_eq!(
            db.count("invitation").await?,
            i64::from(failure != "before-invite")
        );
        assert_eq!(db.count("member").await?, 1);
        if failure != "before-invite" {
            let delivered = callbacks.delivered.lock().unwrap()[0].clone();
            assert_eq!(
                db.text("SELECT id FROM invitation", &[]).await?.as_deref(),
                delivered["id"].as_str()
            );
            assert_eq!(
                db.text("SELECT role FROM invitation", &[])
                    .await?
                    .as_deref(),
                Some("admin")
            );
        }
        if !failure.is_empty() {
            B::close(connection).await?;
            continue;
        }
        let id = body(&result)["id"].as_str().unwrap().to_owned();
        callbacks.reset("limit-zero");
        let _ = call(&auth, invite(), 403).await;
        assert_eq!(*callbacks.events.lock().unwrap(), vec!["limit"]);
        assert_eq!(db.count("invitation").await?, 1);
        assert_eq!(
            db.text("SELECT status FROM invitation WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some("canceled"),
            "reinvite cancellation precedes limit admission"
        );
        for (route, before_phase, after_phase, status, credential) in [
            (
                "reject-invitation",
                "before-reject",
                "after-reject",
                "rejected",
                cookies(&target),
            ),
            (
                "cancel-invitation",
                "before-cancel",
                "after-cancel",
                "canceled",
                cookies(&owner),
            ),
        ] {
            callbacks.reset("");
            let invited = call(&auth, invite(), 200).await;
            let id = body(&invited)["id"].as_str().unwrap().to_owned();
            for phase in [before_phase, after_phase] {
                callbacks.reset(phase);
                let before = db.table("invitation").await?;
                let _ = call(
                    &auth,
                    request(
                        &format!("/organization/{route}"),
                        Some(json!({"invitationId":id})),
                        &credential,
                    ),
                    400,
                )
                .await;
                if phase == before_phase {
                    assert_eq!(db.table("invitation").await?, before);
                    assert_eq!(*callbacks.events.lock().unwrap(), vec![before_phase]);
                } else {
                    assert_eq!(
                        db.text("SELECT status FROM invitation WHERE id=$1", &[&id])
                            .await?
                            .as_deref(),
                        Some(status)
                    );
                    assert_eq!(
                        *callbacks.events.lock().unwrap(),
                        vec![before_phase, after_phase]
                    );
                }
                assert_eq!(db.count("member").await?, 1);
            }
        }
        callbacks.reset("");
        let invited = call(&auth, invite(), 200).await;
        for phase in ["before-accept", "after-accept"] {
            callbacks.reset(phase);
            let before = db.table("sessions").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/accept-invitation",
                    Some(json!({"invitationId":body(&invited)["id"]})),
                    &cookies(&target),
                ),
                400,
            )
            .await;
            let invitation_id = body(&invited)["id"].as_str().unwrap().to_owned();
            assert_eq!(
                db.text(
                    "SELECT status FROM invitation WHERE id=$1",
                    &[&invitation_id]
                )
                .await?
                .as_deref(),
                Some(if phase == "before-accept" {
                    "pending"
                } else {
                    "accepted"
                })
            );
            assert_eq!(
                db.count("member").await?,
                if phase == "before-accept" { 1 } else { 2 }
            );
            if phase == "before-accept" {
                assert_eq!(db.table("sessions").await?, before);
            } else {
                let token = body(&target)["token"].as_str().unwrap().to_owned();
                assert_eq!(
                    db.text(
                        "SELECT active_organization_id FROM sessions WHERE token=$1",
                        &[&token]
                    )
                    .await?
                    .as_deref(),
                    Some(org.as_str())
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-accept" {
                    vec!["before-accept"]
                } else {
                    vec!["before-accept", "after-accept"]
                }
            );
        }
        let member = db
            .text(
                "SELECT id FROM member WHERE user_id=$1 AND organization_id=$2",
                &[&target_id, &org],
            )
            .await?
            .unwrap();
        for phase in ["before-role", "after-role", ""] {
            callbacks.reset(phase);
            let before = db.table("member").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/update-member-role",
                    Some(json!({"organizationId":org,"memberId":member,"role":"member"})),
                    &cookies(&owner),
                ),
                if phase.is_empty() { 200 } else { 400 },
            )
            .await;
            if phase == "before-role" {
                assert_eq!(db.table("member").await?, before);
            } else {
                assert_eq!(
                    db.text("SELECT role FROM member WHERE id=$1", &[&member])
                        .await?
                        .as_deref(),
                    Some("admin")
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-role" {
                    vec!["before-role"]
                } else {
                    vec!["before-role", "after-role"]
                }
            );
        }
        for (phase, selector) in [
            ("before-remove", "target@example.test"),
            ("after-remove", member.as_str()),
        ] {
            callbacks.reset(phase);
            let before = db.table("member").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/remove-member",
                    Some(json!({"organizationId":org,"memberIdOrEmail":selector})),
                    &cookies(&owner),
                ),
                400,
            )
            .await;
            if phase == "before-remove" {
                assert_eq!(db.table("member").await?, before);
            } else {
                assert_eq!(
                    db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&member])
                        .await?,
                    0
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-remove" {
                    vec!["before-remove"]
                } else {
                    vec!["before-remove", "after-remove"]
                }
            );
        }
        assert_eq!(*callbacks.removal_joins.lock().unwrap(), vec![true, false]);
        B::close(connection).await?;
    }
    Ok(())
}

#[async_trait]
impl DefaultTeamFactory for Lifecycle {
    async fn create(
        &self,
        organization: &better_auth_core::Organization,
        _: &DefaultTeamContext,
        store: &dyn better_auth_core::store::TeamStore,
    ) -> AuthResult<Option<better_auth_core::types::Team>> {
        let team = store
            .create_team(better_auth_core::types::CreateTeam {
                name: "Factory default".into(),
                organization_id: organization.id.clone(),
                updated_at: None,
            })
            .await?;
        // Reads through the transactional store must see the uncommitted team.
        let team = store
            .update_team(
                &organization.id,
                &team.id,
                better_auth_core::types::UpdateTeam {
                    name: Some("Factory renamed".into()),
                },
            )
            .await?;
        let teams = store.list_teams(&organization.id).await?;
        assert_eq!(
            teams
                .iter()
                .map(|team| team.name.as_str())
                .collect::<Vec<_>>(),
            ["Factory renamed"]
        );
        Ok(Some(team))
    }
}
