use super::*;

#[tokio::test]
async fn reused_public_request_keeps_caller_state_out_of_success_failure_and_later_signin() {
    let (auth, rows) = configured().await;
    let request = request("sequential-owner@example.test");
    let created = auth.handle_request(request.clone()).await.unwrap();
    assert_eq!(created.status, 200);
    let duplicate = auth.handle_request(request.clone()).await.unwrap();
    assert_eq!(duplicate.status, 422);
    let mut signin = request.clone();
    signin.path = "/api/auth/sign-in/email".into();
    let signed_in = auth.handle_request(signin).await.unwrap();
    assert_eq!(signed_in.status, 200);
    assert_eq!(
        [
            sequence(&created),
            sequence(&duplicate),
            sequence(&signed_in)
        ],
        [1, 2, 3]
    );
    assert_eq!(
        request
            .extensions()
            .get::<ApplicationRequest>()
            .unwrap()
            .sequence,
        999
    );
    assert_eq!(
        *rows.lock().unwrap(),
        vec![(1, "sequential-owner@example.test".into())]
    );
    let user = auth
        .store()
        .get_user_by_email("sequential-owner@example.test")
        .await
        .unwrap()
        .unwrap();
    use better_auth_core::AuthUser;
    assert_eq!(
        auth.store()
            .get_user_accounts(user.id().as_ref())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        auth.store()
            .get_user_sessions(user.id().as_ref())
            .await
            .unwrap()
            .len(),
        2
    );
    let first: Value = serde_json::from_slice(&created.body).unwrap();
    let last: Value = serde_json::from_slice(&signed_in.body).unwrap();
    assert_eq!(
        first.get("user").unwrap().get("id").unwrap(),
        last.get("user").unwrap().get("id").unwrap()
    );
    assert_ne!(first.get("token").unwrap(), last.get("token").unwrap());
}

#[tokio::test]
async fn concurrent_cloned_public_requests_share_only_their_own_trusted_dispatch_context() {
    let (auth, rows) = configured().await;
    let mut request = request("concurrent-owner@example.test");
    let _ = request.headers.insert("x-concurrent".into(), "true".into());
    let (left, right) = tokio::join!(
        auth.handle_request(request.clone()),
        auth.handle_request(request.clone())
    );
    let left = left.unwrap();
    let right = right.unwrap();
    let mut statuses = [left.status, right.status];
    statuses.sort();
    assert_eq!(statuses, [200, 422]);
    let mut markers = [sequence(&left), sequence(&right)];
    markers.sort();
    assert_eq!(markers, [1, 2]);
    assert_eq!(
        request
            .extensions()
            .get::<ApplicationRequest>()
            .unwrap()
            .sequence,
        999
    );
    let attempts = rows.lock().unwrap().clone();
    assert!(!attempts.is_empty());
    assert!(
        attempts
            .iter()
            .all(|(sequence, email)| (1..=2).contains(sequence)
                && email == "concurrent-owner@example.test")
    );
    use better_auth_core::AuthUser;
    let user = auth
        .store()
        .get_user_by_email("concurrent-owner@example.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        auth.store()
            .get_user_accounts(user.id().as_ref())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        auth.store()
            .get_user_sessions(user.id().as_ref())
            .await
            .unwrap()
            .len(),
        1
    );
}
