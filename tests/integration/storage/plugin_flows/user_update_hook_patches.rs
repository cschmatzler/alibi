use super::*;
#[path = "user_update_patch_cases.rs"]
mod cases;

backend_tests!(original_input_user_update_patch_matrix);

async fn original_input_user_update_patch_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let effects = Arc::new(cases::Effects::default());
    let config = cases::config(&effects, "displayUsername");
    let store = B::hook(
        B::store(config.clone(), &connection),
        cases::PhysicalHook(effects.clone()),
    );
    cases::exercise(config, Arc::new(store), effects).await;
    Ok(())
}
