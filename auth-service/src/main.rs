use std::sync::Arc;

use auth_service::get_postgres_pool;
use auth_service::services::{
    postgres_user_store::PostgresUserStore, HashmapLoginAttemptStore, HashmapTwoFACodeStore,
    HashsetBannedTokenStore, MockEmailClient, MockRecaptchaService,
};
use auth_service::utils::constants::{prod, DATABASE_URL};
use auth_service::{app_state::AppState, Application};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(MockEmailClient);

    // For development, use a mock reCAPTCHA service that always succeeds
    // In production, use GoogleRecaptchaService with real secret key
    let recaptcha_service = Arc::new(MockRecaptchaService::new(true));

    let app_state = AppState::new(
        user_store,
        login_attempt_store,
        recaptcha_service,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
