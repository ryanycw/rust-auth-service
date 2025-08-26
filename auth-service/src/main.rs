use std::sync::Arc;

use auth_service::services::{
    postgres_user_store::PostgresUserStore, HashmapLoginAttemptStore, MockEmailClient,
    MockRecaptchaService, RedisBannedTokenStore, RedisTwoFACodeStore,
};
use auth_service::{app_state::AppState, config::Settings, Application};
use auth_service::{get_postgres_pool, get_redis_client};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");

    let pg_pool = configure_postgresql(&settings.database.url()).await;
    let redis_conn = configure_redis(&settings.redis.hostname);

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new_with_config(
        Arc::new(RwLock::new(redis_conn)),
        settings.redis.banned_token_ttl_seconds,
        settings.redis.banned_token_key_prefix.clone(),
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new_with_config(
        Arc::new(RwLock::new(configure_redis(&settings.redis.hostname))),
        settings.redis.two_fa_code_ttl_seconds,
        settings.redis.two_fa_code_key_prefix.clone(),
    )));
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
        settings.clone(),
    );

    let app = Application::build(
        app_state,
        &settings.server_address(),
        &settings.cors.allowed_origins,
    )
    .await
    .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql(database_url: &str) -> PgPool {
    let pg_pool = get_postgres_pool(database_url)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis(redis_hostname: &str) -> redis::Connection {
    get_redis_client(redis_hostname.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
