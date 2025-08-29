use std::str::FromStr;
use std::sync::Arc;

use auth_service::{
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
    config::Settings,
    get_postgres_pool, get_redis_connection,
    services::{
        postgres_user_store::PostgresUserStore, HashmapLoginAttemptStore, MockEmailClient,
        MockRecaptchaService, RedisBannedTokenStore, RedisTwoFACodeStore,
    },
    Application,
};
use reqwest::cookie::Jar;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, Executor, PgPool};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub db_name: String,
    pub clean_up_called: bool,
    pub settings: Settings,
    pub test_id: String,
}

impl TestApp {
    pub async fn new(recaptcha_success: bool) -> Self {
        // Set RUN_MODE to "test" so it loads config/test.toml with short TTLs
        std::env::set_var("RUN_MODE", "test");

        // Load test configuration (will now use config/test.toml)
        let settings = Settings::new().expect("Failed to load test configuration");
        let (pg_pool, db_name) = configure_postgresql(&settings.database.url()).await;
        let redis_conn = configure_redis(&settings.redis.hostname, &settings.redis.password).await;

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
        let test_id = uuid::Uuid::new_v4().to_string();
        let banned_token_store = Arc::new(RwLock::new(
            RedisBannedTokenStore::new_with_config_and_prefix(
                Arc::new(RwLock::new(redis_conn)),
                settings.redis.banned_token_ttl_seconds,
                settings.redis.banned_token_key_prefix.clone(),
                format!("integration_test_{}:", test_id),
            ),
        ));
        let recaptcha_service = Arc::new(MockRecaptchaService::new(recaptcha_success));
        let two_fa_code_store = Arc::new(RwLock::new(
            RedisTwoFACodeStore::new_with_config_and_prefix(
                Arc::new(RwLock::new(configure_redis(
                    &settings.redis.hostname,
                    &settings.redis.password,
                ).await)),
                settings.redis.two_fa_code_ttl_seconds,
                settings.redis.two_fa_code_key_prefix.clone(),
                format!("integration_test_{}:", test_id),
            ),
        ));
        let email_client = Arc::new(MockEmailClient);

        let app_state = AppState::new(
            user_store,
            login_attempt_store,
            recaptcha_service,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
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

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .expect("Failed to build HTTP client");

        Self {
            address,
            http_client,
            cookie_jar,
            banned_token_store,
            two_fa_code_store,
            db_name,
            clean_up_called: false,
            settings,
            test_id,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn delete_account<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .delete(&format!("{}/delete-account", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    /// Construct the Redis key for a banned token
    pub fn get_banned_token_redis_key(&self, token: &str) -> String {
        format!(
            "integration_test_{}:{}{}",
            self.test_id, self.settings.redis.banned_token_key_prefix, token
        )
    }

    /// Construct the Redis key for a 2FA code
    pub fn get_two_fa_code_redis_key(&self, email: &str) -> String {
        format!(
            "integration_test_{}:{}{}",
            self.test_id, self.settings.redis.two_fa_code_key_prefix, email
        )
    }

    /// Check if a key exists in Redis directly
    pub async fn redis_key_exists(&self, key: &str) -> bool {
        use redis::AsyncCommands;
        let mut conn =
            configure_redis(&self.settings.redis.hostname, &self.settings.redis.password).await;
        conn.exists(key).await.unwrap_or(false)
    }

    /// Get the TTL (time to live) of a key in Redis
    /// Returns -1 if key doesn't exist, -2 if key exists but has no expiration
    pub async fn get_redis_ttl(&self, key: &str) -> i64 {
        use redis::AsyncCommands;
        let mut conn =
            configure_redis(&self.settings.redis.hostname, &self.settings.redis.password).await;
        conn.ttl(key).await.unwrap_or(-1)
    }

    pub async fn clean_up(&mut self) {
        let settings = Settings::new().expect("Failed to load test configuration");
        delete_database(&self.db_name, &settings.database.url()).await;
        self.clean_up_called = true;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("TestApp was dropped without calling clean_up()! You must call clean_up() before the TestApp goes out of scope.");
        }
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql(database_url: &str) -> (PgPool, String) {
    let postgresql_conn_url = database_url;

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!
    let db_name = Uuid::new_v4().to_string();

    configure_database(postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);

    // Create a new connection pool and return it with the db name
    let pool = get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!");

    (pool, db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str, database_url: &str) {
    let postgresql_conn_url = database_url;

    let connection_options = PgConnectOptions::from_str(postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}

async fn configure_redis(redis_hostname: &str, password: &str) -> redis::aio::MultiplexedConnection {
    get_redis_connection(redis_hostname.to_owned(), password.to_owned())
        .await
        .expect("Failed to get Redis connection")
}
