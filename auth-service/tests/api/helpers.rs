use std::sync::Arc;

use auth_service::{
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
    services::{
        hashmap_user_store::HashmapUserStore, HashmapLoginAttemptStore, MockRecaptchaService, HashsetBannedTokenStore, HashmapTwoFACodeStore, MockEmailClient,
    },
    utils::constants::test,
    Application,
};
use reqwest::cookie::Jar;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
}

impl TestApp {
    pub async fn new(recaptcha_success: bool) -> Self {
        let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let recaptcha_service = Arc::new(MockRecaptchaService::new(recaptcha_success));
        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(MockEmailClient);

        let app_state = AppState::new(user_store, login_attempt_store, recaptcha_service, banned_token_store.clone(), two_fa_code_store.clone(), email_client);

        let app = Application::build(app_state, test::APP_ADDRESS)
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
            two_fa_code_store
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
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
