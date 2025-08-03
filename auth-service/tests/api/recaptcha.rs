use crate::helpers::{get_random_email, TestApp};
use auth_service::{services::MockRecaptchaService, AppState, Application};
use auth_service::services::hashmap_user_store::HashmapUserStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::StatusCode;

struct TestAppWithFailingRecaptcha {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestAppWithFailingRecaptcha {
    pub async fn new() -> Self {
        let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let login_attempt_store = Arc::new(RwLock::new(auth_service::services::HashmapLoginAttemptStore::new()));
        let recaptcha_service = Arc::new(MockRecaptchaService::new(false)); // Always fails
        let app_state = AppState::new(user_store, login_attempt_store, recaptcha_service);

        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new();

        Self {
            address,
            http_client,
        }
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
}

#[tokio::test]
async fn should_return_400_if_recaptcha_verification_fails() {
    let app = TestAppWithFailingRecaptcha::new().await;

    let response = app
        .post_signup(&serde_json::json!({
            "email": get_random_email(),
            "password": "Password123!",
            "requires2FA": false,
            "recaptchaToken": "invalid_token"
        }))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let error_response = response
        .json::<auth_service::ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    
    assert_eq!(error_response.error, "Invalid credentials");
}

#[tokio::test]
async fn should_return_400_if_recaptcha_token_is_empty() {
    let app = TestApp::new().await;

    let response = app
        .post_signup(&serde_json::json!({
            "email": get_random_email(),
            "password": "Password123!",
            "requires2FA": false,
            "recaptchaToken": ""
        }))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let error_response = response
        .json::<auth_service::ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    
    assert_eq!(error_response.error, "Invalid credentials");
}

#[tokio::test]
async fn should_return_422_if_recaptcha_token_is_missing() {
    let app = TestApp::new().await;

    let response = app
        .post_signup(&serde_json::json!({
            "email": get_random_email(),
            "password": "Password123!",
            "requires2FA": false
            // Missing recaptchaToken field
        }))
        .await;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}