use crate::helpers::{TestApp, get_random_email};
use auth_service::routes::{LoginRequest, SignupRequest};
use reqwest::StatusCode;

#[tokio::test]
async fn login_returns_200_for_valid_credentials() {
    let app = TestApp::new().await;
    
    // First create a user
    let email = get_random_email();
    let password = "Password123!".to_string();
    
    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };
    
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now login with those credentials
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: None, // No reCAPTCHA needed for first attempt
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);
}
