use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    routes::{LoginRequest, SignupRequest},
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use reqwest::StatusCode;

#[tokio::test]
async fn login_returns_200_for_valid_credentials() {
    let app = TestApp::new(true).await;

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

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new(true).await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "Password123!",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new(true).await;

    // Test with invalid email format
    let login_body = LoginRequest {
        email: "invalid-email".to_string(),
        password: "Password123!".to_string(),
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse response");
    assert_eq!(error_response.error, "Invalid input");
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new(true).await;

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

    // Now login with wrong password
    let login_body = LoginRequest {
        email: email.clone(),
        password: "WrongPassword123!".to_string(),
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse response");
    assert_eq!(error_response.error, "Incorrect credentials");
}

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new(true).await;

    // Test with malformed JSON (missing required fields)
    let malformed_body = r#"{"email": "test@example.com"}"#; // Missing password

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/login", &app.address))
        .header("Content-Type", "application/json")
        .body(malformed_body)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
