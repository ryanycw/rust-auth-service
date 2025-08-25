use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::Email,
    routes::{LoginRequest, SignupRequest, TwoFactorAuthResponse},
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use reqwest::StatusCode;
use test_macros::with_db_cleanup;

#[with_db_cleanup]
#[tokio::test]
async fn login_returns_200_for_valid_credentials() {
    let mut app = TestApp::new(true).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new(true).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new(true).await;

    // First create a user with 2FA enabled
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: true, // Enable 2FA for this user
        recaptcha_token: "test_token".to_string(),
    };

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now login with those credentials
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    // Verify that the login_attempt_id is stored in the two_fa_code_store
    let login_attempt_id = json_body.login_attempt_id;
    {
        let two_fa_code_store = &app.two_fa_code_store;
        let two_fa_code_store_lock = two_fa_code_store.read().await;

        // Get the stored code for this email
        let stored_code = two_fa_code_store_lock
            .get_code(&Email::parse(email).unwrap())
            .await
            .expect("2FA code should be stored for this email");

        // Verify the login_attempt_id matches
        assert_eq!(stored_code.0.as_ref(), login_attempt_id);

        // Verify that a 6-digit code was generated (not checking exact value since it's random)
        assert_eq!(stored_code.1.as_ref().len(), 6);
        assert!(stored_code.1.as_ref().chars().all(|c| c.is_ascii_digit()));
    }
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new(true).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new(true).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new(true).await;

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
