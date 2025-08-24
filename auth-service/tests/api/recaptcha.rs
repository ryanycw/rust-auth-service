use crate::helpers::{get_random_email, TestApp};
use reqwest::StatusCode;
use test_macros::with_db_cleanup;

#[with_db_cleanup]
#[tokio::test]
async fn should_return_400_if_recaptcha_verification_fails() {
    let mut app = TestApp::new(false).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_400_if_recaptcha_token_is_empty() {
    let mut app = TestApp::new(true).await;

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

#[with_db_cleanup]
#[tokio::test]
async fn should_return_422_if_recaptcha_token_is_missing() {
    let mut app = TestApp::new(true).await;

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
