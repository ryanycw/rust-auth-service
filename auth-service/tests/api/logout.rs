use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::{StatusCode, Url};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new(true).await;

    // First create and login a user to get a valid JWT cookie
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": email,
        "password": password
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status(), StatusCode::OK);

    // Now logout with the valid JWT cookie
    let response = app.post_logout().await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new(true).await;

    // First create and login a user to get a valid JWT cookie
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": email,
        "password": password
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status(), StatusCode::OK);

    // First logout should succeed
    let response = app.post_logout().await;
    assert_eq!(response.status(), StatusCode::OK);

    // Second logout should fail with missing token error
    let response = app.post_logout().await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    assert_eq!(error_response.error, "Missing token");
}

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new(true).await;

    let response = app.post_logout().await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    assert_eq!(error_response.error, "Missing token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new(true).await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    assert_eq!(error_response.error, "Invalid token");
}
