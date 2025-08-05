use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::{cookie::CookieStore, StatusCode, Url};

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

    // Extract JWT token from cookie jar BEFORE logout
    let cookies = app
        .cookie_jar
        .cookies(&app.address.parse().unwrap())
        .unwrap();
    let cookie_str = cookies.to_str().unwrap();
    let jwt_token = cookie_str
        .split(';')
        .find(|s| s.trim().starts_with(&format!("{}=", JWT_COOKIE_NAME)))
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    // Now logout with the valid JWT cookie
    let response = app.post_logout().await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the token is now in the banned token store
    let is_banned = app
        .banned_token_store
        .read()
        .await
        .contains_token(&jwt_token)
        .await
        .expect("Failed to check banned token store");

    assert!(
        is_banned,
        "JWT token should be in the banned token store after logout"
    );
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
