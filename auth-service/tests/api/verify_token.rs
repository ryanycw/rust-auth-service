use auth_service::ErrorResponse;
use reqwest::{cookie::CookieStore, StatusCode};
use test_macros::with_db_cleanup;

use crate::helpers::{get_random_email, TestApp};

#[with_db_cleanup]
#[tokio::test]
async fn should_return_200_valid_token() {
    let mut app = TestApp::new(true).await;

    // First create and login a user to get a valid JWT token
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

    // Extract JWT token from cookie jar
    let cookies = app
        .cookie_jar
        .cookies(&app.address.parse().unwrap())
        .unwrap();
    let cookie_str = cookies.to_str().unwrap();
    let jwt_token = cookie_str
        .split(';')
        .find(|s| {
            s.trim()
                .starts_with(&format!("{}=", app.settings.auth.jwt_cookie_name))
        })
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .trim();

    // Now test verify-token with the valid token
    let verify_body = serde_json::json!({
        "token": jwt_token
    });

    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new(true).await;

    let verify_body = serde_json::json!({
        "token": "invalid_token_string"
    });

    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse response");
    assert_eq!(error_response.error, "Invalid token");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_banned_token() {
    let mut app = TestApp::new(true).await;

    // First create and login a user to get a valid JWT token
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

    // Extract JWT token from cookie jar
    let cookies = app
        .cookie_jar
        .cookies(&app.address.parse().unwrap())
        .unwrap();
    let cookie_str = cookies.to_str().unwrap();
    let jwt_token = cookie_str
        .split(';')
        .find(|s| s.trim().starts_with("jwt="))
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .trim();

    // Ban the token by adding it to the banned token store
    app.banned_token_store
        .write()
        .await
        .store_token(jwt_token.to_string())
        .await
        .expect("Failed to ban token");

    // Now test verify-token with the banned token
    let verify_body = serde_json::json!({
        "token": jwt_token
    });

    let response = app.post_verify_token(&verify_body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse response");
    assert_eq!(error_response.error, "Invalid token");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new(true).await;

    // Test with malformed JSON (missing required field 'token')
    let malformed_body = r#"{"not_token": "some_value"}"#;

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/verify-token", &app.address))
        .header("Content-Type", "application/json")
        .body(malformed_body)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
