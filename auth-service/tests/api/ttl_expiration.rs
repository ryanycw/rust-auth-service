use reqwest::{cookie::CookieStore, StatusCode};
use test_macros::with_db_cleanup;
use tokio::time::{sleep, Duration};

use crate::helpers::{get_random_email, TestApp};

#[with_db_cleanup]
#[tokio::test]
async fn banned_token_expires_after_ttl() {
    let mut app = TestApp::new(true).await;

    // Create and login a user to get a valid JWT token
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
        .find(|s| {
            s.trim()
                .starts_with(&format!("{}=", app.settings.auth.jwt_cookie_name))
        })
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    // Logout to add token to banned store
    let logout_response = app.post_logout().await;
    assert_eq!(logout_response.status(), StatusCode::OK);

    // Verify the token is immediately banned
    let is_banned = app
        .banned_token_store
        .read()
        .await
        .contains_token(&jwt_token)
        .await
        .expect("Failed to check banned token store");

    assert!(
        is_banned,
        "JWT token should be in the banned token store immediately after logout"
    );

    // Construct the Redis key for the banned token
    let redis_key = app.get_banned_token_redis_key(&jwt_token);

    // Verify the key exists in Redis and has a TTL
    assert!(
        app.redis_key_exists(&redis_key).await,
        "Banned token key should exist in Redis"
    );

    let ttl = app.get_redis_ttl(&redis_key).await;
    assert!(
        ttl > 0,
        "Banned token should have a positive TTL, got: {}",
        ttl
    );

    // Wait for TTL to expire (config/test.toml sets TTL to 1 second)
    sleep(Duration::from_secs(2)).await;

    // Verify the token is no longer banned (expired from Redis)
    let is_still_banned = app
        .banned_token_store
        .read()
        .await
        .contains_token(&jwt_token)
        .await
        .expect("Failed to check banned token store");

    assert!(
        !is_still_banned,
        "JWT token should no longer be banned after TTL expiration"
    );

    // Also verify the key no longer exists in Redis
    assert!(
        !app.redis_key_exists(&redis_key).await,
        "Banned token key should no longer exist in Redis after expiration"
    );
}

#[with_db_cleanup]
#[tokio::test]
async fn two_fa_code_expires_after_ttl() {
    let mut app = TestApp::new(true).await;

    // Create a user with 2FA enabled
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true,
        "recaptchaToken": "test_token"
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login to generate a 2FA code (should return 206 Partial Content)
    let login_body = serde_json::json!({
        "email": email,
        "password": password
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status(), StatusCode::PARTIAL_CONTENT);

    // Verify the 2FA code exists in the store
    let two_fa_result = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&auth_service::domain::Email::parse(email.clone()).unwrap())
        .await;

    assert!(
        two_fa_result.is_ok(),
        "2FA code should exist in the store immediately after login"
    );

    // Construct the Redis key for the 2FA code
    let redis_key = app.get_two_fa_code_redis_key(&email);

    // Verify the key exists in Redis and has a TTL
    assert!(
        app.redis_key_exists(&redis_key).await,
        "2FA code key should exist in Redis"
    );

    let ttl = app.get_redis_ttl(&redis_key).await;
    assert!(ttl > 0, "2FA code should have a positive TTL, got: {}", ttl);

    // Wait for TTL to expire (config/test.toml sets TTL to 1 second)
    sleep(Duration::from_secs(2)).await;

    // Verify the 2FA code is no longer in the store (expired from Redis)
    let two_fa_result_after = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&auth_service::domain::Email::parse(email.clone()).unwrap())
        .await;

    assert!(
        two_fa_result_after.is_err(),
        "2FA code should no longer exist in the store after TTL expiration"
    );

    // Also verify the key no longer exists in Redis
    assert!(
        !app.redis_key_exists(&redis_key).await,
        "2FA code key should no longer exist in Redis after expiration"
    );
}
