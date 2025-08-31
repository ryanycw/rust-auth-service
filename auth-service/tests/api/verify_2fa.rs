use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode},
    routes::Verify2FARequest,
    ErrorResponse,
};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, Secret};
use serde_json::json;
use test_macros::with_db_cleanup;

use crate::helpers::{get_random_email, TestApp};

#[with_db_cleanup]
#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let mut app = TestApp::new(true).await;
    let email = Email::parse(Secret::new(get_random_email())).unwrap();

    // Store a code in the 2FA store
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    {
        let mut store = app.two_fa_code_store.write().await;
        store
            .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
            .await
            .expect("Failed to add 2FA code");
    }

    // Send correct 2FA request
    let correct_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
        two_fa_code: two_fa_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&correct_request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify auth cookie was set
    let cookies = response.cookies();
    let auth_cookie = cookies
        .into_iter()
        .find(|c| c.name() == &app.settings.auth.jwt_cookie_name)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    // Verify the 2FA code was removed from the store
    {
        let store = app.two_fa_code_store.read().await;
        let result = store.get_code(&email).await;
        assert!(
            result.is_err(),
            "2FA code should have been removed after successful authentication"
        );
    }
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new(true).await;

    // Test with invalid email
    let invalid_request = Verify2FARequest {
        email: "invalid-email".to_string(),
        login_attempt_id: "valid-id-123".to_string(),
        two_fa_code: "123456".to_string(),
    };

    let response = app.post_verify_2fa(&invalid_request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Invalid input");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new(true).await;
    let email = Email::parse(Secret::new(get_random_email())).unwrap();

    // Store a code in the 2FA store
    let correct_login_attempt_id = LoginAttemptId::default();
    let correct_code = TwoFACode::default();

    {
        let mut store = app.two_fa_code_store.write().await;
        store
            .add_code(
                email.clone(),
                correct_login_attempt_id.clone(),
                correct_code.clone(),
            )
            .await
            .expect("Failed to add 2FA code");
    }

    // Test with wrong 2FA code (valid format but incorrect value)
    let wrong_code_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: correct_login_attempt_id.as_ref().to_string(),
        two_fa_code: "123456".to_string(), // Valid format but wrong code
    };

    let response = app.post_verify_2fa(&wrong_code_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Incorrect credentials");

    // Test with wrong login attempt ID (valid UUID format but incorrect value)
    let wrong_login_id = LoginAttemptId::default();
    let wrong_id_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: wrong_login_id.as_ref().to_string(),
        two_fa_code: correct_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&wrong_id_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Incorrect credentials");

    // Test with non-existent email
    let non_existent_request = Verify2FARequest {
        email: get_random_email(),
        login_attempt_id: correct_login_attempt_id.as_ref().to_string(),
        two_fa_code: correct_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&non_existent_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Incorrect credentials");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new(true).await;
    let email = Email::parse(Secret::new(get_random_email())).unwrap();

    // Store a code in the 2FA store
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    {
        let mut store = app.two_fa_code_store.write().await;
        store
            .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
            .await
            .expect("Failed to add 2FA code");
    }

    // First request with correct code - should succeed
    let correct_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
        two_fa_code: two_fa_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&correct_request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the code was removed
    {
        let store = app.two_fa_code_store.read().await;
        let result = store.get_code(&email).await;
        assert!(result.is_err(), "2FA code should have been removed");
    }

    // Second request with the same code - should fail
    let same_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
        two_fa_code: two_fa_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&same_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Incorrect credentials");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login request. This should fail.
    let mut app = TestApp::new(true).await;
    let email = Email::parse(Secret::new(get_random_email())).unwrap();

    // Add first 2FA code
    let first_login_attempt_id = LoginAttemptId::default();
    let first_code = TwoFACode::default();

    {
        let mut store = app.two_fa_code_store.write().await;
        store
            .add_code(
                email.clone(),
                first_login_attempt_id.clone(),
                first_code.clone(),
            )
            .await
            .expect("Failed to add first 2FA code");
    }

    // Simulate second login - this should overwrite the first code
    let second_login_attempt_id = LoginAttemptId::default();
    let second_code = TwoFACode::default();

    {
        let mut store = app.two_fa_code_store.write().await;
        // Remove old code first (simulating what login would do)
        let _ = store.remove_code(&email).await;
        // Add new code
        store
            .add_code(
                email.clone(),
                second_login_attempt_id.clone(),
                second_code.clone(),
            )
            .await
            .expect("Failed to add second 2FA code");
    }

    // Try to use the first (old) 2FA code - this should fail
    let old_code_request = Verify2FARequest {
        email: email.as_ref().expose_secret().to_string(),
        login_attempt_id: first_login_attempt_id.as_ref().to_string(),
        two_fa_code: first_code.as_ref().to_string(),
    };

    let response = app.post_verify_2fa(&old_code_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse response");
    assert_eq!(body.error, "Incorrect credentials");
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new(true).await;

    // Test with missing fields
    let malformed_request = json!({
        "email": get_random_email()
        // Missing loginAttemptId and 2FACode
    });

    let response = app.post_verify_2fa(&malformed_request).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Test with wrong field names
    let wrong_fields_request = json!({
        "email": get_random_email(),
        "login_attempt_id": "some-id", // Should be loginAttemptId
        "twofa_code": "123456" // Should be 2FACode
    });

    let response = app.post_verify_2fa(&wrong_fields_request).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Test with null values
    let null_values_request = json!({
        "email": null,
        "loginAttemptId": "some-id",
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&null_values_request).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Test with wrong types
    let wrong_types_request = json!({
        "email": 123, // Should be string
        "loginAttemptId": "some-id",
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&wrong_types_request).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
