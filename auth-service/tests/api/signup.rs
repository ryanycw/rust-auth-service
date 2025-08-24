use auth_service::{routes::SignupResponse, ErrorResponse};
use test_macros::with_db_cleanup;

use crate::helpers::{get_random_email, TestApp};

#[with_db_cleanup]
#[tokio::test]
async fn should_return_201_if_valid_input() {
    let mut app = TestApp::new(true).await;

    let response = app
        .post_signup(&serde_json::json!({
            "email": "test@example.com",
            "password": "Password123!",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);
    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new(true).await;

    let test_cases = [
        // Empty email
        serde_json::json!({
            "email": "",
            "password": "Password123!",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Email without '@'
        serde_json::json!({
            "email": "invalidemail",
            "password": "Password123!",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Email without '@' (different format)
        serde_json::json!({
            "email": "invalid.email.com",
            "password": "Password123!",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Password less than 8 characters
        serde_json::json!({
            "email": "test@example.com",
            "password": "short",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Password exactly 7 characters
        serde_json::json!({
            "email": "test@example.com",
            "password": "1234567",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Both email and password invalid
        serde_json::json!({
            "email": "",
            "password": "short",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        // Email without '@' and short password
        serde_json::json!({
            "email": "invalidemail",
            "password": "123",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let mut app = TestApp::new(true).await;

    let email = get_random_email();
    let signup_body = serde_json::json!({
        "email": email,
        "password": "Password123!",
        "requires2FA": true,
        "recaptchaToken": "test_token"
    });

    // First signup should succeed
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Second signup with same email should fail with 409
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}

#[with_db_cleanup]
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new(true).await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "Password123!",
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true,
            "recaptchaToken": "test_token"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}
