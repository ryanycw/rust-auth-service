use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let response = app
        .post_signup(&serde_json::json!({
            "email": "test@example.com",
            "password": "password123",
            "requires2FA": true
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

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        // Empty email
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true
        }),
        // Email without '@'
        serde_json::json!({
            "email": "invalidemail",
            "password": "password123",
            "requires2FA": true
        }),
        // Email without '@' (different format)
        serde_json::json!({
            "email": "invalid.email.com",
            "password": "password123",
            "requires2FA": true
        }),
        // Password less than 8 characters
        serde_json::json!({
            "email": "test@example.com",
            "password": "short",
            "requires2FA": true
        }),
        // Password exactly 7 characters
        serde_json::json!({
            "email": "test@example.com",
            "password": "1234567",
            "requires2FA": true
        }),
        // Both email and password invalid
        serde_json::json!({
            "email": "",
            "password": "short",
            "requires2FA": true
        }),
        // Email without '@' and short password
        serde_json::json!({
            "email": "invalidemail",
            "password": "123",
            "requires2FA": true
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

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let signup_body = serde_json::json!({
        "email": email,
        "password": "password123",
        "requires2FA": true
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

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
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
