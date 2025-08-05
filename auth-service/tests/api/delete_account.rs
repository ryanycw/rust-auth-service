use crate::helpers::{get_random_email, TestApp};
use auth_service::routes::{DeleteAccountRequest, SignupRequest};
use reqwest::StatusCode;

#[tokio::test]
async fn should_delete_account_with_valid_credentials() {
    let app = TestApp::new(true).await;

    // First, create a user
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

    // Now delete the account
    let delete_body = DeleteAccountRequest {
        email: email.clone(),
        password: password.clone(),
    };

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::OK);

    let json_body = delete_response
        .json::<auth_service::routes::DeleteAccountResponse>()
        .await
        .expect("Could not deserialize response body to DeleteAccountResponse");

    assert_eq!(json_body.message, "Account deleted successfully!");

    // Verify the user can no longer sign up with the same email (meaning it was truly deleted)
    let signup_again_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_again_response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn should_fail_to_delete_account_with_wrong_password() {
    let app = TestApp::new(true).await;

    // First, create a user
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

    // Try to delete with wrong password
    let delete_body = DeleteAccountRequest {
        email: email.clone(),
        password: "WrongPassword456!".to_string(),
    };

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);

    // Verify the user still exists by trying to create the same user again
    let signup_again_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_again_response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn should_fail_to_delete_non_existent_account() {
    let app = TestApp::new(true).await;

    let delete_body = DeleteAccountRequest {
        email: get_random_email(),
        password: "Password123!".to_string(),
    };

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn should_fail_to_delete_account_with_invalid_email() {
    let app = TestApp::new(true).await;

    let delete_body = DeleteAccountRequest {
        email: "invalid-email".to_string(),
        password: "Password123!".to_string(),
    };

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn should_fail_to_delete_account_with_invalid_password() {
    let app = TestApp::new(true).await;

    // Create a user first
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

    // Try to delete with invalid password format
    let delete_body = DeleteAccountRequest {
        email: email.clone(),
        password: "weak".to_string(), // Too weak password
    };

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);

    // Verify the user still exists
    let signup_again_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_again_response.status(), StatusCode::CONFLICT);
}
