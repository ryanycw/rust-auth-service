use crate::helpers::{get_random_email, TestApp};
use reqwest::StatusCode;
use test_macros::with_db_cleanup;

#[with_db_cleanup]
#[tokio::test]
async fn should_delete_account_with_valid_credentials() {
    let mut app = TestApp::new(true).await;

    // First, create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now delete the account
    let delete_body = serde_json::json!({
        "email": email,
        "password": password,
    });

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

#[with_db_cleanup]
#[tokio::test]
async fn should_fail_to_delete_account_with_wrong_password() {
    let mut app = TestApp::new(true).await;

    // First, create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Try to delete with wrong password
    let delete_body = serde_json::json!({
        "email": email,
        "password": "WrongPassword456!",
    });

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);

    // Verify the user still exists by trying to create the same user again
    let signup_again_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_again_response.status(), StatusCode::CONFLICT);
}

#[with_db_cleanup]
#[tokio::test]
async fn should_fail_to_delete_non_existent_account() {
    let mut app = TestApp::new(true).await;

    let delete_body = serde_json::json!({
        "email": get_random_email(),
        "password": "Password123!",
    });

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
}

#[with_db_cleanup]
#[tokio::test]
async fn should_fail_to_delete_account_with_invalid_email() {
    let mut app = TestApp::new(true).await;

    let delete_body = serde_json::json!({
        "email": "invalid-email",
        "password": "Password123!",
    });

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);
}

#[with_db_cleanup]
#[tokio::test]
async fn should_fail_to_delete_account_with_invalid_password() {
    let mut app = TestApp::new(true).await;

    // Create a user first
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false,
        "recaptchaToken": "test_token"
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Try to delete with invalid password format
    let delete_body = serde_json::json!({
        "email": email,
        "password": "weak", // Too weak password
    });

    let delete_response = app.delete_account(&delete_body).await;
    assert_eq!(delete_response.status(), StatusCode::BAD_REQUEST);

    // Verify the user still exists
    let signup_again_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_again_response.status(), StatusCode::CONFLICT);
}
