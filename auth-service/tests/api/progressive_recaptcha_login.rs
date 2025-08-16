use crate::helpers::{get_random_email, TestApp};
use auth_service::routes::{LoginRequest, LoginResponse, SignupRequest};
use reqwest::StatusCode;

#[tokio::test]
async fn should_allow_login_without_recaptcha_for_first_attempts() {
    let app = TestApp::new(true).await;

    // Create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };

    app.post_signup(&signup_body).await;

    // First login attempt without reCAPTCHA should work (if credentials are correct)
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let login_response = response
        .json::<LoginResponse>()
        .await
        .expect("Could not deserialize response");

    assert_eq!(login_response, LoginResponse::RegularAuth);
}

#[tokio::test]
async fn should_require_recaptcha_after_three_failed_attempts() {
    let app = TestApp::new(true).await;

    // Create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };

    app.post_signup(&signup_body).await;

    // Make 3 failed login attempts
    for _ in 0..3 {
        let login_body = LoginRequest {
            email: email.clone(),
            password: "WrongPassword123!".to_string(),
            recaptcha_token: None,
        };

        let response = app.post_login(&login_body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Invalid credentials
    }

    // 4th attempt without reCAPTCHA should require reCAPTCHA
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(), // Correct password this time
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

    let login_response = response
        .json::<LoginResponse>()
        .await
        .expect("Could not deserialize response");

    assert_eq!(login_response, LoginResponse::RecaptchaRequired);
}

#[tokio::test]
async fn should_allow_login_with_valid_recaptcha_after_failed_attempts() {
    let app = TestApp::new(true).await;

    // Create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };

    app.post_signup(&signup_body).await;

    // Make 3 failed login attempts to trigger reCAPTCHA requirement
    for _ in 0..3 {
        let login_body = LoginRequest {
            email: email.clone(),
            password: "WrongPassword123!".to_string(),
            recaptcha_token: None,
        };
        app.post_login(&login_body).await;
    }

    // Now login with correct credentials and valid reCAPTCHA
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: Some("valid_test_token".to_string()),
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn should_reject_login_with_invalid_recaptcha() {
    let app = TestApp::new(false).await;

    // Create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };

    app.post_signup(&signup_body).await;

    // Make 3 failed login attempts to trigger reCAPTCHA requirement
    for _ in 0..3 {
        let login_body = LoginRequest {
            email: email.clone(),
            password: "WrongPassword123!".to_string(),
            recaptcha_token: None,
        };
        app.post_login(&login_body).await;
    }

    // Try to login with invalid reCAPTCHA (MockRecaptchaService always fails)
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: Some("invalid_token".to_string()),
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn should_reset_attempts_after_successful_login() {
    let app = TestApp::new(true).await;

    // Create a user
    let email = get_random_email();
    let password = "Password123!".to_string();

    let signup_body = SignupRequest {
        email: email.clone(),
        password: password.clone(),
        requires_2fa: false,
        recaptcha_token: "test_token".to_string(),
    };

    app.post_signup(&signup_body).await;

    // Make 3 failed login attempts
    for _ in 0..3 {
        let login_body = LoginRequest {
            email: email.clone(),
            password: "WrongPassword123!".to_string(),
            recaptcha_token: None,
        };
        app.post_login(&login_body).await;
    }

    // Successful login with reCAPTCHA should reset the counter
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: Some("valid_test_token".to_string()),
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Next login attempt should not require reCAPTCHA (counter was reset)
    let login_body = LoginRequest {
        email: email.clone(),
        password: password.clone(),
        recaptcha_token: None,
    };

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn should_track_attempts_separately_for_different_emails() {
    let app = TestApp::new(true).await;

    // Create two users
    let email1 = get_random_email();
    let email2 = get_random_email();
    let password = "Password123!".to_string();

    for email in [&email1, &email2] {
        let signup_body = SignupRequest {
            email: email.clone(),
            password: password.clone(),
            requires_2fa: false,
            recaptcha_token: "test_token".to_string(),
        };
        app.post_signup(&signup_body).await;
    }

    // Make 3 failed attempts for email1
    for _ in 0..3 {
        let login_body = LoginRequest {
            email: email1.clone(),
            password: "WrongPassword123!".to_string(),
            recaptcha_token: None,
        };
        app.post_login(&login_body).await;
    }

    // email1 should now require reCAPTCHA
    let login_body = LoginRequest {
        email: email1.clone(),
        password: password.clone(),
        recaptcha_token: None,
    };
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

    // email2 should still not require reCAPTCHA
    let login_body = LoginRequest {
        email: email2.clone(),
        password: password.clone(),
        recaptcha_token: None,
    };
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status(), StatusCode::OK);
}
