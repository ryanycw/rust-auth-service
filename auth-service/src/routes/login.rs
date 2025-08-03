use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthAPIError, UserStore, Email, Password, RecaptchaToken, LoginAttempt, LoginAttemptStore},
    AppState,
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // For login, create Email and Password without validation (validation only needed for signup)
    let email = Email::from_string(request.email.clone());
    let password = Password::from_string(request.password.clone());

    // Check if reCAPTCHA is required for this email
    let login_attempt_summary = {
        let login_attempt_store = state.login_attempt_store.read().await;
        login_attempt_store.get_attempt_summary(&email).await
            .map_err(|_| AuthAPIError::UnexpectedError)?
    };

    // If reCAPTCHA is required but not provided, return error with indication
    if login_attempt_summary.requires_recaptcha {
        if let Some(recaptcha_token_str) = request.recaptcha_token {
            let recaptcha_token = RecaptchaToken::new(recaptcha_token_str)
                .map_err(|_| AuthAPIError::InvalidCredentials)?;
            
            state.recaptcha_service
                .verify_token(&recaptcha_token, None)
                .await
                .map_err(|_| AuthAPIError::InvalidCredentials)?;
        } else {
            // Return specific error indicating reCAPTCHA is required
            return Ok((StatusCode::PRECONDITION_REQUIRED, Json(LoginResponse::RecaptchaRequired)));
        }
    }

    // Validate user credentials
    let user_store = state.user_store.read().await;
    let validation_result = user_store.validate_user(&email, &password).await;

    // Record the login attempt
    let login_attempt = LoginAttempt::new(email.clone(), validation_result.is_ok());
    {
        let mut login_attempt_store = state.login_attempt_store.write().await;
        login_attempt_store.record_attempt(login_attempt).await
            .map_err(|_| AuthAPIError::UnexpectedError)?;
    }

    match validation_result {
        Ok(_) => {
            // Successful login
            let response = Json(LoginResponse::Success { 
                message: "Login successful".to_string() 
            });
            Ok((StatusCode::OK, response))
        }
        Err(_) => {
            // Failed login - return invalid credentials error
            Err(AuthAPIError::InvalidCredentials)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "recaptchaToken")]
    pub recaptcha_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "status")]
pub enum LoginResponse {
    #[serde(rename = "success")]
    Success { message: String },
    #[serde(rename = "recaptcha_required")]
    RecaptchaRequired,
}
