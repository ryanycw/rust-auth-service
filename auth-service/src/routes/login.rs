use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        AuthAPIError, Email, LoginAttempt, LoginAttemptStore, Password, RecaptchaToken, UserStore,
    },
    utils::auth::generate_auth_cookie,
    AppState,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Parse email and password
    let email = match Email::parse(request.email) {
        Ok(e) => e,
        Err(_) => return (jar, Err(AuthAPIError::InvalidInput)),
    };
    
    let password = match Password::parse(request.password) {
        Ok(p) => p,
        Err(_) => return (jar, Err(AuthAPIError::InvalidInput)),
    };

    // Check if reCAPTCHA is required for this email
    let requires_recaptcha = {
        let store = state.login_attempt_store.read().await;
        match store.get_attempt_summary(&email).await {
            Ok(summary) => summary.requires_recaptcha,
            Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        }
    };

    // Handle reCAPTCHA verification if required
    if requires_recaptcha {
        match request.recaptcha_token {
            Some(token_str) => {
                let token = match RecaptchaToken::new(token_str) {
                    Ok(t) => t,
                    Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
                };

                if let Err(_) = state.recaptcha_service.verify_token(&token, None).await {
                    return (jar, Err(AuthAPIError::InvalidCredentials));
                }
            }
            None => {
                return (
                    jar,
                    Ok((
                        StatusCode::PRECONDITION_REQUIRED,
                        Json(LoginResponse::RecaptchaRequired),
                    )),
                );
            }
        }
    }

    // Validate user credentials
    let is_valid_user = {
        let store = state.user_store.read().await;
        store.validate_user(&email, &password).await.is_ok()
    };

    // Record the login attempt
    {
        let mut store = state.login_attempt_store.write().await;
        let attempt = LoginAttempt::new(email.clone(), is_valid_user);
        if let Err(_) = store.record_attempt(attempt).await {
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
    }

    // Return error if credentials are invalid
    if !is_valid_user {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // Generate auth cookie for successful login
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    // Return success with updated cookie jar
    (
        jar.add(auth_cookie),
        Ok((
            StatusCode::OK,
            Json(LoginResponse::Success {
                message: "Login successful".to_string(),
            }),
        )),
    )
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