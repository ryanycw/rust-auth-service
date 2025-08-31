use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::Result;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{
        AuthAPIError, Email, LoginAttempt, LoginAttemptStore, Password, RecaptchaToken, UserStore,
    },
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Parse email and password
    let email = match Email::parse(Secret::new(request.email)) {
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
            Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
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

    // Get user and validate credentials
    let user = {
        let store = state.user_store.read().await;
        match store.validate_user(&email, &password).await {
            Ok(_) => store.get_user(&email).await.ok(),
            Err(_) => None,
        }
    };

    // Record the login attempt
    {
        let mut store = state.login_attempt_store.write().await;
        let attempt = LoginAttempt::new(email.clone(), user.is_some());
        if let Err(e) = store.record_attempt(attempt).await {
            return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
        }
    }

    // Return error if credentials are invalid
    let user = match user {
        Some(u) => u,
        None => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&user.email, jar, state).await,
        false => handle_no_2fa(&user.email, jar, &state.settings.auth).await,
    }
}

#[tracing::instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    jar: CookieJar,
    state: AppState,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    use crate::domain::data_stores::{LoginAttemptId, TwoFACode};

    // Generate a new login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // Store the 2FA code in the store
    if let Err(e) = state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    // Send 2FA code via email
    if let Err(e) = state
        .email_client
        .send_email(
            email,
            "Your 2FA Code",
            &format!(
                "Your two-factor authentication code is: {}",
                two_fa_code.as_ref()
            ),
        )
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e)));
    }

    (
        jar,
        Ok((
            StatusCode::PARTIAL_CONTENT,
            Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
                message: "2FA required".to_string(),
                login_attempt_id: login_attempt_id.as_ref().to_string(),
            })),
        )),
    )
}

#[tracing::instrument(name = "Handle No 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
    auth_config: &crate::config::AuthConfig,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // Generate auth cookie for successful login
    let auth_cookie = match generate_auth_cookie(email, auth_config) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    // Return success with updated cookie jar
    (
        jar.add(auth_cookie),
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Secret<String>,
    #[serde(rename = "recaptchaToken")]
    pub recaptcha_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status")]
pub enum LoginResponse {
    #[serde(rename = "success")]
    RegularAuth,
    #[serde(rename = "2fa_required")]
    TwoFactorAuth(TwoFactorAuthResponse),
    #[serde(rename = "recaptcha_required")]
    RecaptchaRequired,
}
