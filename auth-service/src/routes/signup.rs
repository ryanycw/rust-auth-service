use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthAPIError, User, UserStore, Email, Password},
    AppState,
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Use Email and Password parsing for validation
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email.clone(), password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    if user_store.get_user(&email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    user_store
        .add_user(user)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}
