use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthAPIError, Email, Password, UserStore},
    AppState,
};

pub async fn delete_account(
    State(state): State<AppState>,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Parse and validate email and password
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let password =
        Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    // Delete the user (this validates credentials internally)
    user_store
        .delete_user(&email, &password)
        .await
        .map_err(|e| match e {
            crate::domain::UserStoreError::UserNotFound => AuthAPIError::InvalidCredentials,
            crate::domain::UserStoreError::InvalidCredentials => AuthAPIError::InvalidCredentials,
            _ => AuthAPIError::UnexpectedError,
        })?;

    let response = Json(DeleteAccountResponse {
        message: "Account deleted successfully!".to_string(),
    });

    Ok((StatusCode::OK, response))
}

#[derive(Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DeleteAccountResponse {
    pub message: String,
}
