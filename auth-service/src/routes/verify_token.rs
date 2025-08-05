use axum::{extract::{Json, State}, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::auth::validate_token, AppState};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

pub async fn verify_token(
    State(app_state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    match validate_token(&request.token, &app_state.banned_token_store).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
