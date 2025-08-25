use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    AppState,
};

pub async fn logout(
    State(app_state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value();

    match validate_token(token, &app_state.banned_token_store).await {
        Ok(_) => (),
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }

    // Add the token to the banned token store
    if let Err(_) = app_state
        .banned_token_store
        .write()
        .await
        .store_token(token.to_string())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Remove the JWT cookie by creating a removal cookie
    let removal_cookie = Cookie::build((JWT_COOKIE_NAME, "")).path("/").build();

    let jar = jar.remove(removal_cookie);

    (jar, Ok(StatusCode::OK))
}
