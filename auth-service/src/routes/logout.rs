use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{domain::AuthAPIError, utils::auth::validate_token, AppState};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(app_state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(&app_state.settings.auth.jwt_cookie_name) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value();

    match validate_token(
        token,
        &app_state.banned_token_store,
        &app_state.settings.auth,
    )
    .await
    {
        Ok(_) => (),
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }

    // Add the token to the banned token store
    if let Err(e) = app_state
        .banned_token_store
        .write()
        .await
        .store_token(token.to_string())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    // Remove the JWT cookie by creating a removal cookie
    let removal_cookie = Cookie::build((app_state.settings.auth.jwt_cookie_name.clone(), ""))
        .path("/")
        .build();

    let jar = jar.remove(removal_cookie);

    (jar, Ok(StatusCode::OK))
}
