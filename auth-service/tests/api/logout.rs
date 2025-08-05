use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::{StatusCode, Url};

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new(true).await;

    let response = app.post_logout().await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    assert_eq!(error_response.error, "Missing token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new(true).await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");
    assert_eq!(error_response.error, "Invalid token");
}
