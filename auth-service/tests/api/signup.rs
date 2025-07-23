use crate::helpers::TestApp;

#[tokio::test]
pub async fn signup_returns_200_for_valid_credentials() {
    let app = TestApp::new().await;

    let response = app.get_signup().await;

    assert_eq!(response.status().as_u16(), 200);
}
