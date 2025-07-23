use crate::helpers::TestApp;

#[tokio::test]
async fn logout_returns_200_for_valid_credentials() {
    let app = TestApp::new().await;

    let response = app.get_logout().await;

    assert_eq!(response.status().as_u16(), 200);
}