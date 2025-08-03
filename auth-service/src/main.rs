use std::sync::Arc;

use auth_service::services::{hashmap_user_store::HashmapUserStore, HashmapLoginAttemptStore, MockRecaptchaService};
use auth_service::{AppState, Application};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
    
    // For development, use a mock reCAPTCHA service that always succeeds
    // In production, use GoogleRecaptchaService with real secret key
    let recaptcha_service = Arc::new(MockRecaptchaService::new(true));
    
    let app_state = AppState::new(user_store, login_attempt_store, recaptcha_service);

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
