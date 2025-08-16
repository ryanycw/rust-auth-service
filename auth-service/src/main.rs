use std::sync::Arc;

use auth_service::services::{
    hashmap_user_store::HashmapUserStore, HashmapLoginAttemptStore, MockRecaptchaService, HashsetBannedTokenStore, HashmapTwoFACodeStore,
};
use auth_service::utils::constants::prod;
use auth_service::{app_state::AppState, Application};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let login_attempt_store = Arc::new(RwLock::new(HashmapLoginAttemptStore::new()));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));

    // For development, use a mock reCAPTCHA service that always succeeds
    // In production, use GoogleRecaptchaService with real secret key
    let recaptcha_service = Arc::new(MockRecaptchaService::new(true));

    let app_state = AppState::new(user_store, login_attempt_store, recaptcha_service, banned_token_store, two_fa_code_store);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
