use std::sync::Arc;
use tokio::sync::RwLock;

use crate::services::{
    hashmap_user_store::HashmapUserStore, HashmapLoginAttemptStore, RecaptchaService,
};

use crate::domain::{BannedTokenStore, TwoFACodeStore};

// Using type aliases to improve readability!
pub type UserStoreType = Arc<RwLock<HashmapUserStore>>;
pub type LoginAttemptStoreType = Arc<RwLock<HashmapLoginAttemptStore>>;
pub type RecaptchaServiceType = Arc<dyn RecaptchaService + Send + Sync>;
pub type BannedTokenStoreType = Arc<RwLock<dyn BannedTokenStore + Send + Sync>>;
pub type TwoFACodeStoreType = Arc<RwLock<dyn TwoFACodeStore + Send + Sync>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub login_attempt_store: LoginAttemptStoreType,
    pub recaptcha_service: RecaptchaServiceType,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        login_attempt_store: LoginAttemptStoreType,
        recaptcha_service: RecaptchaServiceType,
        banned_token_store: BannedTokenStoreType,
        two_fa_code_store: TwoFACodeStoreType, 
    ) -> Self {
        Self {
            user_store,
            login_attempt_store,
            recaptcha_service,
            banned_token_store,
            two_fa_code_store,
        }
    }
}