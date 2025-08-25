use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);
        let ttl = TOKEN_TTL_SECONDS as u64;
        
        let mut conn = self.conn.write().await;
        conn.set_ex(&key, true, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);
        
        let mut conn = self.conn.write().await;
        conn.exists(&key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_redis_client;
    use crate::utils::constants::DEFAULT_REDIS_HOSTNAME;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_store() -> RedisBannedTokenStore {
        let redis_client = get_redis_client(DEFAULT_REDIS_HOSTNAME.to_owned())
            .expect("Failed to get Redis client");
        let conn = redis_client
            .get_connection()
            .expect("Failed to get Redis connection");
        let conn = Arc::new(RwLock::new(conn));
        RedisBannedTokenStore::new(conn)
    }

    #[tokio::test]
    async fn test_store_token_success() {
        let mut store = create_test_store().await;
        let token = "test_token_123".to_string();

        let result = store.store_token(token.clone()).await;
        assert!(result.is_ok());

        let contains_result = store.contains_token(&token).await;
        assert!(contains_result.is_ok());
        assert!(contains_result.unwrap());

        // Clean up
        let key = get_key(&token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_contains_token_not_found() {
        let store = create_test_store().await;
        let token = "nonexistent_token";

        let result = store.contains_token(token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_store_multiple_tokens() {
        let mut store = create_test_store().await;
        let token1 = "token_1".to_string();
        let token2 = "token_2".to_string();
        let token3 = "token_3".to_string();

        assert!(store.store_token(token1.clone()).await.is_ok());
        assert!(store.store_token(token2.clone()).await.is_ok());
        assert!(store.store_token(token3.clone()).await.is_ok());

        assert!(store.contains_token(&token1).await.unwrap());
        assert!(store.contains_token(&token2).await.unwrap());
        assert!(store.contains_token(&token3).await.unwrap());
        assert!(!store.contains_token("nonexistent").await.unwrap());

        // Clean up
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&[get_key(&token1), get_key(&token2), get_key(&token3)]).unwrap();
    }

    #[tokio::test]
    async fn test_store_duplicate_token() {
        let mut store = create_test_store().await;
        let token = "duplicate_token".to_string();

        assert!(store.store_token(token.clone()).await.is_ok());
        assert!(store.store_token(token.clone()).await.is_ok()); // Should not fail

        assert!(store.contains_token(&token).await.unwrap());

        // Clean up
        let key = get_key(&token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_empty_token() {
        let mut store = create_test_store().await;
        let empty_token = "".to_string();

        assert!(store.store_token(empty_token.clone()).await.is_ok());
        assert!(store.contains_token(&empty_token).await.unwrap());

        // Clean up
        let key = get_key(&empty_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_special_characters_in_token() {
        let mut store = create_test_store().await;
        let special_token = "token_with_special!@#$%^&*()_+{}|:<>?[]\";".to_string();

        assert!(store.store_token(special_token.clone()).await.is_ok());
        assert!(store.contains_token(&special_token).await.unwrap());

        // Clean up
        let key = get_key(&special_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_long_token() {
        let mut store = create_test_store().await;
        let long_token = "a".repeat(1000);

        assert!(store.store_token(long_token.clone()).await.is_ok());
        assert!(store.contains_token(&long_token).await.unwrap());

        // Clean up
        let key = get_key(&long_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }
}
