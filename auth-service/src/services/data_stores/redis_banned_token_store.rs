use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

pub struct RedisBannedTokenStore {
    pub conn: Arc<RwLock<Connection>>,
    pub key_prefix: Option<String>,
    pub token_ttl: u64,
    pub key_prefix_base: String,
}

impl RedisBannedTokenStore {
    pub fn new_with_config(
        conn: Arc<RwLock<Connection>>,
        token_ttl: u64,
        key_prefix_base: String,
    ) -> Self {
        Self {
            conn,
            key_prefix: None,
            token_ttl,
            key_prefix_base,
        }
    }

    pub fn new_with_config_and_prefix(
        conn: Arc<RwLock<Connection>>,
        token_ttl: u64,
        key_prefix_base: String,
        prefix: String,
    ) -> Self {
        Self {
            conn,
            key_prefix: Some(prefix),
            token_ttl,
            key_prefix_base,
        }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = self.get_key(&token);

        let mut conn = self.conn.write().await;
        conn.set_ex(&key, true, self.token_ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = self.get_key(token);

        let mut conn = self.conn.write().await;
        conn.exists(&key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }
}

impl RedisBannedTokenStore {
    fn get_key(&self, token: &str) -> String {
        match &self.key_prefix {
            Some(prefix) => format!("{}{}{}", prefix, self.key_prefix_base, token),
            None => format!("{}{}", self.key_prefix_base, token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Settings, get_redis_client};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_store(test_prefix: &str) -> RedisBannedTokenStore {
        let settings = Settings::new().expect("Failed to load test configuration");
        let redis_client = get_redis_client(
            settings.redis.hostname.clone(),
            settings.redis.password.clone(),
        )
        .expect("Failed to get Redis client");
        let conn = redis_client
            .get_connection()
            .expect("Failed to get Redis connection");
        let conn = Arc::new(RwLock::new(conn));
        RedisBannedTokenStore::new_with_config_and_prefix(
            conn,
            settings.redis.banned_token_ttl_seconds,
            settings.redis.banned_token_key_prefix,
            format!("test_{}:", test_prefix),
        )
    }

    #[tokio::test]
    async fn test_store_token_success() {
        let mut store = create_test_store("store_token_success").await;
        let token = "test_token_123".to_string();

        let result = store.store_token(token.clone()).await;
        assert!(result.is_ok());

        let contains_result = store.contains_token(&token).await;
        assert!(contains_result.is_ok());
        assert!(contains_result.unwrap());

        // Clean up
        let key = store.get_key(&token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_contains_token_not_found() {
        let store = create_test_store("contains_token_not_found").await;
        let token = "nonexistent_token";

        let result = store.contains_token(token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_store_multiple_tokens() {
        let mut store = create_test_store("store_multiple_tokens").await;
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
        let _: () = conn
            .del(&[
                store.get_key(&token1),
                store.get_key(&token2),
                store.get_key(&token3),
            ])
            .unwrap();
    }

    #[tokio::test]
    async fn test_store_duplicate_token() {
        let mut store = create_test_store("store_duplicate_token").await;
        let token = "duplicate_token".to_string();

        assert!(store.store_token(token.clone()).await.is_ok());
        assert!(store.store_token(token.clone()).await.is_ok()); // Should not fail

        assert!(store.contains_token(&token).await.unwrap());

        // Clean up
        let key = store.get_key(&token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_empty_token() {
        let mut store = create_test_store("empty_token").await;
        let empty_token = "".to_string();

        assert!(store.store_token(empty_token.clone()).await.is_ok());
        assert!(store.contains_token(&empty_token).await.unwrap());

        // Clean up
        let key = store.get_key(&empty_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_special_characters_in_token() {
        let mut store = create_test_store("special_characters_in_token").await;
        let special_token = "token_with_special!@#$%^&*()_+{}|:<>?[]\";".to_string();

        assert!(store.store_token(special_token.clone()).await.is_ok());
        assert!(store.contains_token(&special_token).await.unwrap());

        // Clean up
        let key = store.get_key(&special_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_long_token() {
        let mut store = create_test_store("long_token").await;
        let long_token = "a".repeat(1000);

        assert!(store.store_token(long_token.clone()).await.is_ok());
        assert!(store.contains_token(&long_token).await.unwrap());

        // Clean up
        let key = store.get_key(&long_token);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }
}
