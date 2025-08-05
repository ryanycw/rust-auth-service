use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_token_success() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "test_token_123".to_string();

        let result = store.store_token(token.clone()).await;
        assert!(result.is_ok());

        let contains_result = store.contains_token(&token).await;
        assert!(contains_result.is_ok());
        assert!(contains_result.unwrap());
    }

    #[tokio::test]
    async fn test_contains_token_not_found() {
        let store = HashsetBannedTokenStore::default();
        let token = "nonexistent_token";

        let result = store.contains_token(token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_store_multiple_tokens() {
        let mut store = HashsetBannedTokenStore::default();
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
    }

    #[tokio::test]
    async fn test_store_duplicate_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "duplicate_token".to_string();

        assert!(store.store_token(token.clone()).await.is_ok());
        assert!(store.store_token(token.clone()).await.is_ok()); // Should not fail

        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_empty_token() {
        let mut store = HashsetBannedTokenStore::default();
        let empty_token = "".to_string();

        assert!(store.store_token(empty_token.clone()).await.is_ok());
        assert!(store.contains_token(&empty_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_special_characters_in_token() {
        let mut store = HashsetBannedTokenStore::default();
        let special_token = "token_with_special!@#$%^&*()_+{}|:<>?[]\";',./".to_string();

        assert!(store.store_token(special_token.clone()).await.is_ok());
        assert!(store.contains_token(&special_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_long_token() {
        let mut store = HashsetBannedTokenStore::default();
        let long_token = "a".repeat(1000);

        assert!(store.store_token(long_token.clone()).await.is_ok());
        assert!(store.contains_token(&long_token).await.unwrap());
    }
}