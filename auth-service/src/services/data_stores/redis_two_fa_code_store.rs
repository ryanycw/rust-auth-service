use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
    key_prefix: Option<String>,
    ttl_seconds: u64,
    key_prefix_base: String,
}

impl RedisTwoFACodeStore {
    pub fn new_with_config(
        conn: Arc<RwLock<Connection>>,
        ttl_seconds: u64,
        key_prefix_base: String,
    ) -> Self {
        Self {
            conn,
            key_prefix: None,
            ttl_seconds,
            key_prefix_base,
        }
    }

    pub fn new_with_config_and_prefix(
        conn: Arc<RwLock<Connection>>,
        ttl_seconds: u64,
        key_prefix_base: String,
        prefix: String,
    ) -> Self {
        Self {
            conn,
            key_prefix: Some(prefix),
            ttl_seconds,
            key_prefix_base,
        }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = self.get_key(&email);
        let two_fa_tuple = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );

        let serialized_tuple = serde_json::to_string(&two_fa_tuple)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let mut conn = self.conn.write().await;
        conn.set_ex(&key, serialized_tuple, self.ttl_seconds)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = self.get_key(email);
        let mut conn = self.conn.write().await;
        conn.del(&key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = self.get_key(email);
        let mut conn = self.conn.write().await;

        let serialized_tuple: String = conn
            .get(&key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let two_fa_tuple: TwoFATuple = serde_json::from_str(&serialized_tuple)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let login_attempt_id = LoginAttemptId::parse(two_fa_tuple.0)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let two_fa_code =
            TwoFACode::parse(two_fa_tuple.1).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, two_fa_code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

impl RedisTwoFACodeStore {
    fn get_key(&self, email: &Email) -> String {
        match &self.key_prefix {
            Some(prefix) => format!("{}{}{}", prefix, self.key_prefix_base, email.as_ref()),
            None => format!("{}{}", self.key_prefix_base, email.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_stores::{LoginAttemptId, TwoFACode};
    use crate::domain::Email;
    use crate::{config::Settings, get_redis_client};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_store(test_prefix: &str) -> RedisTwoFACodeStore {
        let settings = Settings::new().expect("Failed to load test configuration");
        let redis_client =
            get_redis_client(settings.redis.hostname.clone()).expect("Failed to get Redis client");
        let conn = redis_client
            .get_connection()
            .expect("Failed to get Redis connection");
        let conn = Arc::new(RwLock::new(conn));
        RedisTwoFACodeStore::new_with_config_and_prefix(
            conn,
            settings.redis.two_fa_code_ttl_seconds,
            settings.redis.two_fa_code_key_prefix,
            format!("test_{}:", test_prefix),
        )
    }

    #[tokio::test]
    async fn test_add_and_get_code() {
        let mut store = create_test_store("add_and_get_code").await;
        let email = Email::parse("test_add_get@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        // Add code
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert!(result.is_ok());

        // Get code
        let result = store.get_code(&email).await;
        assert!(result.is_ok());
        let (retrieved_id, retrieved_code) = result.unwrap();
        assert_eq!(retrieved_id, login_attempt_id);
        assert_eq!(retrieved_code, code);

        // Clean up
        let key = store.get_key(&email);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_get_nonexistent_code() {
        let store = create_test_store("get_nonexistent_code").await;
        let email = Email::parse("nonexistent_get@example.com".to_string()).unwrap();

        let result = store.get_code(&email).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = create_test_store("remove_code").await;
        let email = Email::parse("test_remove@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        // Add code
        store
            .add_code(email.clone(), login_attempt_id, code)
            .await
            .unwrap();

        // Remove code
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());

        // Verify code is removed
        let result = store.get_code(&email).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_overwrite_existing_code() {
        let mut store = create_test_store("overwrite_existing_code").await;
        let email = Email::parse("test_overwrite@example.com".to_string()).unwrap();
        let login_attempt_id1 = LoginAttemptId::default();
        let code1 = TwoFACode::default();
        let login_attempt_id2 = LoginAttemptId::default();
        let code2 = TwoFACode::default();

        // Add first code
        store
            .add_code(email.clone(), login_attempt_id1.clone(), code1.clone())
            .await
            .unwrap();

        // Overwrite with second code
        store
            .add_code(email.clone(), login_attempt_id2.clone(), code2.clone())
            .await
            .unwrap();

        // Should get the second code
        let result = store.get_code(&email).await;
        assert!(result.is_ok());
        let (retrieved_id, retrieved_code) = result.unwrap();
        assert_eq!(retrieved_id, login_attempt_id2);
        assert_eq!(retrieved_code, code2);
        assert_ne!(retrieved_id, login_attempt_id1);
        assert_ne!(retrieved_code, code1);

        // Clean up
        let key = store.get_key(&email);
        let mut conn = store.conn.write().await;
        let _: () = conn.del(&key).unwrap();
    }

    #[tokio::test]
    async fn test_multiple_emails() {
        let mut store = create_test_store("multiple_emails").await;
        let email1 = Email::parse("test_multi1@example.com".to_string()).unwrap();
        let email2 = Email::parse("test_multi2@example.com".to_string()).unwrap();
        let login_attempt_id1 = LoginAttemptId::default();
        let login_attempt_id2 = LoginAttemptId::default();
        let code1 = TwoFACode::default();
        let code2 = TwoFACode::default();

        // Add codes for both emails
        store
            .add_code(email1.clone(), login_attempt_id1.clone(), code1.clone())
            .await
            .unwrap();
        store
            .add_code(email2.clone(), login_attempt_id2.clone(), code2.clone())
            .await
            .unwrap();

        // Verify both codes exist and are correct
        let result1 = store.get_code(&email1).await;
        assert!(result1.is_ok());
        let (retrieved_id1, retrieved_code1) = result1.unwrap();
        assert_eq!(retrieved_id1, login_attempt_id1);
        assert_eq!(retrieved_code1, code1);

        let result2 = store.get_code(&email2).await;
        assert!(result2.is_ok());
        let (retrieved_id2, retrieved_code2) = result2.unwrap();
        assert_eq!(retrieved_id2, login_attempt_id2);
        assert_eq!(retrieved_code2, code2);

        // Clean up
        let mut conn = store.conn.write().await;
        let _: () = conn
            .del(&[store.get_key(&email1), store.get_key(&email2)])
            .unwrap();
    }

    #[tokio::test]
    async fn test_remove_nonexistent_code() {
        let mut store = create_test_store("remove_nonexistent_code").await;
        let email = Email::parse("nonexistent_remove@example.com".to_string()).unwrap();

        // Should not error when removing non-existent code
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
    }
}
