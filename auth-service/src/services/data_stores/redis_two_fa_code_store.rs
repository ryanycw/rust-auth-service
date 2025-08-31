use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<redis::aio::MultiplexedConnection>>,
    key_prefix: Option<String>,
    ttl_seconds: u64,
    key_prefix_base: String,
}

impl RedisTwoFACodeStore {
    #[tracing::instrument(name = "New Redis Two FA Code Store with Config", skip_all)]
    pub fn new_with_config(
        conn: Arc<RwLock<redis::aio::MultiplexedConnection>>,
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

    #[tracing::instrument(name = "New Redis Two FA Code Store with Config and Prefix", skip_all)]
    pub fn new_with_config_and_prefix(
        conn: Arc<RwLock<redis::aio::MultiplexedConnection>>,
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
    #[tracing::instrument(name = "Add Two FA Code", skip_all)]
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
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized_tuple, self.ttl_seconds)
            .await
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "Remove Two FA Code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = self.get_key(email);
        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .await
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "Get Two FA Code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = self.get_key(email);
        match self.conn.write().await.get::<_, String>(&key).await {
            Ok(value) => {
                let data: TwoFATuple = serde_json::from_str(&value)
                    .wrap_err("failed to deserialize 2FA tuple")
                    .map_err(TwoFACodeStoreError::UnexpectedError)?;

                let login_attempt_id =
                    LoginAttemptId::parse(data.0).map_err(TwoFACodeStoreError::UnexpectedError)?;

                let email_code =
                    TwoFACode::parse(data.1).map_err(TwoFACodeStoreError::UnexpectedError)?;

                Ok((login_attempt_id, email_code))
            }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

impl RedisTwoFACodeStore {
    #[tracing::instrument(name = "Get Two FA Code Key", skip_all)]
    fn get_key(&self, email: &Email) -> String {
        match &self.key_prefix {
            Some(prefix) => format!(
                "{}{}{}",
                prefix,
                self.key_prefix_base,
                email.as_ref().expose_secret()
            ),
            None => format!("{}{}", self.key_prefix_base, email.as_ref().expose_secret()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::domain::data_stores::{LoginAttemptId, TwoFACode};
    use crate::domain::Email;
    use secrecy::Secret;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_store(test_prefix: &str) -> RedisTwoFACodeStore {
        let settings = Settings::new().expect("Failed to load test configuration");
        let conn = crate::get_redis_connection(
            settings.redis.hostname.clone(),
            settings.redis.password.clone(),
        )
        .await
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
        let email = Email::parse(Secret::new("test_add_get@example.com".to_string())).unwrap();
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
        let _: () = conn.del(&key).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_nonexistent_code() {
        let store = create_test_store("get_nonexistent_code").await;
        let email = Email::parse(Secret::new("nonexistent_get@example.com".to_string())).unwrap();

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
        let email = Email::parse(Secret::new("test_remove@example.com".to_string())).unwrap();
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
        let email = Email::parse(Secret::new("test_overwrite@example.com".to_string())).unwrap();
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
        let _: () = conn.del(&key).await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_emails() {
        let mut store = create_test_store("multiple_emails").await;
        let email1 = Email::parse(Secret::new("test_multi1@example.com".to_string())).unwrap();
        let email2 = Email::parse(Secret::new("test_multi2@example.com".to_string())).unwrap();
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
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_remove_nonexistent_code() {
        let mut store = create_test_store("remove_nonexistent_code").await;
        let email =
            Email::parse(Secret::new("nonexistent_remove@example.com".to_string())).unwrap();

        // Should not error when removing non-existent code
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
    }
}
