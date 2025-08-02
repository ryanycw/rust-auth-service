use std::collections::HashMap;

use crate::domain::{user::User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_user(email: &str, password: &str) -> User {
        User::new(email.to_string(), password.to_string(), true)
    }

    #[tokio::test]
    async fn test_add_user_success() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("test@example.com", "password123").await;
        let email = user.email.clone();
        let password = user.password.clone();

        let result = user_store.add_user(user).await;
        assert!(result.is_ok());

        let stored_user = user_store.get_user("test@example.com").await.unwrap();
        assert_eq!(stored_user.email, email);
        assert_eq!(stored_user.password, password);
    }

    #[tokio::test]
    async fn test_add_duplicate_user_fails() {
        let mut user_store = HashmapUserStore::default();
        let user1 = create_user("duplicate@example.com", "password123").await;
        let user2 = create_user("duplicate@example.com", "different_password").await;

        assert!(user_store.add_user(user1).await.is_ok());

        let result = user_store.add_user(user2).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_existing_user() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("existing@example.com", "password123").await;
        let user_clone = user.clone();
        user_store.add_user(user).await.unwrap();

        let result = user_store.get_user("existing@example.com").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_clone);
    }

    #[tokio::test]
    async fn test_get_non_existent_user() {
        let user_store = HashmapUserStore::default();

        let result = user_store.get_user("nonexistent@example.com").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_validate_user_correct_credentials() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("valid@example.com", "correct_password").await;
        user_store.add_user(user).await.unwrap();

        let result = user_store
            .validate_user("valid@example.com", "correct_password")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user_incorrect_password() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("user@example.com", "correct_password").await;
        user_store.add_user(user).await.unwrap();

        let result = user_store
            .validate_user("user@example.com", "wrong_password")
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_validate_non_existent_user() {
        let user_store = HashmapUserStore::default();

        let result = user_store
            .validate_user("ghost@example.com", "any_password")
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let mut user_store = HashmapUserStore::default();

        let user1 = create_user("user1@example.com", "password1").await;
        let user2 = create_user("user2@example.com", "password2").await;
        let user3 = create_user("user3@example.com", "password3").await;

        assert!(user_store.add_user(user1).await.is_ok());
        assert!(user_store.add_user(user2).await.is_ok());
        assert!(user_store.add_user(user3).await.is_ok());

        assert!(user_store.get_user("user1@example.com").await.is_ok());
        assert!(user_store.get_user("user2@example.com").await.is_ok());
        assert!(user_store.get_user("user3@example.com").await.is_ok());

        assert!(user_store
            .validate_user("user1@example.com", "password1")
            .await
            .is_ok());
        assert!(user_store
            .validate_user("user2@example.com", "password2")
            .await
            .is_ok());
        assert!(user_store
            .validate_user("user3@example.com", "password3")
            .await
            .is_ok());
    }
}
