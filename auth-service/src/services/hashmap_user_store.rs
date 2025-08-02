use std::collections::HashMap;

use crate::domain::{user::User, UserStore, UserStoreError, Email, Password};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
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

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password != *password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_user(email: &str, password: &str) -> User {
        let email = Email::parse(email.to_string()).unwrap();
        let password = Password::parse(password.to_string()).unwrap();
        User::new(email, password, true)
    }

    #[tokio::test]
    async fn test_add_user_success() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("test@example.com", "Password123!").await;
        let email = user.email.clone();
        let password = user.password.clone();

        let result = user_store.add_user(user).await;
        assert!(result.is_ok());

        let stored_user = user_store.get_user(&email).await.unwrap();
        assert_eq!(stored_user.email, email);
        assert_eq!(stored_user.password, password);
    }

    #[tokio::test]
    async fn test_add_duplicate_user_fails() {
        let mut user_store = HashmapUserStore::default();
        let user1 = create_user("duplicate@example.com", "Password123!").await;
        let user2 = create_user("duplicate@example.com", "Different123!").await;

        assert!(user_store.add_user(user1).await.is_ok());

        let result = user_store.add_user(user2).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_get_existing_user() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("existing@example.com", "Password123!").await;
        let user_clone = user.clone();
        let email = user.email.clone();
        user_store.add_user(user).await.unwrap();

        let result = user_store.get_user(&email).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user_clone);
    }

    #[tokio::test]
    async fn test_get_non_existent_user() {
        let user_store = HashmapUserStore::default();
        let email = Email::parse("nonexistent@example.com".to_string()).unwrap();

        let result = user_store.get_user(&email).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_validate_user_correct_credentials() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("valid@example.com", "Correct123!").await;
        let email = user.email.clone();
        let password = user.password.clone();
        user_store.add_user(user).await.unwrap();

        let result = user_store
            .validate_user(&email, &password)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user_incorrect_password() {
        let mut user_store = HashmapUserStore::default();
        let user = create_user("user@example.com", "Correct123!").await;
        let email = user.email.clone();
        let wrong_password = Password::parse("Wrong456!".to_string()).unwrap();
        user_store.add_user(user).await.unwrap();

        let result = user_store
            .validate_user(&email, &wrong_password)
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_validate_non_existent_user() {
        let user_store = HashmapUserStore::default();
        let email = Email::parse("ghost@example.com".to_string()).unwrap();
        let password = Password::parse("AnyPass123!".to_string()).unwrap();

        let result = user_store
            .validate_user(&email, &password)
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UserStoreError::UserNotFound);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let mut user_store = HashmapUserStore::default();

        let user1 = create_user("user1@example.com", "Password1!").await;
        let user2 = create_user("user2@example.com", "Password2!").await;
        let user3 = create_user("user3@example.com", "Password3!").await;

        let email1 = user1.email.clone();
        let email2 = user2.email.clone();
        let email3 = user3.email.clone();
        let password1 = user1.password.clone();
        let password2 = user2.password.clone();
        let password3 = user3.password.clone();

        assert!(user_store.add_user(user1).await.is_ok());
        assert!(user_store.add_user(user2).await.is_ok());
        assert!(user_store.add_user(user3).await.is_ok());

        assert!(user_store.get_user(&email1).await.is_ok());
        assert!(user_store.get_user(&email2).await.is_ok());
        assert!(user_store.get_user(&email3).await.is_ok());

        assert!(user_store
            .validate_user(&email1, &password1)
            .await
            .is_ok());
        assert!(user_store
            .validate_user(&email2, &password2)
            .await
            .is_ok());
        assert!(user_store
            .validate_user(&email3, &password3)
            .await
            .is_ok());
    }
}
