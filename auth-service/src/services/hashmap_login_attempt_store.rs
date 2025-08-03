use std::collections::HashMap;
use std::time::Duration;

use crate::domain::{
    Email, LoginAttempt, LoginAttemptStore, LoginAttemptStoreError, LoginAttemptSummary,
};

#[derive(Default)]
pub struct HashmapLoginAttemptStore {
    attempts: HashMap<Email, LoginAttemptSummary>,
    cleanup_expiry: Duration,
}

impl HashmapLoginAttemptStore {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            cleanup_expiry: Duration::from_secs(3600), // 1 hour expiry
        }
    }

    pub fn with_expiry(expiry: Duration) -> Self {
        Self {
            attempts: HashMap::new(),
            cleanup_expiry: expiry,
        }
    }

    fn cleanup_expired_attempts(&mut self) {
        self.attempts
            .retain(|_, summary| !summary.is_expired(self.cleanup_expiry));
    }
}

#[async_trait::async_trait]
impl LoginAttemptStore for HashmapLoginAttemptStore {
    async fn record_attempt(
        &mut self,
        attempt: LoginAttempt,
    ) -> Result<(), LoginAttemptStoreError> {
        self.cleanup_expired_attempts();

        let summary = self.attempts.entry(attempt.email.clone()).or_default();

        if attempt.success {
            summary.reset_on_success();
        } else {
            summary.add_failed_attempt();
        }

        Ok(())
    }

    async fn get_attempt_summary(
        &self,
        email: &Email,
    ) -> Result<LoginAttemptSummary, LoginAttemptStoreError> {
        let summary = self.attempts.get(email).cloned().unwrap_or_default();

        // Check if expired and return default if so
        if summary.is_expired(self.cleanup_expiry) {
            Ok(LoginAttemptSummary::default())
        } else {
            Ok(summary)
        }
    }

    async fn reset_attempts(&mut self, email: &Email) -> Result<(), LoginAttemptStoreError> {
        if let Some(summary) = self.attempts.get_mut(email) {
            summary.reset_on_success();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Email;

    async fn create_email(email_str: &str) -> Email {
        Email::parse(email_str.to_string()).unwrap()
    }

    #[tokio::test]
    async fn test_record_failed_attempt() {
        let mut store = HashmapLoginAttemptStore::new();
        let email = create_email("test@example.com").await;

        let attempt = LoginAttempt::new(email.clone(), false);
        store.record_attempt(attempt).await.unwrap();

        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert_eq!(summary.failed_attempts, 1);
        assert!(!summary.requires_recaptcha);
    }

    #[tokio::test]
    async fn test_requires_recaptcha_after_three_failures() {
        let mut store = HashmapLoginAttemptStore::new();
        let email = create_email("test@example.com").await;

        // Record 3 failed attempts
        for _ in 0..3 {
            let attempt = LoginAttempt::new(email.clone(), false);
            store.record_attempt(attempt).await.unwrap();
        }

        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert_eq!(summary.failed_attempts, 3);
        assert!(summary.requires_recaptcha);
    }

    #[tokio::test]
    async fn test_reset_on_successful_login() {
        let mut store = HashmapLoginAttemptStore::new();
        let email = create_email("test@example.com").await;

        // Record 3 failed attempts
        for _ in 0..3 {
            let attempt = LoginAttempt::new(email.clone(), false);
            store.record_attempt(attempt).await.unwrap();
        }

        // Verify requires reCAPTCHA
        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert!(summary.requires_recaptcha);

        // Record successful attempt
        let success_attempt = LoginAttempt::new(email.clone(), true);
        store.record_attempt(success_attempt).await.unwrap();

        // Verify reset
        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert_eq!(summary.failed_attempts, 0);
        assert!(!summary.requires_recaptcha);
    }

    #[tokio::test]
    async fn test_explicit_reset_attempts() {
        let mut store = HashmapLoginAttemptStore::new();
        let email = create_email("test@example.com").await;

        // Record failed attempts
        for _ in 0..3 {
            let attempt = LoginAttempt::new(email.clone(), false);
            store.record_attempt(attempt).await.unwrap();
        }

        // Explicitly reset
        store.reset_attempts(&email).await.unwrap();

        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert_eq!(summary.failed_attempts, 0);
        assert!(!summary.requires_recaptcha);
    }

    #[tokio::test]
    async fn test_expired_attempts_cleanup() {
        let mut store = HashmapLoginAttemptStore::with_expiry(Duration::from_millis(10));
        let email = create_email("test@example.com").await;

        // Record failed attempt
        let attempt = LoginAttempt::new(email.clone(), false);
        store.record_attempt(attempt).await.unwrap();

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Get summary should return default (expired)
        let summary = store.get_attempt_summary(&email).await.unwrap();
        assert_eq!(summary.failed_attempts, 0);
        assert!(!summary.requires_recaptcha);
    }

    #[tokio::test]
    async fn test_different_emails_tracked_separately() {
        let mut store = HashmapLoginAttemptStore::new();
        let email1 = create_email("user1@example.com").await;
        let email2 = create_email("user2@example.com").await;

        // Record failures for email1
        for _ in 0..3 {
            let attempt = LoginAttempt::new(email1.clone(), false);
            store.record_attempt(attempt).await.unwrap();
        }

        // Record one failure for email2
        let attempt = LoginAttempt::new(email2.clone(), false);
        store.record_attempt(attempt).await.unwrap();

        let summary1 = store.get_attempt_summary(&email1).await.unwrap();
        let summary2 = store.get_attempt_summary(&email2).await.unwrap();

        assert_eq!(summary1.failed_attempts, 3);
        assert!(summary1.requires_recaptcha);

        assert_eq!(summary2.failed_attempts, 1);
        assert!(!summary2.requires_recaptcha);
    }
}
