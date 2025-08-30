use super::Email;
use color_eyre::eyre::{Report, Result};
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LoginAttempt {
    pub email: Email,
    pub timestamp: SystemTime,
    pub success: bool,
}

impl LoginAttempt {
    pub fn new(email: Email, success: bool) -> Self {
        Self {
            email,
            timestamp: SystemTime::now(),
            success,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoginAttemptSummary {
    pub failed_attempts: u32,
    pub requires_recaptcha: bool,
    pub last_attempt: Option<SystemTime>,
}

impl LoginAttemptSummary {
    pub fn new() -> Self {
        Self {
            failed_attempts: 0,
            requires_recaptcha: false,
            last_attempt: None,
        }
    }

    pub fn add_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        self.last_attempt = Some(SystemTime::now());
        self.requires_recaptcha = self.failed_attempts >= 3;
    }

    pub fn reset_on_success(&mut self) {
        self.failed_attempts = 0;
        self.requires_recaptcha = false;
        self.last_attempt = Some(SystemTime::now());
    }

    pub fn is_expired(&self, expiry_duration: Duration) -> bool {
        match self.last_attempt {
            Some(last) => SystemTime::now()
                .duration_since(last)
                .map(|duration| duration > expiry_duration)
                .unwrap_or(true),
            None => true,
        }
    }
}

impl Default for LoginAttemptSummary {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
pub trait LoginAttemptStore {
    async fn record_attempt(&mut self, attempt: LoginAttempt)
        -> Result<(), LoginAttemptStoreError>;
    async fn get_attempt_summary(
        &self,
        email: &Email,
    ) -> Result<LoginAttemptSummary, LoginAttemptStoreError>;
    async fn reset_attempts(&mut self, email: &Email) -> Result<(), LoginAttemptStoreError>;
}

#[derive(Debug, Error)]
pub enum LoginAttemptStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_attempt_summary_requires_recaptcha_after_three_failures() {
        let mut summary = LoginAttemptSummary::new();

        assert!(!summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 0);

        summary.add_failed_attempt();
        assert!(!summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 1);

        summary.add_failed_attempt();
        assert!(!summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 2);

        summary.add_failed_attempt();
        assert!(summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 3);
    }

    #[test]
    fn test_login_attempt_summary_reset_on_success() {
        let mut summary = LoginAttemptSummary::new();

        summary.add_failed_attempt();
        summary.add_failed_attempt();
        summary.add_failed_attempt();

        assert!(summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 3);

        summary.reset_on_success();

        assert!(!summary.requires_recaptcha);
        assert_eq!(summary.failed_attempts, 0);
    }

    #[test]
    fn test_login_attempt_expiry() {
        let mut summary = LoginAttemptSummary::new();

        // New summary should be considered expired
        assert!(summary.is_expired(Duration::from_secs(3600)));

        summary.add_failed_attempt();

        // Recent attempt should not be expired
        assert!(!summary.is_expired(Duration::from_secs(3600)));

        // Should be expired if we check with zero duration
        assert!(summary.is_expired(Duration::ZERO));
    }
}
