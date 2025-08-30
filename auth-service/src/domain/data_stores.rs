use super::{Email, Password, User};
use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use thiserror::Error;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
    async fn delete_user(
        &mut self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(Self(parsed_id.to_string()))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        LoginAttemptId(uuid::Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;

        match (100_000..=999_999).contains(&code_as_u32) {
            true => Ok(Self(code)),
            false => Err(eyre!("Invalid 2FA code")),
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let mut rng = rand::thread_rng();
        let code = rng.gen_range(100000..1000000).to_string();
        TwoFACode(code)
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
