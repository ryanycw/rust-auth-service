use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid credentials")]
    IncorrectCredentials,
    #[error("Incorrect credentials")]
    InvalidCredentials,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing token")]
    MissingToken,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
