#[derive(Debug)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidInput,
    IncorrectCredentials,
    InvalidCredentials,
    UnexpectedError,
    InvalidToken,
    MissingToken,
}
