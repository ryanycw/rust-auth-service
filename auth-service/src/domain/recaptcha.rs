use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub struct RecaptchaToken(String);

impl RecaptchaToken {
    pub fn new(token: String) -> Result<Self, RecaptchaTokenError> {
        if token.trim().is_empty() {
            return Err(RecaptchaTokenError::EmptyToken);
        }
        Ok(RecaptchaToken(token))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum RecaptchaTokenError {
    EmptyToken,
}

#[derive(Serialize)]
pub struct RecaptchaVerifyRequest {
    pub secret: String,
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remoteip: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct RecaptchaVerifyResponse {
    pub success: bool,
    #[serde(rename = "challenge_ts")]
    pub challenge_timestamp: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Option<Vec<String>>,
}

#[derive(Debug, PartialEq)]
pub enum RecaptchaError {
    InvalidToken,
    VerificationFailed,
    NetworkError,
    InvalidSecret,
    UnexpectedError,
}

impl std::fmt::Display for RecaptchaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecaptchaError::InvalidToken => write!(f, "Invalid reCAPTCHA token"),
            RecaptchaError::VerificationFailed => write!(f, "reCAPTCHA verification failed"),
            RecaptchaError::NetworkError => {
                write!(f, "Network error during reCAPTCHA verification")
            }
            RecaptchaError::InvalidSecret => write!(f, "Invalid reCAPTCHA secret"),
            RecaptchaError::UnexpectedError => {
                write!(f, "Unexpected error during reCAPTCHA verification")
            }
        }
    }
}

impl std::error::Error for RecaptchaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_recaptcha_token() {
        let token = RecaptchaToken::new("valid_token_123".to_string());
        assert!(token.is_ok());
        assert_eq!(token.unwrap().as_str(), "valid_token_123");
    }

    #[test]
    fn test_empty_recaptcha_token() {
        let token = RecaptchaToken::new("".to_string());
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), RecaptchaTokenError::EmptyToken);
    }

    #[test]
    fn test_whitespace_only_recaptcha_token() {
        let token = RecaptchaToken::new("   ".to_string());
        assert!(token.is_err());
        assert_eq!(token.unwrap_err(), RecaptchaTokenError::EmptyToken);
    }
}
