use crate::domain::{
    RecaptchaError, RecaptchaToken, RecaptchaVerifyRequest, RecaptchaVerifyResponse,
};

#[async_trait::async_trait]
pub trait RecaptchaService {
    async fn verify_token(
        &self,
        token: &RecaptchaToken,
        user_ip: Option<String>,
    ) -> Result<(), RecaptchaError>;
}

pub struct GoogleRecaptchaService {
    secret_key: String,
    client: reqwest::Client,
}

impl GoogleRecaptchaService {
    pub fn new(secret_key: String) -> Self {
        Self {
            secret_key,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl RecaptchaService for GoogleRecaptchaService {
    async fn verify_token(
        &self,
        token: &RecaptchaToken,
        user_ip: Option<String>,
    ) -> Result<(), RecaptchaError> {
        let request = RecaptchaVerifyRequest {
            secret: self.secret_key.clone(),
            response: token.as_str().to_string(),
            remoteip: user_ip,
        };

        let response = self
            .client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&request)
            .send()
            .await
            .map_err(|_| RecaptchaError::NetworkError)?;

        let verify_response: RecaptchaVerifyResponse = response
            .json()
            .await
            .map_err(|_| RecaptchaError::UnexpectedError)?;

        if verify_response.success {
            Ok(())
        } else {
            // Check for specific error codes if needed
            if let Some(error_codes) = &verify_response.error_codes {
                if error_codes.contains(&"invalid-input-secret".to_string()) {
                    return Err(RecaptchaError::InvalidSecret);
                }
                if error_codes.contains(&"invalid-input-response".to_string()) {
                    return Err(RecaptchaError::InvalidToken);
                }
            }
            Err(RecaptchaError::VerificationFailed)
        }
    }
}

// Mock implementation for testing
pub struct MockRecaptchaService {
    should_succeed: bool,
}

impl MockRecaptchaService {
    pub fn new(should_succeed: bool) -> Self {
        Self { should_succeed }
    }
}

#[async_trait::async_trait]
impl RecaptchaService for MockRecaptchaService {
    async fn verify_token(
        &self,
        _token: &RecaptchaToken,
        _user_ip: Option<String>,
    ) -> Result<(), RecaptchaError> {
        if self.should_succeed {
            Ok(())
        } else {
            Err(RecaptchaError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_recaptcha_service_success() {
        let service = MockRecaptchaService::new(true);
        let token = RecaptchaToken::new("test_token".to_string()).unwrap();

        let result = service.verify_token(&token, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_recaptcha_service_failure() {
        let service = MockRecaptchaService::new(false);
        let token = RecaptchaToken::new("test_token".to_string()).unwrap();

        let result = service.verify_token(&token, None).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RecaptchaError::VerificationFailed);
    }
}
