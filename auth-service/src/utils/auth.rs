use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::domain::email::Email;
use crate::app_state::BannedTokenStoreType;

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apple cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
fn generate_auth_token(email: &Email) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or(GenerateTokenError::UnexpectedError)?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError)?;

    let sub = email.as_ref().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims).map_err(GenerateTokenError::TokenError)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
pub async fn validate_token(
    token: &str,
    banned_token_store: &BannedTokenStoreType,
) -> Result<Claims, ValidateTokenError> {
    // Check if token is banned first
    let is_banned = banned_token_store
        .read()
        .await
        .contains_token(token)
        .await
        .map_err(|_| ValidateTokenError::UnexpectedError)?;

    if is_banned {
        return Err(ValidateTokenError::BannedToken);
    }

    // Validate token signature and expiration
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(ValidateTokenError::TokenError)
}

#[derive(Debug)]
pub enum ValidateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    BannedToken,
    UnexpectedError,
}

// Create JWT auth token by encoding claims using the JWT secret
fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::HashsetBannedTokenStore;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_banned_token_store() -> BannedTokenStoreType {
        Arc::new(RwLock::new(HashsetBannedTokenStore::default()))
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_token_store = create_test_banned_token_store();
        
        let result = validate_token(&token, &banned_token_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let banned_token_store = create_test_banned_token_store();
        
        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidateTokenError::TokenError(_) => (),
            _ => panic!("Expected TokenError"),
        }
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_token_store = create_test_banned_token_store();
        
        // First ban the token
        banned_token_store
            .write()
            .await
            .store_token(token.clone())
            .await
            .unwrap();
        
        // Then try to validate it
        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidateTokenError::BannedToken => (),
            _ => panic!("Expected BannedToken error"),
        }
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_unbanned_token() {
        let email1 = Email::parse("test1@example.com".to_owned()).unwrap();
        let email2 = Email::parse("test2@example.com".to_owned()).unwrap();
        let token1 = generate_auth_token(&email1).unwrap();
        let token2 = generate_auth_token(&email2).unwrap();
        let banned_token_store = create_test_banned_token_store();
        
        // Ban only token1
        banned_token_store
            .write()
            .await
            .store_token(token1.clone())
            .await
            .unwrap();
        
        // token2 should still be valid
        let result = validate_token(&token2, &banned_token_store).await;
        assert!(result.is_ok());
        
        // token1 should be banned
        let result = validate_token(&token1, &banned_token_store).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidateTokenError::BannedToken => (),
            _ => panic!("Expected BannedToken error"),
        }
    }
}
