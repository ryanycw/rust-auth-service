use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::app_state::BannedTokenStoreType;
use crate::config::AuthConfig;
use crate::domain::email::Email;

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie(
    email: &Email,
    auth_config: &AuthConfig,
) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email, auth_config)?;
    Ok(create_auth_cookie(
        token,
        auth_config.jwt_cookie_name.clone(),
    ))
}

// Create cookie and set the value to the passed-in token string
fn create_auth_cookie(token: String, cookie_name: String) -> Cookie<'static> {
    let cookie = Cookie::build((cookie_name, token))
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

// Create JWT auth token
fn generate_auth_token(
    email: &Email,
    auth_config: &AuthConfig,
) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(auth_config.token_ttl_seconds)
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

    create_token(&claims, auth_config).map_err(GenerateTokenError::TokenError)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
pub async fn validate_token(
    token: &str,
    banned_token_store: &BannedTokenStoreType,
    auth_config: &AuthConfig,
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
        &DecodingKey::from_secret(auth_config.jwt_secret.as_bytes()),
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
fn create_token(
    claims: &Claims,
    auth_config: &AuthConfig,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(auth_config.jwt_secret.as_bytes()),
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
    use crate::{
        config::{AuthConfig, Settings},
        services::RedisBannedTokenStore,
    };
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_auth_config() -> AuthConfig {
        let settings = Settings::new().expect("Failed to load test configuration");
        settings.auth
    }

    async fn create_test_banned_token_store(test_name: &str) -> BannedTokenStoreType {
        let settings = Settings::new().expect("Failed to load test configuration");
        let conn = crate::get_redis_connection(
            settings.redis.hostname.clone(),
            settings.redis.password.clone(),
        )
        .await
        .expect("Failed to get Redis connection");

        let conn = Arc::new(RwLock::new(conn));
        Arc::new(RwLock::new(
            RedisBannedTokenStore::new_with_config_and_prefix(
                conn,
                settings.redis.banned_token_ttl_seconds,
                settings.redis.banned_token_key_prefix,
                format!("test_{}:", test_name),
            ),
        ))
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let auth_config = create_test_auth_config();
        let cookie = generate_auth_cookie(&email, &auth_config).unwrap();
        assert_eq!(cookie.name(), auth_config.jwt_cookie_name);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let auth_config = create_test_auth_config();
        let cookie = create_auth_cookie(token.clone(), auth_config.jwt_cookie_name.clone());
        assert_eq!(cookie.name(), auth_config.jwt_cookie_name);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let auth_config = create_test_auth_config();
        let result = generate_auth_token(&email, &auth_config).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let auth_config = create_test_auth_config();
        let token = generate_auth_token(&email, &auth_config).unwrap();
        let banned_token_store = create_test_banned_token_store("validate_token_with_valid_token").await;

        let result = validate_token(&token, &banned_token_store, &auth_config)
            .await
            .unwrap();
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
        let auth_config = create_test_auth_config();
        let banned_token_store =
            create_test_banned_token_store("validate_token_with_invalid_token").await;

        let result = validate_token(&token, &banned_token_store, &auth_config).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidateTokenError::TokenError(_) => (),
            _ => panic!("Expected TokenError"),
        }
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let auth_config = create_test_auth_config();
        let token = generate_auth_token(&email, &auth_config).unwrap();
        let banned_token_store = create_test_banned_token_store("validate_token_with_banned_token").await;

        // First ban the token
        banned_token_store
            .write()
            .await
            .store_token(token.clone())
            .await
            .unwrap();

        // Then try to validate it
        let result = validate_token(&token, &banned_token_store, &auth_config).await;
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
        let auth_config = create_test_auth_config();
        let token1 = generate_auth_token(&email1, &auth_config).unwrap();
        let token2 = generate_auth_token(&email2, &auth_config).unwrap();
        let banned_token_store =
            create_test_banned_token_store("validate_token_with_valid_unbanned_token").await;

        // Ban only token1
        banned_token_store
            .write()
            .await
            .store_token(token1.clone())
            .await
            .unwrap();

        // token2 should still be valid
        let result = validate_token(&token2, &banned_token_store, &auth_config).await;
        assert!(result.is_ok());

        // token1 should be banned
        let result = validate_token(&token1, &banned_token_store, &auth_config).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidateTokenError::BannedToken => (),
            _ => panic!("Expected BannedToken error"),
        }
    }
}
