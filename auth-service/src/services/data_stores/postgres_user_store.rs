use std::error::Error;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::thread_rng;
use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        let result = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.constraint() == Some("users_pkey") => {
                Err(UserStoreError::UserAlreadyExists)
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let result = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => {
                let email = Email::parse(row.email).map_err(|_| UserStoreError::UnexpectedError)?;
                let password = Password::from_hash(row.password_hash);
                Ok(User::new(email, password, row.requires_2fa))
            }
            Err(sqlx::Error::RowNotFound) => Err(UserStoreError::UserNotFound),
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let result = sqlx::query!(
            "SELECT password_hash FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => verify_password_hash(row.password_hash, password.as_ref().to_string())
                .await
                .map_err(|_| UserStoreError::InvalidCredentials),
            Err(sqlx::Error::RowNotFound) => Err(UserStoreError::UserNotFound),
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn delete_user(
        &mut self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        // First validate the user credentials
        self.validate_user(email, password).await?;

        let result = sqlx::query!("DELETE FROM users WHERE email = $1", email.as_ref())
            .execute(&self.pool)
            .await;

        match result {
            Ok(query_result) => {
                if query_result.rows_affected() == 0 {
                    Err(UserStoreError::UserNotFound)
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }
}

// Helper function to verify if a given password matches an expected hash
#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let current_span: tracing::Span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            // New!
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .map_err(|e| e.into())
        })
    })
    .await;

    result?
}

// Helper function to hash passwords before persisting them in the database.
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(
    password: String,
) -> Result<String, Box<dyn Error + Send + Sync + 'static>> {
    let current_span: tracing::Span = tracing::Span::current();
    let hash = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt = argon2::password_hash::SaltString::generate(&mut thread_rng());
            let password_hash = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
            Ok(password_hash)
        })
    })
    .await;

    hash?
}
