use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

/// Main application configuration
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub cors: CorsConfig,
}

/// Server configuration
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// Database configuration
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// Redis configuration  
#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub hostname: String,
    pub password: String,
    pub banned_token_ttl_seconds: u64,
    pub banned_token_key_prefix: String,
    pub two_fa_code_ttl_seconds: u64,
    pub two_fa_code_key_prefix: String,
}

/// Authentication configuration
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_cookie_name: String,
    pub token_ttl_seconds: i64,
}

/// CORS configuration
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origins: String,
}

impl DatabaseConfig {
    pub fn url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}",
            self.username, self.password, self.host, self.port
        )
    }
}

impl Settings {
    /// Load configuration from multiple sources in order of precedence:
    /// 1. Default values
    /// 2. Configuration files (config/default.toml, config/{environment}.toml)
    /// 3. Environment variables (prefixed with APP_)
    pub fn new() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        // Determine environment (default to "default")
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "default".into());

        let mut builder = Config::builder()
            // Start with default values
            .add_source(File::with_name("config/default").required(false))
            // Add environment-specific configuration
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            // Add environment variables with prefix APP_ (highest precedence)
            .add_source(Environment::with_prefix("APP").separator("__"));

        // Manually override specific environment variables to ensure precedence
        // This is needed because Environment source doesn't always take precedence over file sources
        for (key, value) in env::vars() {
            if let Some(stripped) = key.strip_prefix("APP_") {
                let config_key = stripped.replace("__", ".").to_lowercase();
                let target_key = match key.as_str() {
                    "APP_POSTGRES__PASSWORD" => "database.password",
                    _ => &config_key,
                };
                builder = builder.set_override(target_key, value)?;
            }
        }

        let config = builder.build()?;
        config.try_deserialize()
    }

    /// Get the complete server address (host:port)
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_configuration() {
        let settings = Settings::new().unwrap();
        assert_eq!(settings.server.host, "127.0.0.1");
        assert_eq!(settings.server.port, 0);
        assert_eq!(settings.auth.jwt_cookie_name, "jwt");
        assert_eq!(settings.auth.token_ttl_seconds, 600);
        assert_eq!(settings.redis.hostname, "127.0.0.1");
        assert_eq!(settings.redis.banned_token_ttl_seconds, 600);
        assert_eq!(settings.redis.banned_token_key_prefix, "banned_token:");
        assert_eq!(settings.redis.two_fa_code_ttl_seconds, 600);
        assert_eq!(settings.redis.two_fa_code_key_prefix, "two_fa_code:");
    }

    #[test]
    fn test_server_address() {
        let settings = Settings::new().unwrap();
        assert_eq!(settings.server_address(), "127.0.0.1:0");
    }
}
