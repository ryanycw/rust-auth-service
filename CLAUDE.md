# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Architecture

This is a **two-service Rust authentication system** with distinct responsibilities:

### Services Overview
- **auth-service** (port 3000): Core authentication API with user management, login/logout, JWT tokens, and 2FA
- **app-service** (port 8000): Frontend web application that consumes the auth service
- **nginx**: Reverse proxy handling routing and SSL termination
- **certbot**: SSL certificate management

### Auth Service Structure
- **Domain Layer** (`src/domain/`): Core business logic and types
  - `User`: struct with Email, Password, and 2FA flag
  - `Email` and `Password`: value objects with validation
  - `UserStore` trait: async interface for user persistence
  - `UserStoreError`: domain-specific error types
- **Services Layer** (`src/services/`): Implementation of domain traits
  - `HashmapUserStore`: in-memory HashMap implementation of UserStore
- **Routes Layer** (`src/routes/`): HTTP endpoint handlers
  - Current routes: `/signup`, `/login`, `/logout`, `/verify-2fa`, `/verify-token`
- **Main Application**: `Application` struct encapsulating server setup and routing

### Key Design Patterns
- **Repository Pattern**: `UserStore` trait abstracts storage implementation
- **Type Safety**: Strong types for Email and Password with validation
- **Async/Await**: Throughout the application using tokio
- **State Management**: Shared `AppState` with `Arc<RwLock<HashmapUserStore>>`

## Development Commands

### Build and Development
```bash
# Build auth service
cd auth-service && cargo build

# Build app service  
cd app-service && cargo build

# Run auth service with hot reload
cd auth-service && cargo watch -q -c -w src/ -w assets/ -x run

# Run app service with hot reload
cd app-service && cargo watch -q -c -w src/ -w assets/ -w templates/ -x run
```

### Testing
```bash
# Run auth service tests
cd auth-service && cargo test

# Run API integration tests
cd auth-service && cargo test --test api
```

### Docker Operations
```bash
# Local development with Docker
docker compose build && docker compose up

# Production deployment
./init-letsencrypt.sh  # Initialize SSL certificates
docker compose up -d   # Run with HTTPS
```

## Storage Implementation

Currently uses **in-memory HashMap storage** via `HashmapUserStore`. The `UserStore` trait design allows easy migration to persistent storage (PostgreSQL, etc.) in future iterations.

## API Endpoints (Auth Service)

- `POST /signup` - Create new user account
- `POST /login` - Authenticate user
- `POST /logout` - End user session  
- `POST /verify-2fa` - Two-factor authentication verification
- `POST /verify-token` - JWT token validation
- Static assets served from `/assets/`

## Testing Infrastructure

- **Unit Tests**: Comprehensive tests in `HashmapUserStore` and domain types
- **Integration Tests**: API endpoint testing in `tests/api/` using `TestApp` helper
- **Test Utilities**: `helpers.rs` provides `TestApp` for spawning test servers and `get_random_email()` for unique test data

## Development Notes

- All user data validation occurs at the domain layer through Email and Password types
- Password validation includes complexity requirements (implemented in Password struct)
- Email validation uses regex patterns (implemented in Email struct)  
- Error handling follows domain-driven design with `AuthAPIError` mapping to HTTP responses
- The system is designed for future extension (database integration, additional auth methods, etc.)