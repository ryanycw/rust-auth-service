# rust-auth-service

A production-ready authentication service built with Rust, featuring JWT tokens, two-factor authentication, and comprehensive testing infrastructure.

## Setup & Building

```bash
cargo install cargo-watch
cd app-service
cargo build
cd ..
cd auth-service
cargo build
cd ..
```

## Run servers locally (Manually)

#### App service

```bash
cd app-service
cargo watch -q -c -w src/ -w assets/ -w templates/ -x run
```

visit http://localhost:8000

#### Auth service

```bash
cd auth-service
cargo watch -q -c -w src/ -w assets/ -x run
```

visit http://localhost:3000

## Run servers locally (Docker)

```bash
docker compose build
docker compose up
```

visit http://localhost:8000 and http://localhost:3000

## HTTPS Setup

**Prerequisites:** Ensure rust-acc.duckdns.org points to your server IP (64.227.24.69)

```bash
# Initialize SSL certificates with Let's Encrypt
./init-letsencrypt.sh

# Start production services with HTTPS
docker compose up -d
```

## Production

**HTTP (current):** http://64.227.24.69:8000/ and http://64.227.24.69:3000  
**HTTPS:** 
- App service: https://rust-acc.duckdns.org/app
- Auth service: https://rust-acc.duckdns.org/auth
- Root (app): https://rust-acc.duckdns.org
