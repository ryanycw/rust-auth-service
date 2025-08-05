#!/bin/bash

# Script for local development - runs without SSL certificates

# Set JWT_SECRET for local development
export JWT_SECRET="your-256-bit-secret-for-local-dev"

echo "Starting local development environment..."

# Run docker compose with local override
docker compose -f compose.yml -f compose.local.yml up --build "$@"