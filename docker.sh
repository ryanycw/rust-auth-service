#!/bin/bash

# Script for local development - runs without SSL certificates
echo "Starting local development environment..."

# Set environment variables for local development
export RUN_MODE=development
export REDIS_PASSWORD=password
export POSTGRES_PASSWORD=password

# Run docker compose with local override
docker compose -f compose.yml -f compose.local.yml up --build "$@"