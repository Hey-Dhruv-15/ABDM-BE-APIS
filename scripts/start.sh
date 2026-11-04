#!/bin/bash
set -e

# Production-ready startup script for the gateway

echo "Starting Interoperability Gateway..."

# Select worker count based on CPU core count if not specified
WORKERS=${WORKERS:-$(nproc)}
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}

echo "Environment: ${APP_ENV:-development}"
echo "Workers: $WORKERS"

LOG_ARGS=""
if [ -f "app/logging/logging_config.json" ]; then
    LOG_ARGS="--log-config app/logging/logging_config.json"
fi

# Start the FastAPI application with Uvicorn
exec uvicorn app.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --workers "$WORKERS" \
    $LOG_ARGS \
    --proxy-headers \
    --forwarded-allow-ips='*'
