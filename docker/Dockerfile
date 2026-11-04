# Production-ready Dockerfile for Interoperability Gateway
# Stage 1: Build
FROM python:3.11-slim-bookworm AS builder

# Set directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy project files
COPY pyproject.toml .
COPY README.md .

# Install dependencies into a virtual environment
RUN uv venv .venv && \
    uv pip install -e .

# Stage 2: Runtime
FROM python:3.11-slim-bookworm AS runtime

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Copy virtual environment from builder
COPY --from=builder /build/.venv /app/.venv

# Copy application code
COPY app /app/app
COPY scripts /app/scripts

# Fix permissions
RUN chmod +x /app/scripts/start.sh

# Expose ports (HTTP + MLLP default)
EXPOSE 8000
EXPOSE 2575

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Entrypoint
ENTRYPOINT ["/app/scripts/start.sh"]
