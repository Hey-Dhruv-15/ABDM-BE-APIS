# =========================
# Stage 1: Builder
# =========================
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy package metadata
COPY pyproject.toml .
COPY README.md .

# Copy application source because the package is "app"
COPY app ./app

# Create virtual environment at a fixed path
RUN uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python .


# =========================
# Stage 2: Runtime
# =========================
FROM python:3.11-slim-bookworm AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Copy virtual environment to the SAME path
COPY --from=builder /opt/venv /opt/venv

# Copy application
COPY app /app/app
COPY scripts /app/scripts

RUN chmod +x /app/scripts/start.sh

EXPOSE 8000

HEALTHCHECK --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["/app/scripts/start.sh"]
