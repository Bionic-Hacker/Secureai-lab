# syntax=docker/dockerfile:1.7

# ---- Build stage: compile wheels with build tooling that never ships ----
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# ---- Runtime stage: minimal, non-root, no compilers ----
FROM python:3.12-slim-bookworm AS runtime

# Runtime-only shared libs (libpq for asyncpg's libpq bindings if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libmagic1 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 secureai \
    && useradd --uid 10001 --gid secureai --shell /usr/sbin/nologin --no-create-home secureai

WORKDIR /app

COPY --from=builder /build/wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY --chown=secureai:secureai app ./app
COPY --chown=secureai:secureai alembic.ini ./alembic.ini
COPY --chown=secureai:secureai alembic ./alembic

# Upload/data directory owned by the app user, not world-writable
RUN mkdir -p /data/uploads && chown -R secureai:secureai /data

USER secureai

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# --proxy-headers only because TLS is terminated at the reverse proxy;
# workers count is intentionally modest for the demo — production sizing
# is discussed in documentation/architecture/phase-1-architecture.md.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
