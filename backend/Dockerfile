# syntax=docker/dockerfile:1.7

# ---- Build stage: compile wheels with build tooling that never ships ----
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# --extra-index-url points pip at PyTorch's CPU-only wheel index IN ADDITION
# to normal PyPI — torch resolves from there (a few hundred MB, no CUDA),
# everything else resolves from PyPI as usual. Without this, sentence-
# transformers' torch dependency pulls the ~2GB GPU build by default, which
# this project has no use for (no GPU in this Docker setup) and would
# roughly triple the image size for nothing.
RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /build/wheels \
       --extra-index-url https://download.pytorch.org/whl/cpu \
       -r requirements.txt

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
COPY --chown=secureai:secureai semgrep-rules ./semgrep-rules

# Upload/data directory owned by the app user, not world-writable
RUN mkdir -p /data/uploads && chown -R secureai:secureai /data

# HuggingFace/sentence-transformers cache directory — the secureai user has
# no home directory (--no-create-home above), so HF_HOME must be set
# explicitly or model downloads have nowhere sane to go.
ENV HF_HOME=/app/.cache/huggingface
RUN mkdir -p /app/.cache/huggingface && chown -R secureai:secureai /app/.cache

USER secureai

# Pre-download the local embedding model's weights at build time, so a
# freshly-started container never needs internet access to fetch them and
# the first real ingestion request isn't slowed down by a cold download.
# This hardcodes the model name rather than reading LOCAL_EMBEDDING_MODEL
# from .env (Docker build args would be needed for that) — if you change
# that setting to a different model, update this line to match, or accept
# a one-time runtime download as a fallback (local_provider.py handles
# that gracefully either way).
RUN python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-small-en-v1.5')"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# --proxy-headers only because TLS is terminated at the reverse proxy;
# workers count is intentionally modest for the demo — production sizing
# is discussed in documentation/architecture/phase-1-architecture.md.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
