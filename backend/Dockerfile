# syntax=docker/dockerfile:1.7

# ---- Build stage: compile wheels with build tooling that never ships ----
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# PyTorch is no longer a dependency: local embeddings run on ONNX Runtime
# (see app/services/embeddings/local_provider.py), so the CPU-only torch
# wheel index this step used to need is gone.
RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /build/wheels \
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
# Runtime stage previously had no pip upgrade step at all - it silently
# inherited whatever pip version happened to ship baked into the base
# image, which Trivy flagged with 5 known CVEs (path traversal via
# malicious entry point names, wheel extraction path traversal, symlink
# extraction checks, import-timing arbitrary code execution). The
# builder stage self-upgrades pip too, but that pip is discarded -
# only the wheels it built get copied forward, not pip itself.
RUN pip install --no-cache-dir --upgrade "pip>=26.2.1"
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

# Pre-download the local embedding model's ONNX weights and tokenizer at
# build time, so a running container never fetches anything: HF_HUB_OFFLINE
# below makes that a guarantee rather than a hope (the local container's
# filesystem is read-only, and on Render a runtime download would repeat on
# every restart). This hardcodes the model name rather than reading
# LOCAL_EMBEDDING_MODEL from .env - if you change that setting, update this
# line to match.
RUN python3 -c "from huggingface_hub import hf_hub_download; [hf_hub_download('BAAI/bge-small-en-v1.5', f) for f in ('onnx/model.onnx', 'tokenizer.json')]"
ENV HF_HUB_OFFLINE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# --proxy-headers only because TLS is terminated at the reverse proxy;
# workers count is intentionally modest for the demo — production sizing
# is discussed in documentation/architecture/phase-1-architecture.md.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
