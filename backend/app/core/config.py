"""
Centralized application configuration.

All configuration is loaded from environment variables (see .env.example).
Nothing here is hardcoded. In production, APP_DEBUG must be false and
secrets must come from a real secrets manager (AWS Secrets Manager, Vault,
etc.) injected as env vars at deploy time — .env files are for local dev only.
"""
from functools import lru_cache
from typing import List, Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # --- App ---
    app_env: Literal["development", "staging", "production"] = "development"
    app_debug: bool = False
    app_name: str = "SecureAI Lab"
    api_v1_prefix: str = "/api/v1"
    frontend_origin: str = "http://localhost:5173"

    # --- Database ---
    database_url: str

    # --- JWT ---
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # --- Password / lockout policy ---
    account_lockout_threshold: int = 5
    account_lockout_window_minutes: int = 15
    account_lockout_duration_minutes: int = 30

    # --- MFA ---
    mfa_issuer_name: str = "SecureAI Lab"
    mfa_encryption_key: str

    # --- Field encryption ---
    field_encryption_key: str

    # --- Rate limiting ---
    rate_limit_per_minute: int = 60
    login_rate_limit_per_minute: int = 5
    upload_rate_limit_per_minute: int = 20
    redis_url: str = "redis://redis:6379/0"

    # --- CORS ---
    cors_allowed_origins: str = "http://localhost:5173"

    # --- AI ---
    ai_provider: Literal["openai", "local"] = "local"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    # Embeddings have their own provider switch, deliberately separate from
    # ai_provider above (which will govern Phase 4's chat model). This lets
    # you run local embeddings + OpenAI chat, or any other combination,
    # without the two being coupled — exactly the setup recommended for
    # this project: local embeddings for the privacy/no-external-call
    # story, independent of whatever chat model Phase 4 ends up using.
    embedding_provider: Literal["openai", "local"] = "local"
    openai_embedding_model: str = "text-embedding-3-small"
    local_embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dimensions: int = 1536
    local_llm_base_url: str = "http://ollama:11434/v1"
    # llama3.2:3b, not the originally-referenced 8b model — meaningfully
    # lighter for CPU-only inference (this stack has no GPU), while still
    # producing coherent responses. Swappable via .env once you've
    # confirmed your hardware handles it; see Phase 4 walkthrough.
    local_llm_model: str = "llama3.2:3b"

    # --- Vector DB ---
    chroma_host: str = "vector-db"
    chroma_port: int = 8000
    chroma_auth_token: str = ""
    chroma_collection_name: str = "document_chunks"

    # --- RAG ingestion/retrieval ---
    rag_chunk_size_tokens: int = 500
    rag_chunk_overlap_tokens: int = 50
    rag_retrieval_top_k: int = 5

    # --- AI Assistant (Phase 4) ---
    assistant_max_history_messages: int = 10
    assistant_max_response_tokens: int = 800
    assistant_use_rag_context: bool = True

    # --- Uploads ---
    max_upload_size_mb: int = 25
    upload_storage_path: str = "/data/uploads"
    allowed_upload_extensions: str = ".pdf,.docx,.txt"

    # --- Storage backend ---
    # 'local' writes encrypted blobs to a Docker volume — fine for this
    # local dev environment. 's3' targets any S3-compatible object store
    # (AWS S3, Cloudflare R2, Backblaze B2, DigitalOcean Spaces, MinIO) via
    # a configurable endpoint URL, which is what lets the backend run on
    # hosts like Fly.io/Railway/Render that don't offer persistent local
    # disk the way this dev compose stack does.
    storage_backend: Literal["local", "s3"] = "local"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "auto"
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""

    # --- ClamAV ---
    clamav_host: str = "clamav"
    clamav_port: int = 3310

    # --- Audit ---
    audit_log_retention_days: int = 365
    log_level: str = "INFO"

    @field_validator("jwt_secret_key")
    @classmethod
    def _reject_default_secret(cls, v: str) -> str:
        if v.lower().startswith("replace_with") or v == "":
            raise ValueError(
                "JWT_SECRET_KEY is still the placeholder value from .env.example. "
                "Generate a real secret with `openssl rand -hex 64`."
            )
        return v

    @field_validator("field_encryption_key")
    @classmethod
    def _validate_field_encryption_key(cls, v: str) -> str:
        # This key backs AES-256-GCM for file-content encryption at rest
        # (see core/file_encryption.py) — it must be exactly 32 raw bytes,
        # hex-encoded (64 hex characters), NOT a Fernet-format key. Fernet
        # keys are base64, 44 characters, and internally only use a 128-bit
        # AES key — that doesn't satisfy an "AES-256 at rest" requirement,
        # which is why file encryption uses this separate, explicitly-typed
        # key rather than reusing MFA_ENCRYPTION_KEY's Fernet key.
        if v == "" or v.lower().startswith("replace_with"):
            raise ValueError(
                "FIELD_ENCRYPTION_KEY is still a placeholder. Generate one with "
                "`openssl rand -hex 32` (NOT the Fernet-key command used for "
                "MFA_ENCRYPTION_KEY — this one must be raw hex)."
            )
        try:
            raw = bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError(
                "FIELD_ENCRYPTION_KEY must be a 64-character hex string. "
                "Generate one with `openssl rand -hex 32`."
            ) from exc
        if len(raw) != 32:
            raise ValueError(
                f"FIELD_ENCRYPTION_KEY must decode to exactly 32 bytes (got {len(raw)}). "
                "Generate one with `openssl rand -hex 32`."
            )
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def allowed_upload_extensions_list(self) -> List[str]:
        return [e.strip().lower() for e in self.allowed_upload_extensions.split(",") if e.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
