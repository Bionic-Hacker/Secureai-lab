"""
Security primitives: password hashing, JWT, MFA secret encryption,
opaque-token hashing for refresh/reset tokens.

Design decisions:
- Argon2id for password hashing (memory-hard, resists GPU cracking better
  than bcrypt at equivalent settings; OWASP's current recommendation).
- Refresh & password-reset tokens are random opaque strings; only their
  SHA-256 hash is stored, so a DB read/leak doesn't yield usable tokens.
- MFA TOTP secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC),
  not just hashed, because we need to decrypt them to verify TOTP codes.
- JWTs are short-lived access tokens only; long-lived sessions are backed
  by the server-side refresh_tokens table so they can be revoked.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHash
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

settings = get_settings()

_password_hasher = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, plain_password)
    except (VerificationError, InvalidHash):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the hash was made with weaker parameters than current policy."""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHash:
        return True


MIN_PASSWORD_LENGTH = 12


def validate_password_strength(password: str) -> Optional[str]:
    """Returns an error message if the password fails policy, else None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    checks = [
        (any(c.islower() for c in password), "a lowercase letter"),
        (any(c.isupper() for c in password), "an uppercase letter"),
        (any(c.isdigit() for c in password), "a digit"),
        (any(not c.isalnum() for c in password), "a special character"),
    ]
    missing = [label for ok, label in checks if not ok]
    if missing:
        return f"Password must contain at least {', '.join(missing)}."
    return None


# --------------------------------------------------------------------------
# JWT access tokens
# --------------------------------------------------------------------------
def create_access_token(subject: str, role: str, extra_claims: Optional[dict] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "jti": secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on invalid/expired/tampered tokens."""
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Not an access token")
    return payload


# --------------------------------------------------------------------------
# Opaque tokens (refresh tokens, password reset tokens) — random, stored
# only as a hash. This means a leaked DB row cannot be replayed as a token.
# --------------------------------------------------------------------------
def generate_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def hash_opaque_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# MFA secret encryption at rest
# --------------------------------------------------------------------------
_fernet = Fernet(settings.mfa_encryption_key.encode("utf-8"))


def encrypt_mfa_secret(secret: str) -> str:
    return _fernet.encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_mfa_secret(token: str) -> str:
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("MFA secret could not be decrypted — possible key rotation mismatch") from exc


def hash_recovery_code(code: str) -> str:
    # Recovery codes are short but single-use and rate-limited at the
    # endpoint, so a fast hash (SHA-256) is acceptable here — unlike
    # passwords, they are high-entropy random strings, not user-chosen.
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
