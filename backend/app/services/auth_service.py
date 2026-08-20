"""
Auth business logic, kept separate from the HTTP layer so it's independently
testable and so the endpoints stay thin.

Key security behaviors implemented here:
- Constant-shape responses for "user not found" vs "wrong password" (no
  user enumeration via error messages or timing — see login()).
- Account lockout after N failed attempts within a rolling window.
- MFA (TOTP) required on login when enabled, checked AFTER password
  verification succeeds (never reveal MFA status before proving password
  knowledge).
- Refresh token rotation: each refresh issues a new refresh token and
  revokes the old one, with `replaced_by` chaining. Reuse of an already-
  rotated (revoked) refresh token revokes the entire token family —
  a strong signal of token theft.
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    hash_recovery_code,
    verify_password,
)
from app.models.token import RefreshToken
from app.models.user import User

settings = get_settings()


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class MfaRequiredError(Exception):
    """Raised to signal the client must resubmit login with an MFA code."""


async def register_user(db: AsyncSession, email: str, display_name: str, password: str) -> User:
    existing = await db.execute(select(User).where(User.email == email.lower()))
    if existing.scalar_one_or_none() is not None:
        # Generic message — do not reveal that this email is already registered.
        raise AuthError("Registration could not be completed with the provided details.", 400)

    user = User(
        email=email.lower(),
        display_name=display_name,
        password_hash=hash_password(password),
    )
    db.add(user)
    await db.flush()
    return user


async def _register_failed_attempt(db: AsyncSession, user: User) -> None:
    now = datetime.now(timezone.utc)
    window = timedelta(minutes=settings.account_lockout_window_minutes)

    if user.failed_login_window_start is None or (now - user.failed_login_window_start) > window:
        user.failed_login_attempts = 1
        user.failed_login_window_start = now
    else:
        user.failed_login_attempts += 1

    if user.failed_login_attempts >= settings.account_lockout_threshold:
        user.locked_until = now + timedelta(minutes=settings.account_lockout_duration_minutes)

    await db.flush()


async def _clear_failed_attempts(db: AsyncSession, user: User) -> None:
    user.failed_login_attempts = 0
    user.failed_login_window_start = None
    user.locked_until = None
    await db.flush()


async def authenticate(
    db: AsyncSession, email: str, password: str, mfa_code: Optional[str]
) -> User:
    """
    Raises AuthError on bad credentials / lockout, MfaRequiredError when a
    valid password was given but MFA code is missing.
    """
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()

    # Perform a dummy hash verification even when the user doesn't exist,
    # so response timing doesn't reveal account existence.
    if user is None:
        verify_password(password, "$argon2id$v=19$m=65536,t=3,p=4$" + "0" * 22 + "$" + "0" * 43)
        raise AuthError("Invalid email or password.")

    if user.is_locked():
        raise AuthError("Account is temporarily locked due to repeated failed login attempts.", 423)

    if not verify_password(password, user.password_hash):
        await _register_failed_attempt(db, user)
        raise AuthError("Invalid email or password.")

    if not user.is_active:
        raise AuthError("Account is disabled.", 403)

    if user.mfa_enabled:
        if not mfa_code:
            raise MfaRequiredError()
        if not _verify_totp(user, mfa_code):
            await _register_failed_attempt(db, user)
            raise AuthError("Invalid MFA code.")

    await _clear_failed_attempts(db, user)
    return user


def _verify_totp(user: User, code: str) -> bool:
    if not user.mfa_secret_encrypted:
        return False
    secret = decrypt_mfa_secret(user.mfa_secret_encrypted)
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # allow 1 step (~30s) clock drift


def issue_access_token(user: User) -> tuple[str, int]:
    token = create_access_token(subject=str(user.id), role=user.role.value)
    return token, settings.access_token_expire_minutes * 60


async def issue_refresh_token(
    db: AsyncSession, user: User, user_agent: Optional[str], ip_address: Optional[str]
) -> str:
    raw_token = generate_opaque_token()
    now = datetime.now(timezone.utc)
    record = RefreshToken(
        user_id=user.id,
        token_hash=hash_opaque_token(raw_token),
        issued_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        user_agent=user_agent,
        ip_address=ip_address,
    )
    db.add(record)
    await db.flush()
    return raw_token


async def rotate_refresh_token(
    db: AsyncSession, raw_token: str, user_agent: Optional[str], ip_address: Optional[str]
) -> tuple[User, str]:
    """
    Validates + rotates a refresh token. If the presented token was already
    revoked (i.e. reused after rotation — classic token-theft signature),
    the entire token family for that user is revoked and an AuthError raised.
    """
    token_hash = hash_opaque_token(raw_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    existing = result.scalar_one_or_none()

    if existing is None:
        raise AuthError("Invalid refresh token.")

    now = datetime.now(timezone.utc)

    if existing.revoked_at is not None:
        # Reuse of a rotated token: revoke every active token for this user.
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == existing.user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.flush()
        raise AuthError("Refresh token reuse detected; all sessions revoked. Please log in again.", 401)

    if existing.expires_at <= now:
        raise AuthError("Refresh token expired.")

    result = await db.execute(select(User).where(User.id == existing.user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive.")

    new_raw = generate_opaque_token()
    new_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_opaque_token(new_raw),
        issued_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        user_agent=user_agent,
        ip_address=ip_address,
    )
    db.add(new_record)
    await db.flush()

    existing.revoked_at = now
    existing.replaced_by = new_record.id
    await db.flush()

    return user, new_raw


async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> None:
    token_hash = hash_opaque_token(raw_token)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.token_hash == token_hash, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.flush()


# --------------------------------------------------------------------------
# MFA enrollment
# --------------------------------------------------------------------------
def generate_mfa_enrollment(user: User) -> tuple[str, str, list[str]]:
    """Returns (encrypted_secret, provisioning_uri, plaintext_recovery_codes)."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name=settings.mfa_issuer_name)
    recovery_codes = [secrets.token_hex(5) for _ in range(8)]
    return encrypt_mfa_secret(secret), uri, recovery_codes


def hash_recovery_codes(codes: list[str]) -> list[str]:
    return [hash_recovery_code(c) for c in codes]
