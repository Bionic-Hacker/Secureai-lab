from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import get_current_user
from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.token import PasswordResetToken
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MfaSetupResponse,
    MfaVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    UserOut,
)
from app.services import auth_service
from app.services.audit_service import record as audit_record

router = APIRouter(prefix="/auth", tags=["authentication"])
settings = get_settings()


def _client_meta(request: Request) -> tuple[str, str]:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    return ip, ua


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip, ua = _client_meta(request)
    try:
        user = await auth_service.register_user(db, payload.email, payload.display_name, payload.password)
    except auth_service.AuthError as e:
        await audit_record(
            db, event_type="registration_failed", event_category="auth",
            actor_email=payload.email, ip_address=ip, user_agent=ua,
            outcome="failure", metadata={"reason": "duplicate_or_invalid"},
        )
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="registration_success", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()
    return user


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip, ua = _client_meta(request)
    try:
        user = await auth_service.authenticate(db, payload.email, payload.password, payload.mfa_code)
    except auth_service.MfaRequiredError:
        await db.commit()
        return LoginResponse(access_token="", expires_in=0, mfa_required=True)
    except auth_service.AuthError as e:
        await audit_record(
            db, event_type="login_failed", event_category="auth",
            actor_email=payload.email, ip_address=ip, user_agent=ua,
            outcome="failure", metadata={"reason": e.message},
        )
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    access_token, expires_in = auth_service.issue_access_token(user)
    refresh_token = await auth_service.issue_refresh_token(db, user, ua, ip)

    await audit_record(
        db, event_type="login_success", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()

    return LoginResponse(
        access_token=access_token, expires_in=expires_in, refresh_token=refresh_token
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh(payload: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip, ua = _client_meta(request)
    try:
        user, new_refresh = await auth_service.rotate_refresh_token(db, payload.refresh_token, ua, ip)
    except auth_service.AuthError as e:
        await audit_record(
            db, event_type="token_refresh_failed", event_category="auth",
            ip_address=ip, user_agent=ua, outcome="failure", metadata={"reason": e.message},
        )
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    access_token, expires_in = auth_service.issue_access_token(user)
    await audit_record(
        db, event_type="token_refresh_success", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()
    return LoginResponse(access_token=access_token, expires_in=expires_in, refresh_token=new_refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    await auth_service.revoke_refresh_token(db, payload.refresh_token)
    await audit_record(
        db, event_type="logout", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generates a new TOTP secret. MFA is not enabled until /mfa/verify confirms a code."""
    ip, ua = _client_meta(request)
    encrypted_secret, uri, recovery_codes = auth_service.generate_mfa_enrollment(user)
    user.mfa_secret_encrypted = encrypted_secret
    user.mfa_recovery_codes_hash = auth_service.hash_recovery_codes(recovery_codes)
    await db.flush()

    await audit_record(
        db, event_type="mfa_enrollment_started", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()
    # Recovery codes are shown exactly once, at generation time, then only
    # their hashes exist server-side.
    return MfaSetupResponse(provisioning_uri=uri, recovery_codes=recovery_codes)


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_verify(
    payload: MfaVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    if not auth_service._verify_totp(user, payload.code):
        await audit_record(
            db, event_type="mfa_enrollment_failed", event_category="auth",
            actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
            outcome="failure",
        )
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code.")

    user.mfa_enabled = True
    await audit_record(
        db, event_type="mfa_enabled", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def password_reset_request(
    payload: PasswordResetRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    """
    Always returns 202 regardless of whether the email exists — prevents
    user enumeration via this endpoint. The reset email (not implemented
    in this demo — see documentation) is only sent if the account exists.
    """
    ip, ua = _client_meta(request)
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = result.scalar_one_or_none()

    if user is not None:
        raw_token = generate_opaque_token()
        reset = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_opaque_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.add(reset)
        await audit_record(
            db, event_type="password_reset_requested", event_category="auth",
            actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        )
        # In production: enqueue an email send here with the raw_token in a
        # signed link. Never log or return raw_token in the API response.

    await db.commit()
    return {"detail": "If an account with that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def password_reset_confirm(
    payload: PasswordResetConfirm, request: Request, db: AsyncSession = Depends(get_db)
):
    ip, ua = _client_meta(request)
    token_hash = hash_opaque_token(payload.token)
    result = await db.execute(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash))
    reset = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if reset is None or reset.used_at is not None or reset.expires_at <= now:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token.")

    result = await db.execute(select(User).where(User.id == reset.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token.")

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = now
    reset.used_at = now

    await audit_record(
        db, event_type="password_reset_completed", event_category="auth",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
    )
    await db.commit()


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return user
