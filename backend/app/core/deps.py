"""
Auth dependencies: extract & validate the bearer JWT, load the current
user, and enforce RBAC. Role checks happen server-side against the DB
role column on every request — the JWT's `role` claim is used only as a
fast-path hint for logging, never trusted alone for authorization,
because a token issued before a role change must not grant the old role
after that change (short access-token TTL bounds this window further).
"""
from typing import Callable, Iterable
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User, UserRole

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Access token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid access token")

    try:
        user_id = UUID(payload["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token subject")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    if user.is_locked():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is locked")

    request.state.current_user_id = str(user.id)
    return user


def require_roles(*allowed_roles: UserRole) -> Callable:
    """
    Usage: @router.get(..., dependencies=[Depends(require_roles(UserRole.ADMINISTRATOR))])
    Authorization is enforced against the freshly-loaded DB row's role,
    not the JWT claim, so a demoted user is denied even mid-token-lifetime
    for any endpoint that re-checks (defense in depth alongside short TTLs).
    """

    async def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role.value}' is not permitted to perform this action.",
            )
        return user

    return _checker
