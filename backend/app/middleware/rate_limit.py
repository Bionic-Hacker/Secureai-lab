"""
Simple fixed-window rate limiter backed by Redis (INCR + EXPIRE), applied
per-client-IP and per-route-group. Login/MFA endpoints get a much tighter
limit than general API traffic to blunt credential-stuffing and brute
force, independent of the account-lockout logic in auth_service (which
protects a specific account; this protects the service as a whole).
"""
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from redis.asyncio import Redis

from app.core.config import get_settings

settings = get_settings()

_SENSITIVE_PREFIXES = ("/api/v1/auth/login", "/api/v1/auth/mfa")
_UPLOAD_PREFIXES = ("/api/v1/documents",)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_client: Redis):
        super().__init__(app)
        self.redis = redis_client

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        if path.startswith(_SENSITIVE_PREFIXES):
            tier, limit = "sensitive", settings.login_rate_limit_per_minute
        elif path.startswith(_UPLOAD_PREFIXES) and request.method == "POST":
            # Uploads are far more expensive per-request than a typical
            # read (malware scan + AES-256-GCM encryption + a storage
            # write), so they get their own, tighter budget rather than
            # sharing the general API limit — this is the OWASP API4
            # "unrestricted resource consumption" control for this route.
            tier, limit = "upload", settings.upload_rate_limit_per_minute
        else:
            tier, limit = "general", settings.rate_limit_per_minute

        window_seconds = 60
        bucket = int(time.time() // window_seconds)
        key = f"ratelimit:{tier}:{client_ip}:{bucket}"

        current = await self.redis.incr(key)
        if current == 1:
            await self.redis.expire(key, window_seconds)

        if current > limit:
            return Response(
                content='{"detail":"Rate limit exceeded. Please try again shortly."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(window_seconds)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current))
        return response
