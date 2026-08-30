import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from prometheus_fastapi_instrumentator import Instrumentator
from redis.asyncio import Redis

from app.api.v1.endpoints import assistant as assistant_endpoints
from app.api.v1.endpoints import auth as auth_endpoints
from app.api.v1.endpoints import code_review as code_review_endpoints
from app.api.v1.endpoints import documents as documents_endpoints
from app.api.v1.endpoints import governance as governance_endpoints
from app.api.v1.endpoints import rag as rag_endpoints
from app.api.v1.endpoints import threat_models as threat_models_endpoints
from app.core.config import get_settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("secureai")

# API docs are only exposed outside production — never ship an interactive
# schema explorer (and its default "try it out" request forgery surface)
# to a public production deployment.
app = FastAPI(
    title=settings.app_name,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

# CORS: explicit allow-list from config, never "*" — especially important
# since the API accepts credentials (Authorization headers).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(SecurityHeadersMiddleware)

_redis_client = Redis.from_url(settings.redis_url, decode_responses=False)
app.add_middleware(RateLimitMiddleware, redis_client=_redis_client)

app.include_router(auth_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(documents_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(governance_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(rag_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(assistant_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(code_review_endpoints.router, prefix=settings.api_v1_prefix)
app.include_router(threat_models_endpoints.router, prefix=settings.api_v1_prefix)

# /metrics is scraped by Prometheus over the internal backend_net network
# only — nginx's location blocks never proxy it, so it's not reachable from
# the internet. It's excluded from the rate-limit/auth middleware chain
# above by virtue of being registered directly on `app`, matching how
# Prometheus expects an unauthenticated same-network scrape target to work.
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return field-level errors without leaking internals (stack traces,
    # SQL, file paths). Pydantic's default error detail is safe to return
    # as-is since it only describes the client's own malformed input.
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": jsonable_encoder(exc.errors())},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never leak stack traces or internal error text to the client.
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred."},
    )


@app.get("/healthz", tags=["ops"])
async def healthz():
    return {"status": "ok"}
