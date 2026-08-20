import os
import asyncio
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Load test env before any app module reads settings via get_settings().
load_dotenv(Path(__file__).resolve().parent.parent / ".env.test", override=True)

from httpx import AsyncClient, ASGITransport
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import Base, engine, AsyncSessionLocal
from app.main import app


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture()
async def db_session() -> AsyncSession:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(autouse=True)
async def _reset_rate_limits():
    """
    RateLimitMiddleware (app/middleware/rate_limit.py) counts requests in
    Redis per client-IP+route-tier, fixed-window. Without a reset here,
    login/upload counters accumulate across the whole test session — since
    every test in this suite hits the ASGI transport from the same fake
    client IP, that means later tests start failing with 429s that have
    nothing to do with what they're actually testing. .env.test points
    REDIS_URL at a disposable test-only Redis (see its comment), so a full
    flush before each test is safe.
    """
    redis = Redis.from_url(get_settings().redis_url, decode_responses=False)
    await redis.flushdb()
    await redis.aclose()


@pytest.fixture()
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
