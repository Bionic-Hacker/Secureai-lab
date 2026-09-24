"""
One heavy background job at a time.

Embedding a document and scanning code are the two memory-hungry background
jobs. Each fits inside Render's 512MB free tier on its own, but not both at
once: measured, an upload's indexing plus a Semgrep scan got the container
OOM-killed. Both take this lock, so the second simply waits its turn.

Process-local, which matches the deployment: a single uvicorn worker.
"""
import asyncio
from contextlib import asynccontextmanager

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(1)
    return _semaphore


@asynccontextmanager
async def heavy_job():
    async with _get_semaphore():
        yield
