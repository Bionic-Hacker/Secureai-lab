"""
Local filesystem storage — writes to the uploads_data Docker volume
mounted at UPLOAD_STORAGE_PATH. Used by default (STORAGE_BACKEND=local),
matching the Phase 1 docker-compose.yml setup.

Blocking file I/O is offloaded to a thread via asyncio.to_thread so it
doesn't stall the event loop the way a synchronous read/write call would
inside an async endpoint.
"""
import asyncio
from pathlib import Path

from app.core.config import get_settings
from app.services.storage.base import StorageBackend

settings = get_settings()


class LocalFilesystemStorage(StorageBackend):
    def __init__(self, base_path: str | None = None):
        self.base_path = Path(base_path or settings.upload_storage_path).resolve()

    def _resolve(self, key: str) -> Path:
        # Keys are always server-generated (UUID-based — see
        # document_service.upload_document), never derived from client
        # input. This resolve-and-check is defense in depth: even if a key
        # were ever built incorrectly, a path that would escape the base
        # upload directory is rejected outright rather than silently
        # followed.
        candidate = (self.base_path / key).resolve()
        if not str(candidate).startswith(str(self.base_path)):
            raise ValueError("Resolved storage path escapes the base upload directory.")
        return candidate

    async def save(self, key: str, data: bytes) -> None:
        path = self._resolve(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            path.write_bytes(data)
            path.chmod(0o640)  # owner read/write, group read, no world access

        await asyncio.to_thread(_write)

    async def load(self, key: str) -> bytes:
        path = self._resolve(key)
        return await asyncio.to_thread(path.read_bytes)

    async def delete(self, key: str) -> None:
        path = self._resolve(key)
        await asyncio.to_thread(lambda: path.unlink(missing_ok=True))

    async def exists(self, key: str) -> bool:
        path = self._resolve(key)
        return await asyncio.to_thread(path.exists)
