from functools import lru_cache

from app.core.config import get_settings
from app.services.storage.base import StorageBackend
from app.services.storage.local import LocalFilesystemStorage
from app.services.storage.s3 import S3CompatibleStorage

settings = get_settings()


@lru_cache
def get_storage_backend() -> StorageBackend:
    if settings.storage_backend == "s3":
        return S3CompatibleStorage()
    return LocalFilesystemStorage()
