"""
Storage backend abstraction. Every backend deals only in opaque bytes
under a server-generated key — encryption happens one layer up in
document_service, so a backend never needs to know (or be trusted with)
anything about what it's storing.
"""
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    @abstractmethod
    async def save(self, key: str, data: bytes) -> None: ...

    @abstractmethod
    async def load(self, key: str) -> bytes: ...

    @abstractmethod
    async def delete(self, key: str) -> None: ...

    @abstractmethod
    async def exists(self, key: str) -> bool: ...
