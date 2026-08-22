"""
Embedding provider interface. Every provider (OpenAI, local, or any future
addition — Cohere, Google, a self-hosted TEI server, whatever) implements
this same one method. Nothing else in the codebase — ingestion_service.py,
the RAG query endpoint — ever imports a specific provider directly; they
all go through embeddings.embed_texts() in __init__.py, which picks the
active provider based on EMBEDDING_PROVIDER in settings. Switching
providers later is a one-line .env change, not a code change.
"""
from abc import ABC, abstractmethod


class EmbeddingProvider(ABC):
    @abstractmethod
    async def embed_texts(self, texts: list[str]) -> list[list[float]]: ...
