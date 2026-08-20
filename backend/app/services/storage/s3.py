"""
S3-compatible object storage — works against AWS S3 and any S3-API-
compatible provider (Cloudflare R2, Backblaze B2, DigitalOcean Spaces,
MinIO) via a configurable endpoint URL. This is what makes the backend
deployable to Fly.io/Railway/Render, none of which give you the kind of
always-attached local disk that docker-compose's uploads_data volume
provides in dev.

Server-side encryption (SSE) is enabled as defense in depth on top of —
not instead of — the application-level AES-256-GCM encryption already
applied in document_service before bytes ever reach this module. If the
bucket were ever misconfigured to be public, the object stored there is
still ciphertext either way.
"""
import asyncio

import boto3
from botocore.exceptions import ClientError

from app.core.config import get_settings
from app.services.storage.base import StorageBackend

settings = get_settings()


class S3CompatibleStorage(StorageBackend):
    def __init__(self):
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url or None,
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key_id or None,
            aws_secret_access_key=settings.s3_secret_access_key or None,
        )
        self._bucket = settings.s3_bucket

    async def save(self, key: str, data: bytes) -> None:
        def _put() -> None:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=data,
                ServerSideEncryption="AES256",
            )

        await asyncio.to_thread(_put)

    async def load(self, key: str) -> bytes:
        def _get() -> bytes:
            obj = self._client.get_object(Bucket=self._bucket, Key=key)
            return obj["Body"].read()

        return await asyncio.to_thread(_get)

    async def delete(self, key: str) -> None:
        def _del() -> None:
            self._client.delete_object(Bucket=self._bucket, Key=key)

        await asyncio.to_thread(_del)

    async def exists(self, key: str) -> bool:
        def _head() -> bool:
            try:
                self._client.head_object(Bucket=self._bucket, Key=key)
                return True
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                    return False
                raise

        return await asyncio.to_thread(_head)
