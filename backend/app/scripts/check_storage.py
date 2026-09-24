"""
Round-trip check for the configured storage backend: writes a small random
object, confirms it exists, reads it back, deletes it, and confirms it's gone.
Prints no credentials. Use it to verify object-storage settings before
pointing a real deployment at them:

    docker compose exec -e STORAGE_BACKEND=s3 -e S3_BUCKET=... backend \
        python3 -m app.scripts.check_storage
"""
import asyncio
import os
import sys
import uuid

from app.core.config import get_settings
from app.services.storage import get_storage_backend


async def main() -> int:
    settings = get_settings()
    print(f"backend={settings.storage_backend} bucket={settings.s3_bucket or '-'} "
          f"endpoint={settings.s3_endpoint_url or '-'} region={settings.s3_region} "
          f"addressing={getattr(settings, 's3_addressing_style', '-')} "
          f"sse={getattr(settings, 's3_server_side_encryption', '-') or 'off'}")
    storage = get_storage_backend()
    key = f"healthcheck/{uuid.uuid4()}.bin"
    payload = os.urandom(64)
    steps = [
        ("save", lambda: storage.save(key, payload)),
        ("exists", lambda: storage.exists(key)),
        ("load", lambda: storage.load(key)),
        ("delete", lambda: storage.delete(key)),
        ("gone", lambda: storage.exists(key)),
    ]
    for name, step in steps:
        try:
            result = await step()
        except Exception as exc:  # report the first failing step plainly
            print(f"FAIL at {name}: {type(exc).__name__}: {exc}")
            return 1
        if name == "exists" and result is not True:
            print("FAIL at exists: object not found right after saving")
            return 1
        if name == "load" and result != payload:
            print("FAIL at load: bytes read back don't match what was written")
            return 1
        if name == "gone" and result is not False:
            print("FAIL at gone: object still exists after delete")
            return 1
        print(f"  ok  {name}")
    print("PASS - storage round trip works")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
