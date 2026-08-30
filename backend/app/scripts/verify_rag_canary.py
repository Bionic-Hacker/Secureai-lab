"""
Plants a uniquely-named fake secret (a canary/honeytoken) as one user,
then queries the RAG pipeline as a completely different user with a query
deliberately worded to closely match the canary content. If the canary
text appears anywhere in the second user's results, isolation has failed.

This deliberately goes through the real HTTP API - login, upload, poll
for ingestion, query - the same path an actual attacker or a genuinely
different legitimate user would use. A direct database/service-layer
check would prove the query logic is correct in isolation, not that the
real, deployed system actually enforces it end to end.

Cleans up the canary document after the check, pass or fail, so repeated
runs don't leave debris.

Run with:
    docker compose exec backend python3 -m app.scripts.verify_rag_canary \\
        <owner_email> <owner_password> <other_email> <other_password>

Exits 0 on pass (isolation held), 1 on failure (canary leaked) or any
setup error, so this can also be used as a scripted check, not just
read by a human.
"""
import asyncio
import sys
import uuid

import httpx

_BASE_URL = "http://localhost:8000"  # internal container address - this
# script is meant to run inside the backend container via `docker compose
# exec`, the same network context as every other internal verification
# we've done this session, not through nginx's external port.

_POLL_ATTEMPTS = 15
_POLL_DELAY_SECONDS = 2


async def _login(client: httpx.AsyncClient, email: str, password: str) -> str:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    resp.raise_for_status()
    return resp.json()["access_token"]


async def _upload_canary(client: httpx.AsyncClient, token: str, canary_text: str) -> str:
    files = {"file": ("canary-note.txt", canary_text.encode(), "text/plain")}
    resp = await client.post(
        "/api/v1/documents", headers={"Authorization": f"Bearer {token}"}, files=files
    )
    resp.raise_for_status()
    return resp.json()["id"]


async def _wait_for_indexed(client: httpx.AsyncClient, token: str, document_id: str) -> bool:
    for _ in range(_POLL_ATTEMPTS):
        resp = await client.get(
            f"/api/v1/documents/{document_id}", headers={"Authorization": f"Bearer {token}"}
        )
        resp.raise_for_status()
        if resp.json().get("ingestion_status") == "indexed":
            return True
        await asyncio.sleep(_POLL_DELAY_SECONDS)
    return False


async def _query_as(client: httpx.AsyncClient, token: str, query: str) -> list[dict]:
    resp = await client.post(
        "/api/v1/rag/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query},
    )
    resp.raise_for_status()
    return resp.json().get("results", [])


async def _delete_document(client: httpx.AsyncClient, token: str, document_id: str) -> None:
    try:
        await client.delete(
            f"/api/v1/documents/{document_id}", headers={"Authorization": f"Bearer {token}"}
        )
    except httpx.HTTPError as e:
        print(f"Warning: cleanup delete failed for {document_id}: {e}")


async def verify(owner_email: str, owner_password: str, other_email: str, other_password: str) -> bool:
    canary_id = uuid.uuid4().hex[:12]
    canary_secret = f"CANARY-SECRET-{canary_id}"
    canary_text = (
        f"Internal planning note. Project codename honeytoken-verification. "
        f"Reference token: {canary_secret}. This exact token should never appear "
        f"in a retrieval result for any account other than the one that uploaded it."
    )

    async with httpx.AsyncClient(base_url=_BASE_URL, timeout=30.0) as client:
        print("Logging in as owner and other user...")
        owner_token = await _login(client, owner_email, owner_password)
        other_token = await _login(client, other_email, other_password)

        print(f"Planting canary ({canary_secret})...")
        document_id = await _upload_canary(client, owner_token, canary_text)

        print("Waiting for ingestion...")
        if not await _wait_for_indexed(client, owner_token, document_id):
            print("FAIL (inconclusive): canary never finished indexing - cannot verify.")
            await _delete_document(client, owner_token, document_id)
            return False

        # Query worded to closely match the canary content itself - a
        # weak or unrelated query could pass by low semantic similarity
        # alone, which would prove nothing about isolation specifically.
        query = "internal planning note honeytoken verification reference token"

        print("Querying as the OTHER user (should get nothing back)...")
        other_results = await _query_as(client, other_token, query)
        leaked = any(canary_secret in r.get("text", "") for r in other_results)

        print("Querying as the OWNER (sanity check - should find it)...")
        owner_results = await _query_as(client, owner_token, query)
        owner_found_own = any(canary_secret in r.get("text", "") for r in owner_results)

        await _delete_document(client, owner_token, document_id)

        if leaked:
            print(f"FAIL: canary {canary_secret} was returned to a different user. Isolation breach.")
            return False
        if not owner_found_own:
            print(
                f"FAIL (inconclusive): owner could not retrieve their own canary either - "
                f"this indicates a retrieval or embedding problem, not a proven isolation guarantee."
            )
            return False

        print(f"PASS: canary {canary_secret} was retrievable by its owner and invisible to the other user.")
        return True


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            "Usage: python3 -m app.scripts.verify_rag_canary "
            "<owner_email> <owner_password> <other_email> <other_password>"
        )
        sys.exit(1)
    passed = asyncio.run(verify(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
    sys.exit(0 if passed else 1)
