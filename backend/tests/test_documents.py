"""
Phase 2 test suite — document upload, encryption, and access control.

Covers three layers:
  - Pure unit tests for AES-256-GCM encryption and filename sanitization
    (no DB, no HTTP client — fast, no fixtures beyond pytest itself).
  - Integration tests for the upload pipeline (malware-clean, malware-
    infected, scanner-unavailable) against the real endpoint.
  - Integration tests for object-level permission enforcement (ownership,
    sharing, revocation) — the OWASP API1 controls for this feature.

ClamAV isn't running in the unit-test environment, so malware_scan_service
is mocked at its boundary; everything else in the pipeline (validation,
encryption, storage, permissions) runs for real against the test database.
"""
import io

import pytest
from httpx import AsyncClient

from app.core.file_encryption import decrypt_bytes, encrypt_bytes
from app.services import malware_scan_service
from app.services.document_service import DocumentError, sanitize_filename


# ==========================================================================
# Unit tests — no client/db fixtures needed
# ==========================================================================
class TestFileEncryption:
    def test_round_trip(self):
        plaintext = b"the quick brown fox jumps over the lazy dog" * 100
        blob = encrypt_bytes(plaintext)
        assert blob != plaintext
        assert decrypt_bytes(blob) == plaintext

    def test_ciphertext_is_not_stable(self):
        # A fresh random nonce each time means encrypting the same
        # plaintext twice must never produce the same ciphertext —
        # otherwise an attacker could detect repeated uploads by
        # comparing stored blobs.
        plaintext = b"same content"
        assert encrypt_bytes(plaintext) != encrypt_bytes(plaintext)

    def test_tampered_ciphertext_rejected(self):
        from cryptography.exceptions import InvalidTag

        blob = bytearray(encrypt_bytes(b"sensitive document contents"))
        blob[-1] ^= 0xFF  # flip a bit in the auth tag
        with pytest.raises(InvalidTag):
            decrypt_bytes(bytes(blob))

    def test_truncated_blob_rejected(self):
        with pytest.raises(ValueError):
            decrypt_bytes(b"short")


class TestFilenameSanitization:
    def test_normal_filename(self):
        name, ext = sanitize_filename("report.pdf")
        assert name == "report.pdf"
        assert ext == ".pdf"

    def test_path_traversal_unix_style_stripped(self):
        name, ext = sanitize_filename("../../etc/passwd.txt")
        assert "/" not in name
        assert ".." not in name
        assert name == "passwd.txt"

    def test_path_traversal_windows_style_stripped(self):
        name, ext = sanitize_filename("..\\..\\windows\\win.ini.txt")
        assert "\\" not in name
        assert name == "win.ini.txt"

    def test_missing_extension_rejected(self):
        with pytest.raises(DocumentError):
            sanitize_filename("no-extension")

    def test_disallowed_extension_rejected(self):
        with pytest.raises(DocumentError):
            sanitize_filename("payload.exe")

    def test_empty_filename_rejected(self):
        with pytest.raises(DocumentError):
            sanitize_filename("")

    def test_overlong_filename_truncated_not_rejected(self):
        long_name = ("a" * 300) + ".txt"
        name, ext = sanitize_filename(long_name)
        assert len(name) <= 255
        assert ext == ".txt"

    def test_control_characters_stripped(self):
        name, ext = sanitize_filename("evil\x00name.txt")
        assert "\x00" not in name


# ==========================================================================
# Integration tests — use the `client` and `db_session` fixtures from
# tests/conftest.py
# ==========================================================================
@pytest.fixture(autouse=True)
def clean_scan_by_default(monkeypatch):
    """
    ClamAV isn't running in the unit-test environment, so the scanner call
    is mocked at the boundary (malware_scan_service.scan_bytes_async) —
    everything else in the upload pipeline (validation, encryption,
    storage, permissions) runs for real. Individual tests override this to
    exercise the infected/unavailable paths. Harmless no-op for the pure
    unit test classes above, since they never touch this module.
    """

    async def _clean(data: bytes):
        return malware_scan_service.MalwareScanResult(clean=True)

    monkeypatch.setattr(malware_scan_service, "scan_bytes_async", _clean)


async def _register_and_login(client: AsyncClient, email: str) -> str:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": email.split("@")[0], "password": "Str0ng!Passw0rd"},
    )
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": "Str0ng!Passw0rd"})
    return login.json()["access_token"]


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestUpload:
    async def test_upload_succeeds_and_returns_metadata(self, client: AsyncClient, db_session):
        token = await _register_and_login(client, "owner@example.com")
        files = {"file": ("notes.txt", io.BytesIO(b"some plaintext notes"), "text/plain")}
        resp = await client.post("/api/v1/documents", files=files, headers=_auth_headers(token))

        assert resp.status_code == 201
        body = resp.json()
        assert body["original_filename"] == "notes.txt"
        assert body["malware_scan_status"] == "clean"
        assert body["ingestion_status"] == "pending"

    async def test_disallowed_extension_rejected(self, client: AsyncClient, db_session):
        token = await _register_and_login(client, "owner2@example.com")
        files = {"file": ("payload.exe", io.BytesIO(b"MZ\x90\x00fakeexe"), "application/octet-stream")}
        resp = await client.post("/api/v1/documents", files=files, headers=_auth_headers(token))
        assert resp.status_code == 400

    async def test_infected_file_never_persisted(self, client: AsyncClient, db_session, monkeypatch):
        async def _infected(data: bytes):
            return malware_scan_service.MalwareScanResult(clean=False, signature="Eicar-Test-Signature")

        monkeypatch.setattr(malware_scan_service, "scan_bytes_async", _infected)

        token = await _register_and_login(client, "owner3@example.com")
        files = {"file": ("resume.txt", io.BytesIO(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), "text/plain")}
        resp = await client.post("/api/v1/documents", files=files, headers=_auth_headers(token))
        assert resp.status_code == 422

        listing = await client.get("/api/v1/documents", headers=_auth_headers(token))
        assert listing.json() == []

    async def test_scanner_unavailable_fails_closed(self, client: AsyncClient, db_session, monkeypatch):
        async def _unavailable(data: bytes):
            raise malware_scan_service.MalwareScanUnavailable("connection refused")

        monkeypatch.setattr(malware_scan_service, "scan_bytes_async", _unavailable)

        token = await _register_and_login(client, "owner4@example.com")
        files = {"file": ("notes.txt", io.BytesIO(b"content"), "text/plain")}
        resp = await client.post("/api/v1/documents", files=files, headers=_auth_headers(token))
        assert resp.status_code == 503


class TestPermissions:
    async def test_download_round_trips_original_content(self, client: AsyncClient, db_session):
        token = await _register_and_login(client, "alice@example.com")
        original = b"the exact bytes that should come back unchanged"
        files = {"file": ("data.txt", io.BytesIO(original), "text/plain")}
        upload = await client.post("/api/v1/documents", files=files, headers=_auth_headers(token))
        doc_id = upload.json()["id"]

        download = await client.get(f"/api/v1/documents/{doc_id}/content", headers=_auth_headers(token))
        assert download.status_code == 200
        assert download.content == original

    async def test_non_owner_gets_404_not_403(self, client: AsyncClient, db_session):
        owner_token = await _register_and_login(client, "bob@example.com")
        other_token = await _register_and_login(client, "carol@example.com")

        files = {"file": ("private.txt", io.BytesIO(b"secret"), "text/plain")}
        upload = await client.post("/api/v1/documents", files=files, headers=_auth_headers(owner_token))
        doc_id = upload.json()["id"]

        # A user with zero access should see "not found," not "forbidden" —
        # confirming existence to someone with no permission is its own
        # information leak.
        resp = await client.get(f"/api/v1/documents/{doc_id}", headers=_auth_headers(other_token))
        assert resp.status_code == 404

    async def test_sharing_grants_read_access(self, client: AsyncClient, db_session):
        owner_token = await _register_and_login(client, "dave@example.com")
        grantee_token = await _register_and_login(client, "erin@example.com")

        files = {"file": ("shared.txt", io.BytesIO(b"shared content"))}
        upload = await client.post("/api/v1/documents", files=files, headers=_auth_headers(owner_token))
        doc_id = upload.json()["id"]

        share = await client.post(
            f"/api/v1/documents/{doc_id}/share",
            json={"email": "erin@example.com", "permission": "read"},
            headers=_auth_headers(owner_token),
        )
        assert share.status_code == 204

        resp = await client.get(f"/api/v1/documents/{doc_id}", headers=_auth_headers(grantee_token))
        assert resp.status_code == 200

    async def test_shared_read_user_cannot_delete(self, client: AsyncClient, db_session):
        owner_token = await _register_and_login(client, "frank@example.com")
        grantee_token = await _register_and_login(client, "grace@example.com")

        files = {"file": ("shared2.txt", io.BytesIO(b"shared content 2"))}
        upload = await client.post("/api/v1/documents", files=files, headers=_auth_headers(owner_token))
        doc_id = upload.json()["id"]

        await client.post(
            f"/api/v1/documents/{doc_id}/share",
            json={"email": "grace@example.com", "permission": "read"},
            headers=_auth_headers(owner_token),
        )

        resp = await client.delete(f"/api/v1/documents/{doc_id}", headers=_auth_headers(grantee_token))
        assert resp.status_code == 403

    async def test_owner_can_revoke_share(self, client: AsyncClient, db_session):
        owner_token = await _register_and_login(client, "henry@example.com")
        grantee_token = await _register_and_login(client, "irene@example.com")

        files = {"file": ("revoke-me.txt", io.BytesIO(b"content"))}
        upload = await client.post("/api/v1/documents", files=files, headers=_auth_headers(owner_token))
        doc_id = upload.json()["id"]

        me = await client.get("/api/v1/auth/me", headers=_auth_headers(grantee_token))
        grantee_id = me.json()["id"]

        await client.post(
            f"/api/v1/documents/{doc_id}/share",
            json={"email": "irene@example.com", "permission": "read"},
            headers=_auth_headers(owner_token),
        )
        revoke = await client.delete(
            f"/api/v1/documents/{doc_id}/share/{grantee_id}", headers=_auth_headers(owner_token)
        )
        assert revoke.status_code == 204

        resp = await client.get(f"/api/v1/documents/{doc_id}", headers=_auth_headers(grantee_token))
        assert resp.status_code == 404
