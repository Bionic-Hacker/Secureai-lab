import pytest
from httpx import AsyncClient

from app.core.config import get_settings

settings = get_settings()


class TestRegistration:
    async def test_register_success(self, client: AsyncClient, db_session):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "alice@example.com", "display_name": "Alice", "password": "Str0ng!Passw0rd"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "alice@example.com"
        assert "password" not in body
        assert "password_hash" not in body

    async def test_weak_password_rejected(self, client: AsyncClient, db_session):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "bob@example.com", "display_name": "Bob", "password": "weak"},
        )
        assert resp.status_code == 422

    async def test_duplicate_email_returns_generic_error(self, client: AsyncClient, db_session):
        payload = {"email": "carol@example.com", "display_name": "Carol", "password": "Str0ng!Passw0rd"}
        first = await client.post("/api/v1/auth/register", json=payload)
        assert first.status_code == 201

        second = await client.post("/api/v1/auth/register", json=payload)
        assert second.status_code == 400
        # Must not say "email already exists" — that's an enumeration oracle.
        assert "already" not in second.json()["detail"].lower()
        assert "exists" not in second.json()["detail"].lower()


class TestLogin:
    async def _register(self, client, email="dave@example.com", password="Str0ng!Passw0rd"):
        await client.post(
            "/api/v1/auth/register",
            json={"email": email, "display_name": "Dave", "password": password},
        )

    async def test_login_success_issues_tokens(self, client: AsyncClient, db_session):
        await self._register(client)
        resp = await client.post("/api/v1/auth/login", json={"email": "dave@example.com", "password": "Str0ng!Passw0rd"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["refresh_token"]

    async def test_wrong_password_and_unknown_email_same_shape(self, client: AsyncClient, db_session):
        await self._register(client)
        wrong_pw = await client.post("/api/v1/auth/login", json={"email": "dave@example.com", "password": "WrongPass123!"})
        unknown_email = await client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "WrongPass123!"})

        assert wrong_pw.status_code == unknown_email.status_code == 401
        assert wrong_pw.json()["detail"] == unknown_email.json()["detail"]

    async def test_account_locks_after_threshold(self, client: AsyncClient, db_session):
        email = "eve@example.com"
        await self._register(client, email=email)

        for _ in range(settings.account_lockout_threshold):
            resp = await client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPass123!"})
            assert resp.status_code == 401

        # One more attempt, even with the CORRECT password, must now be locked out.
        locked_resp = await client.post("/api/v1/auth/login", json={"email": email, "password": "Str0ng!Passw0rd"})
        assert locked_resp.status_code == 423


class TestProtectedEndpoints:
    async def test_me_requires_auth(self, client: AsyncClient, db_session):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_me_rejects_garbage_token(self, client: AsyncClient, db_session):
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
        assert resp.status_code == 401

    async def test_me_returns_current_user_with_valid_token(self, client: AsyncClient, db_session):
        await client.post(
            "/api/v1/auth/register",
            json={"email": "frank@example.com", "display_name": "Frank", "password": "Str0ng!Passw0rd"},
        )
        login = await client.post("/api/v1/auth/login", json={"email": "frank@example.com", "password": "Str0ng!Passw0rd"})
        token = login.json()["access_token"]

        resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "frank@example.com"
