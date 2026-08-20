import time

import jwt
import pytest

from app.core.security import (
    create_access_token,
    decode_access_token,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    hash_opaque_token,
    hash_password,
    validate_password_strength,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_is_not_plaintext_and_not_stable(self):
        h1 = hash_password("Sup3r$ecurePass!")
        h2 = hash_password("Sup3r$ecurePass!")
        assert h1 != "Sup3r$ecurePass!"
        assert h1 != h2  # salted — same password never hashes the same way twice

    def test_correct_password_verifies(self):
        h = hash_password("Sup3r$ecurePass!")
        assert verify_password("Sup3r$ecurePass!", h) is True

    def test_incorrect_password_rejected(self):
        h = hash_password("Sup3r$ecurePass!")
        assert verify_password("wrong-password", h) is False

    def test_malformed_hash_does_not_raise(self):
        # A corrupted/garbage hash must fail closed, not throw an unhandled
        # exception that could crash the request or be caught as "success"
        # by an overly broad except clause upstream.
        assert verify_password("anything", "not-a-real-hash") is False

    @pytest.mark.parametrize(
        "password,should_fail",
        [
            ("short1!A", True),          # too short
            ("alllowercase123!", True),  # no uppercase
            ("ALLUPPERCASE123!", True),  # no lowercase
            ("NoDigitsHere!!", True),    # no digit
            ("NoSpecialChars123", True), # no special char
            ("ValidPassw0rd!", False),
        ],
    )
    def test_password_policy(self, password, should_fail):
        result = validate_password_strength(password)
        assert (result is not None) == should_fail


class TestJWT:
    def test_round_trip(self):
        token = create_access_token(subject="user-123", role="developer")
        payload = decode_access_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "developer"
        assert payload["type"] == "access"

    def test_tampered_signature_rejected(self):
        token = create_access_token(subject="user-123", role="viewer")
        tampered = token[:-4] + "abcd"
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(tampered)

    def test_expired_token_rejected(self):
        import app.core.security as sec

        original_expiry = sec.settings.access_token_expire_minutes
        sec.settings.access_token_expire_minutes = -1  # force immediate expiry
        try:
            token = create_access_token(subject="user-123", role="viewer")
        finally:
            sec.settings.access_token_expire_minutes = original_expiry

        with pytest.raises(jwt.ExpiredSignatureError):
            decode_access_token(token)

    def test_none_alg_confusion_rejected(self):
        # Classic JWT vuln: a token signed with alg=none must never verify.
        import jwt as pyjwt

        forged = pyjwt.encode({"sub": "attacker", "role": "administrator", "type": "access"}, key="", algorithm="none")
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(forged)


class TestMfaEncryption:
    def test_round_trip(self):
        secret = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_mfa_secret(secret)
        assert encrypted != secret
        assert decrypt_mfa_secret(encrypted) == secret

    def test_tampered_ciphertext_fails_closed(self):
        secret = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_mfa_secret(secret)
        tampered = encrypted[:-2] + "xx"
        with pytest.raises(ValueError):
            decrypt_mfa_secret(tampered)


class TestOpaqueTokenHashing:
    def test_hash_is_deterministic_but_not_reversible_lookalike(self):
        token = "some-refresh-token-value"
        h1 = hash_opaque_token(token)
        h2 = hash_opaque_token(token)
        assert h1 == h2          # must match on lookup
        assert h1 != token       # never store/compare raw
        assert len(h1) == 64     # sha256 hex digest length
