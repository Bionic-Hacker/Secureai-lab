"""
File-content encryption at rest, using AES-256-GCM directly rather than
Fernet.

Why not reuse the Fernet helper from core/security.py? Fernet is well
suited to small tokens (MFA secrets, session data) but internally only
uses a 128-bit AES key with CBC mode. The project's stated requirement is
AES-256 for data at rest, and file contents are exactly the kind of bulk
binary data AES-GCM is designed for: it's authenticated (tampering with
the ciphertext is detected on decrypt, unlike plain CBC) and doesn't need
a separate MAC step.

Nonce handling: a fresh random 96-bit nonce is generated per encryption
and stored *with* the ciphertext (nonce || ciphertext+tag) rather than in
a separate database column. This keeps the encrypted blob self-contained —
whichever storage backend holds it (local disk or S3) doesn't need to know
anything about encryption at all; it just stores and returns opaque bytes.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

settings = get_settings()

_NONCE_SIZE = 12  # 96 bits — the standard, recommended nonce size for AES-GCM

_aesgcm = AESGCM(bytes.fromhex(settings.field_encryption_key))


def encrypt_bytes(plaintext: bytes) -> bytes:
    """Returns nonce || ciphertext+tag as a single blob."""
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = _aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext


def decrypt_bytes(blob: bytes) -> bytes:
    """
    Raises cryptography.exceptions.InvalidTag if the ciphertext was
    tampered with or the wrong key is in use — this is AES-GCM's built-in
    authentication, not something this module has to implement separately.
    """
    if len(blob) < _NONCE_SIZE:
        raise ValueError("Encrypted blob is too short to contain a valid nonce.")
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return _aesgcm.decrypt(nonce, ciphertext, associated_data=None)
