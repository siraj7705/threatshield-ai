"""
ThreatShield AI - Token Encryption Helper

OAuth refresh tokens grant long-lived access to a user's Gmail account, so
they must never be stored in plaintext. This module derives a Fernet key
from the app's SECRET_KEY and provides simple encrypt/decrypt helpers.

NOTE: If SECRET_KEY changes (e.g. rotated in production), previously
encrypted tokens become undecryptable and affected users will need to
reconnect their Gmail account. This is expected and safe — it just forces
re-consent, it does not leak data.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a valid 32-byte urlsafe-base64 Fernet key from an arbitrary secret string."""
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_derive_fernet_key(settings.SECRET_KEY))


def encrypt_token(plaintext: str) -> str:
    """Encrypt a plaintext OAuth token for storage in the database."""
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a stored OAuth token. Raises ValueError if it can't be decrypted."""
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError(
            "Could not decrypt stored token (SECRET_KEY may have changed). "
            "User will need to reconnect their Gmail account."
        )