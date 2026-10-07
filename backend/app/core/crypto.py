import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings


def _fernet(settings: Settings) -> Fernet:
    if settings.data_encryption_key:
        return Fernet(settings.data_encryption_key.encode())
    # Non-production convenience only (Settings refuses to start in production without an explicit key).
    derived = hashlib.sha256(b"data-encryption:" + settings.jwt_secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_json(settings: Settings, data: dict[str, Any]) -> bytes:
    return _fernet(settings).encrypt(json.dumps(data).encode())


def decrypt_json(settings: Settings, blob: bytes | None) -> dict[str, Any]:
    if not blob:
        return {}
    try:
        value = json.loads(_fernet(settings).decrypt(blob))
    except InvalidToken:
        raise ValueError("stored secrets cannot be decrypted with the configured key") from None
    return value if isinstance(value, dict) else {}
