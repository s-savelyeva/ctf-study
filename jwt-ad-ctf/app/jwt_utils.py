"""Утилиты для работы с JWT (без внешних зависимостей вроде PyJWT).

Реализованы: base64url, декодирование/кодирование токенов, HS256 и RS256
подписи через пакет ``cryptography``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------------------------------------------------------------- helpers ---

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


class JwtError(Exception):
    """Ошибка разбора/проверки токена."""


# ------------------------------------------------------------------- jwt ----

def encode_jwt_hs256(payload: dict, secret: str, header: dict | None = None) -> str:
    hdr = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url_encode(json_bytes(hdr))}.{b64url_encode(json_bytes(payload))}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, str]:
    """Разбирает токен БЕЗ проверки подписи.

    Возвращает (header, payload, signature_bytes, signing_input), где
    signing_input — склеенные строкой "header.payload" первые две части.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JwtError("Токен должен содержать три части header.payload.signature")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except Exception as exc:  # noqa: BLE001
        raise JwtError(f"Не удалось разобрать токен: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("header и payload должны быть JSON-объектами")
    return header, payload, signature, ".".join(parts[:2])


def verify_hs256(signing_input: str, signature: bytes, secret: str) -> bool:
    expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def verify_rs256(public_key_pem: bytes, signing_input: str, signature: bytes) -> bool:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
        key.verify(signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:  # noqa: BLE001
        return False


def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    """Возвращает (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem
