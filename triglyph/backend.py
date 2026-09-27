"""
triglyph.backend — выбор реализации AEAD: чистый Python или ускоритель.

TRIGLYPH самодостаточен и работает вообще без зависимостей. Но если в системе
уже установлен пакет `cryptography` (OpenSSL, AES-NI), мы можем считать
AES-256-GCM и ChaCha20-Poly1305 в десятки раз быстрее.

Ускоритель включается ТОЛЬКО если он побайтово совпал с эталонной чистой
реализацией на случайных векторах прямо при импорте. Любое расхождение,
исключение или отсутствие пакета — молча откатываемся на чистый Python.
Формат контейнера от выбора бэкенда не зависит.
"""

from __future__ import annotations

import os
from typing import Callable

from . import aes as _aes
from . import chacha as _chacha
from ._util import IntegrityError

__all__ = [
    "BACKEND",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "xchacha_encrypt",
    "xchacha_decrypt",
    "backend_info",
]

# --- эталон: чистый Python (проверен векторами RFC 8439 / FIPS-197 / NIST) ---
_pure_aes_enc: Callable[..., bytes] = _aes.aes_gcm_encrypt
_pure_aes_dec: Callable[..., bytes] = _aes.aes_gcm_decrypt
_pure_xchacha_enc: Callable[..., bytes] = _chacha.xchacha20poly1305_encrypt
_pure_xchacha_dec: Callable[..., bytes] = _chacha.xchacha20poly1305_decrypt

aes_gcm_encrypt = _pure_aes_enc
aes_gcm_decrypt = _pure_aes_dec
xchacha_encrypt = _pure_xchacha_enc
xchacha_decrypt = _pure_xchacha_dec

BACKEND = "pure-python"


def _try_accelerate() -> str:
    if os.environ.get("TRIGLYPH_PURE_PYTHON"):
        return "pure-python (forced)"
    try:
        from cryptography.hazmat.primitives.ciphers.aead import (  # type: ignore
            AESGCM,
            ChaCha20Poly1305,
        )
    except Exception:
        return "pure-python"

    def fast_aes_enc(key: bytes, iv: bytes, pt: bytes, aad: bytes = b"") -> bytes:
        return AESGCM(key).encrypt(iv, pt, aad or None)

    def fast_aes_dec(key: bytes, iv: bytes, ct: bytes, aad: bytes = b"") -> bytes:
        try:
            return AESGCM(key).decrypt(iv, ct, aad or None)
        except Exception as exc:  # InvalidTag и пр.
            raise IntegrityError("AES-GCM: authentication failed") from exc

    def fast_xchacha_enc(key: bytes, nonce24: bytes, pt: bytes, aad: bytes = b"") -> bytes:
        sub, n12 = _chacha.xchacha20_subkey_nonce(key, nonce24)
        return ChaCha20Poly1305(sub).encrypt(n12, pt, aad or None)

    def fast_xchacha_dec(key: bytes, nonce24: bytes, ct: bytes, aad: bytes = b"") -> bytes:
        sub, n12 = _chacha.xchacha20_subkey_nonce(key, nonce24)
        try:
            return ChaCha20Poly1305(sub).decrypt(n12, ct, aad or None)
        except Exception as exc:
            raise IntegrityError("XChaCha20-Poly1305: authentication failed") from exc

    # --- обязательная сверка с эталоном, иначе ускоритель не включаем ---
    try:
        for size in (0, 1, 15, 16, 17, 64, 333):
            key = os.urandom(32)
            pt = os.urandom(size)
            aad = os.urandom(size % 11)
            iv12 = os.urandom(12)
            n24 = os.urandom(24)
            if fast_aes_enc(key, iv12, pt, aad) != _pure_aes_enc(key, iv12, pt, aad):
                return "pure-python (accelerator mismatch: AES-GCM)"
            if fast_xchacha_enc(key, n24, pt, aad) != _pure_xchacha_enc(key, n24, pt, aad):
                return "pure-python (accelerator mismatch: XChaCha20-Poly1305)"
            if fast_aes_dec(key, iv12, _pure_aes_enc(key, iv12, pt, aad), aad) != pt:
                return "pure-python (accelerator mismatch: AES-GCM decrypt)"
            if fast_xchacha_dec(key, n24, _pure_xchacha_enc(key, n24, pt, aad), aad) != pt:
                return "pure-python (accelerator mismatch: XChaCha decrypt)"
    except Exception:
        return "pure-python (accelerator unusable)"

    global aes_gcm_encrypt, aes_gcm_decrypt, xchacha_encrypt, xchacha_decrypt
    aes_gcm_encrypt = fast_aes_enc
    aes_gcm_decrypt = fast_aes_dec
    xchacha_encrypt = fast_xchacha_enc
    xchacha_decrypt = fast_xchacha_dec
    try:
        import cryptography  # type: ignore

        ver = cryptography.__version__
    except Exception:  # pragma: no cover
        ver = "?"
    return f"openssl via cryptography {ver}"


BACKEND = _try_accelerate()


def backend_info() -> dict:
    return {
        "aead_backend": BACKEND,
        "threefish": "pure-python (always)",
        "hashes": "hashlib (OpenSSL): SHA3-512, SHAKE256, BLAKE2b, scrypt, PBKDF2",
        "note": "формат контейнера не зависит от бэкенда / container format is backend-independent",
    }
