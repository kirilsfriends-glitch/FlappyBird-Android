"""
TRIGLYPH / ТРИГЛИФ / 三纹密码 — каскадный шифр для китайского, русского
и английского языков.

Быстрый старт::

    import triglyph

    blob = triglyph.encrypt_text("Атака на рассвете 黎明时分进攻", password="тайна")
    print(blob)                       # броня подбирается под язык текста
    print(triglyph.decrypt_text(blob, password="тайна"))

Состав каскада (сюита «triple»)::

    XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024-CTR → HMAC-SHA3-512

Всё написано на чистом Python из стандартной библиотеки: ни одной внешней
зависимости, разворачивается везде, где есть Python 3.9+.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "encrypt",
    "decrypt",
    "encrypt_text",
    "decrypt_text",
    "encrypt_stream",
    "decrypt_stream",
    "inspect",
    "self_test",
    "armor",
    "text",
    "shamir",
    "x25519",
    "kdf",
    "PROFILES",
    "SUITES",
    "CryptoError",
    "IntegrityError",
    "FormatError",
    "generate_keypair",
]

from . import armor, kdf, shamir, text, x25519
from ._util import CryptoError, FormatError, IntegrityError
from .cipher import (
    SUITES,
    decrypt,
    decrypt_stream,
    decrypt_text,
    encrypt,
    encrypt_stream,
    encrypt_text,
    inspect,
    self_test,
)
from .kdf import PROFILES


def generate_keypair() -> tuple[bytes, bytes]:
    """Пара ключей X25519: (секретный, публичный)."""
    priv = x25519.generate_private_key()
    return priv, x25519.public_key(priv)
