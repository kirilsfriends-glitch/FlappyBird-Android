"""
triglyph.x25519 — X25519 (RFC 7748): обмен ключами на кривой Curve25519.

Чистый Python, лестница Монтгомери с постоянным числом итераций и
условной перестановкой без ветвлений по секретным битам. Используется для
асимметричного режима TRIGLYPH: «зашифровать для получателя по его
публичному ключу, не зная общего пароля».
"""

from __future__ import annotations

import hashlib
import secrets

from ._util import CryptoError, random_bytes

__all__ = [
    "X25519_KEY_SIZE",
    "generate_private_key",
    "public_key",
    "x25519",
    "key_exchange",
]

X25519_KEY_SIZE = 32

_P = (1 << 255) - 19
_A24 = 121665
_BASE_U = 9


def _cswap(swap: int, x2: int, x3: int) -> tuple[int, int]:
    # swap ∈ {0,1}; маска без ветвления по секрету
    mask = -swap & ((1 << 256) - 1)
    dummy = mask & (x2 ^ x3)
    return x2 ^ dummy, x3 ^ dummy


def _decode_scalar(k: bytes) -> int:
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")
    b = bytearray(u)
    b[31] &= 127  # игнорируем старший бит (RFC 7748 §5)
    return int.from_bytes(bytes(b), "little") % _P


def x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """Скалярное умножение на кривой Curve25519 (RFC 7748 §5)."""
    k = _decode_scalar(scalar)
    u = _decode_u(u_coord)
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + _A24 * e) % _P)) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    result = (x2 * pow(z2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


def generate_private_key() -> bytes:
    """Случайный секретный скаляр (32 байта, «зажимается» при использовании)."""
    return secrets.token_bytes(32)


def public_key(private: bytes) -> bytes:
    """Публичный ключ = X25519(private, 9)."""
    return x25519(private, _BASE_U.to_bytes(32, "little"))


def key_exchange(private: bytes, peer_public: bytes) -> bytes:
    """Общий секрет с проверкой на вырожденные (low-order) точки."""
    shared = x25519(private, peer_public)
    if shared == b"\x00" * 32:
        raise CryptoError("X25519: degenerate shared secret (low-order peer key)")
    return shared
