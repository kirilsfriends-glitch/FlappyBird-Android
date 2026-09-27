"""
triglyph.chacha — ChaCha20 / HChaCha20 / XChaCha20 / Poly1305 / AEAD.

Чистый Python, без зависимостей. Реализовано строго по:
  * RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols)
  * draft-irtf-cfrg-xchacha (HChaCha20, XChaCha20-Poly1305)

Все функции проверяются известными тест-векторами (см. tests/test_vectors.py).
"""

from __future__ import annotations

import struct
from typing import Optional

from ._util import IntegrityError, ct_eq, xor_bytes

__all__ = [
    "chacha20_block",
    "chacha20_keystream",
    "chacha20_xor",
    "hchacha20",
    "xchacha20_xor",
    "poly1305_mac",
    "chacha20poly1305_encrypt",
    "chacha20poly1305_decrypt",
    "xchacha20poly1305_encrypt",
    "xchacha20poly1305_decrypt",
]

_MASK32 = 0xFFFFFFFF
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"
_UNPACK16 = struct.Struct("<16I").unpack
_PACK16 = struct.Struct("<16I").pack
_UNPACK8 = struct.Struct("<8I").unpack
_UNPACK3 = struct.Struct("<3I").unpack


def _rotl32(v: int, n: int) -> int:
    v &= _MASK32
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _core(state: list[int], rounds: int = 20) -> list[int]:
    """Двойные раунды ChaCha (развёрнуто вручную — так втрое быстрее)."""
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = state
    for _ in range(rounds // 2):
        # column round
        x0 = (x0 + x4) & _MASK32; x12 ^= x0; x12 = ((x12 << 16) | (x12 >> 16)) & _MASK32
        x8 = (x8 + x12) & _MASK32; x4 ^= x8; x4 = ((x4 << 12) | (x4 >> 20)) & _MASK32
        x0 = (x0 + x4) & _MASK32; x12 ^= x0; x12 = ((x12 << 8) | (x12 >> 24)) & _MASK32
        x8 = (x8 + x12) & _MASK32; x4 ^= x8; x4 = ((x4 << 7) | (x4 >> 25)) & _MASK32

        x1 = (x1 + x5) & _MASK32; x13 ^= x1; x13 = ((x13 << 16) | (x13 >> 16)) & _MASK32
        x9 = (x9 + x13) & _MASK32; x5 ^= x9; x5 = ((x5 << 12) | (x5 >> 20)) & _MASK32
        x1 = (x1 + x5) & _MASK32; x13 ^= x1; x13 = ((x13 << 8) | (x13 >> 24)) & _MASK32
        x9 = (x9 + x13) & _MASK32; x5 ^= x9; x5 = ((x5 << 7) | (x5 >> 25)) & _MASK32

        x2 = (x2 + x6) & _MASK32; x14 ^= x2; x14 = ((x14 << 16) | (x14 >> 16)) & _MASK32
        x10 = (x10 + x14) & _MASK32; x6 ^= x10; x6 = ((x6 << 12) | (x6 >> 20)) & _MASK32
        x2 = (x2 + x6) & _MASK32; x14 ^= x2; x14 = ((x14 << 8) | (x14 >> 24)) & _MASK32
        x10 = (x10 + x14) & _MASK32; x6 ^= x10; x6 = ((x6 << 7) | (x6 >> 25)) & _MASK32

        x3 = (x3 + x7) & _MASK32; x15 ^= x3; x15 = ((x15 << 16) | (x15 >> 16)) & _MASK32
        x11 = (x11 + x15) & _MASK32; x7 ^= x11; x7 = ((x7 << 12) | (x7 >> 20)) & _MASK32
        x3 = (x3 + x7) & _MASK32; x15 ^= x3; x15 = ((x15 << 8) | (x15 >> 24)) & _MASK32
        x11 = (x11 + x15) & _MASK32; x7 ^= x11; x7 = ((x7 << 7) | (x7 >> 25)) & _MASK32

        # diagonal round
        x0 = (x0 + x5) & _MASK32; x15 ^= x0; x15 = ((x15 << 16) | (x15 >> 16)) & _MASK32
        x10 = (x10 + x15) & _MASK32; x5 ^= x10; x5 = ((x5 << 12) | (x5 >> 20)) & _MASK32
        x0 = (x0 + x5) & _MASK32; x15 ^= x0; x15 = ((x15 << 8) | (x15 >> 24)) & _MASK32
        x10 = (x10 + x15) & _MASK32; x5 ^= x10; x5 = ((x5 << 7) | (x5 >> 25)) & _MASK32

        x1 = (x1 + x6) & _MASK32; x12 ^= x1; x12 = ((x12 << 16) | (x12 >> 16)) & _MASK32
        x11 = (x11 + x12) & _MASK32; x6 ^= x11; x6 = ((x6 << 12) | (x6 >> 20)) & _MASK32
        x1 = (x1 + x6) & _MASK32; x12 ^= x1; x12 = ((x12 << 8) | (x12 >> 24)) & _MASK32
        x11 = (x11 + x12) & _MASK32; x6 ^= x11; x6 = ((x6 << 7) | (x6 >> 25)) & _MASK32

        x2 = (x2 + x7) & _MASK32; x13 ^= x2; x13 = ((x13 << 16) | (x13 >> 16)) & _MASK32
        x8 = (x8 + x13) & _MASK32; x7 ^= x8; x7 = ((x7 << 12) | (x7 >> 20)) & _MASK32
        x2 = (x2 + x7) & _MASK32; x13 ^= x2; x13 = ((x13 << 8) | (x13 >> 24)) & _MASK32
        x8 = (x8 + x13) & _MASK32; x7 ^= x8; x7 = ((x7 << 7) | (x7 >> 25)) & _MASK32

        x3 = (x3 + x4) & _MASK32; x14 ^= x3; x14 = ((x14 << 16) | (x14 >> 16)) & _MASK32
        x9 = (x9 + x14) & _MASK32; x4 ^= x9; x4 = ((x4 << 12) | (x4 >> 20)) & _MASK32
        x3 = (x3 + x4) & _MASK32; x14 ^= x3; x14 = ((x14 << 8) | (x14 >> 24)) & _MASK32
        x9 = (x9 + x14) & _MASK32; x4 ^= x9; x4 = ((x4 << 7) | (x4 >> 25)) & _MASK32
    return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15]


def _initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    k = _UNPACK8(key)
    n = _UNPACK3(nonce)
    return [
        _SIGMA[0], _SIGMA[1], _SIGMA[2], _SIGMA[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        counter & _MASK32, n[0], n[1], n[2],
    ]


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Один 64-байтовый блок гаммы ChaCha20 (RFC 8439 §2.3)."""
    st = _initial_state(key, counter, nonce)
    out = _core(list(st))
    return _PACK16(*[(a + b) & _MASK32 for a, b in zip(out, st)])


def chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("negative length")
    blocks = []
    n = 0
    while n < length:
        blocks.append(chacha20_block(key, counter, nonce))
        counter = (counter + 1) & _MASK32
        n += 64
    return b"".join(blocks)[:length]


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 шифрование/расшифрование (XOR с гаммой)."""
    total = len(data)
    if not total:
        return b""
    st = _initial_state(key, counter, nonce)
    blocks = []
    produced = 0
    while produced < total:
        blocks.append(_PACK16(*[(a + b) & _MASK32 for a, b in zip(_core(list(st)), st)]))
        st[12] = (st[12] + 1) & _MASK32
        produced += 64
    return xor_bytes(data, b"".join(blocks))


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20: расширение нонса до 192 бит (draft-irtf-cfrg-xchacha §2.2)."""
    if len(key) != 32:
        raise ValueError("HChaCha20 key must be 32 bytes")
    if len(nonce16) != 16:
        raise ValueError("HChaCha20 nonce must be 16 bytes")
    k = _UNPACK8(key)
    n = struct.unpack("<4I", nonce16)
    st = [
        _SIGMA[0], _SIGMA[1], _SIGMA[2], _SIGMA[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        n[0], n[1], n[2], n[3],
    ]
    out = _core(st)
    return struct.pack("<8I", out[0], out[1], out[2], out[3], out[12], out[13], out[14], out[15])


def xchacha20_subkey_nonce(key: bytes, nonce24: bytes) -> tuple[bytes, bytes]:
    if len(nonce24) != 24:
        raise ValueError("XChaCha20 nonce must be 24 bytes")
    subkey = hchacha20(key, nonce24[:16])
    return subkey, b"\x00\x00\x00\x00" + nonce24[16:]


def xchacha20_xor(key: bytes, counter: int, nonce24: bytes, data: bytes) -> bytes:
    subkey, n12 = xchacha20_subkey_nonce(key, nonce24)
    return chacha20_xor(subkey, counter, n12, data)


# --------------------------------------------------------------------------
# Poly1305 (RFC 8439 §2.5)
# --------------------------------------------------------------------------

_P1305 = (1 << 130) - 5


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """Одноразовый аутентификатор Poly1305. Ключ используется РОВНО один раз."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block + b"\x01", "little") if len(block) == 16 else int.from_bytes(
            block + b"\x01", "little"
        )
        acc = ((acc + n) * r) % _P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _poly1305_key_gen(key: bytes, nonce12: bytes) -> bytes:
    return chacha20_block(key, 0, nonce12)[:32]


def _aead_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    pad1 = b"\x00" * ((16 - len(aad) % 16) % 16)
    pad2 = b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    return (
        aad
        + pad1
        + ciphertext
        + pad2
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )


def chacha20poly1305_encrypt(
    key: bytes, nonce12: bytes, plaintext: bytes, aad: bytes = b""
) -> bytes:
    """AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8). Возвращает ciphertext||tag(16)."""
    otk = _poly1305_key_gen(key, nonce12)
    ct = chacha20_xor(key, 1, nonce12, plaintext)
    tag = poly1305_mac(_aead_mac_data(aad, ct), otk)
    return ct + tag


def chacha20poly1305_decrypt(
    key: bytes, nonce12: bytes, ct_and_tag: bytes, aad: bytes = b""
) -> bytes:
    if len(ct_and_tag) < 16:
        raise IntegrityError("ciphertext too short for Poly1305 tag")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    otk = _poly1305_key_gen(key, nonce12)
    expected = poly1305_mac(_aead_mac_data(aad, ct), otk)
    if not ct_eq(expected, tag):
        raise IntegrityError("ChaCha20-Poly1305: authentication failed")
    return chacha20_xor(key, 1, nonce12, ct)


def xchacha20poly1305_encrypt(
    key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes = b""
) -> bytes:
    """XChaCha20-Poly1305: 192-битный нонс, безопасен при случайной генерации."""
    subkey, n12 = xchacha20_subkey_nonce(key, nonce24)
    return chacha20poly1305_encrypt(subkey, n12, plaintext, aad)


def xchacha20poly1305_decrypt(
    key: bytes, nonce24: bytes, ct_and_tag: bytes, aad: bytes = b""
) -> bytes:
    subkey, n12 = xchacha20_subkey_nonce(key, nonce24)
    return chacha20poly1305_decrypt(subkey, n12, ct_and_tag, aad)
