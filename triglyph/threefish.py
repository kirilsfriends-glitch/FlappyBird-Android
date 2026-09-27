"""
triglyph.threefish — Threefish-1024 (блочный шифр из семейства Skein) + режим CTR.

Threefish — ARX-шифр с блоком и ключом по 1024 бита и 128-битным твиком,
80 раундов. В TRIGLYPH он используется ТРЕТЬИМ (внешним) слоем каскада как
«страховка на случай прорыва» в AES или ChaCha: даже если внешний слой
окажется слабым, он остаётся биекцией и не может ослабить внутренние слои,
а целостность обеспечивается независимым HMAC-SHA3-512.

Спецификация: Skein 1.3, раздел 3.3 (таблицы вращений и перестановок).
"""

from __future__ import annotations

import struct
from typing import List

from ._util import xor_bytes

__all__ = ["Threefish1024", "threefish1024_ctr_xor"]

_M64 = 0xFFFFFFFFFFFFFFFF
_C240 = 0x1BD11BDAA9FC1A22  # константа чётности ключа (Skein 1.3)

# Таблица вращений R[d mod 8][j] для Threefish-1024 (Skein 1.3, табл. 4)
_ROT = (
    (24, 13, 8, 47, 8, 17, 22, 37),
    (38, 19, 10, 55, 49, 18, 23, 52),
    (33, 4, 51, 13, 34, 41, 59, 17),
    (5, 20, 48, 41, 47, 28, 16, 25),
    (41, 9, 37, 31, 12, 47, 44, 30),
    (16, 34, 56, 51, 4, 53, 42, 41),
    (31, 44, 47, 46, 19, 42, 44, 25),
    (9, 48, 35, 52, 23, 31, 37, 20),
)

# Перестановка слов для Nw = 16
_PERM = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)
_INV_PERM = [0] * 16
for _i, _p in enumerate(_PERM):
    _INV_PERM[_p] = _i
_INV_PERM = tuple(_INV_PERM)  # type: ignore[assignment]

_NW = 16
_ROUNDS = 80
_UNPACK = struct.Struct("<16Q").unpack
_PACK = struct.Struct("<16Q").pack


def _rotl(x: int, n: int) -> int:
    x &= _M64
    return ((x << n) | (x >> (64 - n))) & _M64


class Threefish1024:
    """Threefish-1024: ключ 128 байт, твик 16 байт, блок 128 байт."""

    __slots__ = ("ks", "tw")

    def __init__(self, key: bytes, tweak: bytes = b"\x00" * 16) -> None:
        if len(key) != 128:
            raise ValueError("Threefish-1024 key must be 128 bytes")
        if len(tweak) != 16:
            raise ValueError("tweak must be 16 bytes")
        k = list(_UNPACK(key))
        parity = _C240
        for w in k:
            parity ^= w
        k.append(parity & _M64)
        t = list(struct.unpack("<2Q", tweak))
        t.append((t[0] ^ t[1]) & _M64)
        # предвычисление 21 подключа (по одному на каждые 4 раунда + финальный)
        ks: List[List[int]] = []
        for s in range(_ROUNDS // 4 + 1):
            sub = [k[(s + i) % (_NW + 1)] for i in range(_NW)]
            sub[_NW - 3] = (sub[_NW - 3] + t[s % 3]) & _M64
            sub[_NW - 2] = (sub[_NW - 2] + t[(s + 1) % 3]) & _M64
            sub[_NW - 1] = (sub[_NW - 1] + s) & _M64
            ks.append(sub)
        self.ks = ks
        self.tw = tweak

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 128:
            raise ValueError("Threefish-1024 block must be 128 bytes")
        v = list(_UNPACK(block))
        ks = self.ks
        for d in range(_ROUNDS):
            if d % 4 == 0:
                sub = ks[d // 4]
                for i in range(_NW):
                    v[i] = (v[i] + sub[i]) & _M64
            rot = _ROT[d % 8]
            nv = [0] * _NW
            for j in range(_NW // 2):
                x0 = v[2 * j]
                x1 = v[2 * j + 1]
                y0 = (x0 + x1) & _M64
                y1 = _rotl(x1, rot[j]) ^ y0
                nv[2 * j] = y0
                nv[2 * j + 1] = y1
            v = [nv[_PERM[i]] for i in range(_NW)]
        sub = ks[_ROUNDS // 4]
        for i in range(_NW):
            v[i] = (v[i] + sub[i]) & _M64
        return _PACK(*v)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 128:
            raise ValueError("Threefish-1024 block must be 128 bytes")
        v = list(_UNPACK(block))
        ks = self.ks
        sub = ks[_ROUNDS // 4]
        for i in range(_NW):
            v[i] = (v[i] - sub[i]) & _M64
        for d in range(_ROUNDS - 1, -1, -1):
            pv = [v[_INV_PERM[i]] for i in range(_NW)]
            rot = _ROT[d % 8]
            nv = [0] * _NW
            for j in range(_NW // 2):
                y0 = pv[2 * j]
                y1 = pv[2 * j + 1]
                x1 = _rotl(y1 ^ y0, 64 - rot[j])
                x0 = (y0 - x1) & _M64
                nv[2 * j] = x0
                nv[2 * j + 1] = x1
            v = nv
            if d % 4 == 0:
                sub = ks[d // 4]
                for i in range(_NW):
                    v[i] = (v[i] - sub[i]) & _M64
        return _PACK(*v)


def threefish1024_ctr_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """Режим счётчика: гамма = E_K(nonce||counter), твик = (nonce_hi, counter)."""
    if len(key) != 128:
        raise ValueError("Threefish-1024 key must be 128 bytes")
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    if not data:
        return b""
    tf = Threefish1024(key, nonce)
    block_count = (len(data) + 127) // 128
    enc = tf.encrypt_block
    pad = b"\x00" * 96
    ks = b"".join(
        enc(nonce + (counter + i).to_bytes(16, "big") + pad) for i in range(block_count)
    )
    return xor_bytes(data, ks)
