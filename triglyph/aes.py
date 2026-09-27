"""
triglyph.aes — AES-128/192/256 (FIPS-197), режимы CTR и GCM (NIST SP 800-38D).

Чистый Python. S-box и таблицы раундов вычисляются из математики поля GF(2^8)
при импорте — никаких «зашитых» констант, которые можно опечатать.

Замечание о производительности: это программная реализация на Python, она не
использует AES-NI и не является константной по времени относительно кэша.
Для сценария «шифрование текста/сообщений» этого достаточно; см. docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import struct
from typing import List

from ._util import IntegrityError, ct_eq, u32, xor_bytes

__all__ = [
    "AES",
    "aes_ctr_xor",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "S_BOX",
]

_MASK32 = 0xFFFFFFFF


# --------------------------------------------------------------------------
# Поле GF(2^8): экспоненты/логарифмы, S-box, таблицы Te
# --------------------------------------------------------------------------

def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r & 0xFF


def _build_sbox() -> tuple[List[int], List[int]]:
    # мультипликативная инверсия в GF(2^8) через таблицы log/exp (генератор 3)
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _gmul(x, 3)
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    def inv(a: int) -> int:
        return 0 if a == 0 else exp[255 - log[a]]

    sbox = [0] * 256
    for a in range(256):
        c = inv(a)
        s = c
        for _ in range(4):
            c = ((c << 1) | (c >> 7)) & 0xFF
            s ^= c
        sbox[a] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


S_BOX, INV_S_BOX = _build_sbox()


def _build_te() -> tuple[List[int], List[int], List[int], List[int]]:
    te0: List[int] = []
    for i in range(256):
        s = S_BOX[i]
        s2 = _xtime(s)
        s3 = s2 ^ s
        te0.append(((s2 << 24) | (s << 16) | (s << 8) | s3) & _MASK32)
    te1 = [((w >> 8) | (w << 24)) & _MASK32 for w in te0]
    te2 = [((w >> 16) | (w << 16)) & _MASK32 for w in te0]
    te3 = [((w >> 24) | (w << 8)) & _MASK32 for w in te0]
    return te0, te1, te2, te3


_TE0, _TE1, _TE2, _TE3 = _build_te()
_RCON = [0x01000000]
for _i in range(1, 10):
    _RCON.append((_xtime(_RCON[-1] >> 24) << 24) & _MASK32)


class AES:
    """AES-блок с расширенным ключом. Поддерживает 128/192/256 бит."""

    __slots__ = ("nr", "rk", "key_size")

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.key_size = len(key) * 8
        nk = len(key) // 4
        self.nr = nk + 6
        w = list(struct.unpack(f"!{nk}I", key))
        for i in range(nk, 4 * (self.nr + 1)):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) | (t >> 24)) & _MASK32  # RotWord
                t = (
                    (S_BOX[(t >> 24) & 0xFF] << 24)
                    | (S_BOX[(t >> 16) & 0xFF] << 16)
                    | (S_BOX[(t >> 8) & 0xFF] << 8)
                    | S_BOX[t & 0xFF]
                )
                t ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = (
                    (S_BOX[(t >> 24) & 0xFF] << 24)
                    | (S_BOX[(t >> 16) & 0xFF] << 16)
                    | (S_BOX[(t >> 8) & 0xFF] << 8)
                    | S_BOX[t & 0xFF]
                )
            w.append((w[i - nk] ^ t) & _MASK32)
        self.rk = w

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        rk = self.rk
        s0, s1, s2, s3 = struct.unpack("!4I", block)
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3]
        k = 4
        te0, te1, te2, te3 = _TE0, _TE1, _TE2, _TE3
        for _ in range(self.nr - 1):
            t0 = te0[(s0 >> 24) & 0xFF] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ rk[k]
            t1 = te0[(s1 >> 24) & 0xFF] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ rk[k + 1]
            t2 = te0[(s2 >> 24) & 0xFF] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ rk[k + 2]
            t3 = te0[(s3 >> 24) & 0xFF] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ rk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        sb = S_BOX
        t0 = ((sb[(s0 >> 24) & 0xFF] << 24) | (sb[(s1 >> 16) & 0xFF] << 16) | (sb[(s2 >> 8) & 0xFF] << 8) | sb[s3 & 0xFF]) ^ rk[k]
        t1 = ((sb[(s1 >> 24) & 0xFF] << 24) | (sb[(s2 >> 16) & 0xFF] << 16) | (sb[(s3 >> 8) & 0xFF] << 8) | sb[s0 & 0xFF]) ^ rk[k + 1]
        t2 = ((sb[(s2 >> 24) & 0xFF] << 24) | (sb[(s3 >> 16) & 0xFF] << 16) | (sb[(s0 >> 8) & 0xFF] << 8) | sb[s1 & 0xFF]) ^ rk[k + 2]
        t3 = ((sb[(s3 >> 24) & 0xFF] << 24) | (sb[(s0 >> 16) & 0xFF] << 16) | (sb[(s1 >> 8) & 0xFF] << 8) | sb[s2 & 0xFF]) ^ rk[k + 3]
        return struct.pack("!4I", t0 & _MASK32, t1 & _MASK32, t2 & _MASK32, t3 & _MASK32)

    def decrypt_block(self, block: bytes) -> bytes:
        """Обратное преобразование (нужно только для самопроверок; CTR/GCM не использует)."""
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = [list(block[i::4]) for i in range(4)]  # column-major -> rows
        rk = self.rk

        def add_round_key(rnd: int) -> None:
            for c in range(4):
                w = rk[rnd * 4 + c]
                state[0][c] ^= (w >> 24) & 0xFF
                state[1][c] ^= (w >> 16) & 0xFF
                state[2][c] ^= (w >> 8) & 0xFF
                state[3][c] ^= w & 0xFF

        add_round_key(self.nr)
        for rnd in range(self.nr - 1, -1, -1):
            for r in range(1, 4):  # InvShiftRows
                state[r] = state[r][-r:] + state[r][:-r]
            for r in range(4):  # InvSubBytes
                state[r] = [INV_S_BOX[v] for v in state[r]]
            add_round_key(rnd)
            if rnd:  # InvMixColumns
                for c in range(4):
                    a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
                    state[0][c] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
                    state[1][c] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
                    state[2][c] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
                    state[3][c] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
        return bytes(state[r][c] for c in range(4) for r in range(4))


# --------------------------------------------------------------------------
# CTR
# --------------------------------------------------------------------------

def aes_ctr_xor(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    """AES-CTR: 128-битный счётчик увеличивается на 1 (mod 2^128) для каждого блока."""
    aes = AES(key)
    if len(counter_block) != 16:
        raise ValueError("counter block must be 16 bytes")
    ctr = int.from_bytes(counter_block, "big")
    enc = aes.encrypt_block
    nblocks = (len(data) + 15) // 16
    ks = b"".join(
        enc(((ctr + i) & ((1 << 128) - 1)).to_bytes(16, "big")) for i in range(nblocks)
    )
    return xor_bytes(data, ks)


# --------------------------------------------------------------------------
# GHASH / GCM
# --------------------------------------------------------------------------

_GCM_R = 0xE1000000000000000000000000000000


class _GHash:
    """GHASH с таблицей по 4-битным окнам (32 обращения на блок)."""

    __slots__ = ("tables", "acc")

    def __init__(self, h: bytes) -> None:
        hv = int.from_bytes(h, "big")
        # P[i] = H * x^i в представлении GCM (умножение на x = сдвиг вправо)
        p = [0] * 128
        v = hv
        for i in range(128):
            p[i] = v
            v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
        tables: List[List[int]] = []
        for nib in range(32):
            t = [0] * 16
            base = nib * 4
            for val in range(16):
                acc = 0
                for bit in range(4):
                    if val & (8 >> bit):
                        acc ^= p[base + bit]
                t[val] = acc
            tables.append(t)
        self.tables = tables
        self.acc = 0

    def _mul(self, x: int) -> int:
        z = 0
        tables = self.tables
        for nib in range(32):
            z ^= tables[nib][(x >> (4 * (31 - nib))) & 0xF]
        return z

    def update(self, data: bytes) -> "_GHash":
        if len(data) % 16:
            data = data + b"\x00" * (16 - len(data) % 16)
        acc = self.acc
        for i in range(0, len(data), 16):
            acc = self._mul(acc ^ int.from_bytes(data[i : i + 16], "big"))
        self.acc = acc
        return self

    def digest(self) -> bytes:
        return self.acc.to_bytes(16, "big")


def _gcm_j0(aes: AES, ghash_h: bytes, iv: bytes) -> bytes:
    if len(iv) == 12:
        return iv + b"\x00\x00\x00\x01"
    g = _GHash(ghash_h)
    g.update(iv)
    g.update(b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big"))
    return g.digest()


def _inc32(block: bytes) -> bytes:
    pre, ctr = block[:12], int.from_bytes(block[12:], "big")
    return pre + ((ctr + 1) & _MASK32).to_bytes(4, "big")


def _gctr(aes: AES, icb: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    pre = icb[:12]
    ctr = int.from_bytes(icb[12:], "big")
    enc = aes.encrypt_block
    nblocks = (len(data) + 15) // 16
    ks = b"".join(
        enc(pre + ((ctr + i) & _MASK32).to_bytes(4, "big")) for i in range(nblocks)
    )
    return xor_bytes(data, ks)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM (NIST SP 800-38D). Возвращает ciphertext || tag(16)."""
    aes = AES(key)
    h = aes.encrypt_block(b"\x00" * 16)
    j0 = _gcm_j0(aes, h, iv)
    ct = _gctr(aes, _inc32(j0), plaintext)
    g = _GHash(h)
    g.update(aad)
    g.update(ct)
    g.update((len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    tag = _gctr(aes, j0, g.digest())
    return ct + tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ct_and_tag: bytes, aad: bytes = b"") -> bytes:
    if len(ct_and_tag) < 16:
        raise IntegrityError("ciphertext too short for GCM tag")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    aes = AES(key)
    h = aes.encrypt_block(b"\x00" * 16)
    j0 = _gcm_j0(aes, h, iv)
    g = _GHash(h)
    g.update(aad)
    g.update(ct)
    g.update((len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    expected = _gctr(aes, j0, g.digest())
    if not ct_eq(expected, tag):
        raise IntegrityError("AES-GCM: authentication failed")
    return _gctr(aes, _inc32(j0), ct)
