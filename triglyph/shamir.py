"""
triglyph.shamir — разделение секрета по схеме Шамира в поле GF(2^8).

Зачем в шифре: главный ключ можно разрезать на N частей так, что любые K из
них восстанавливают ключ, а K−1 частей не дают о нём вообще ничего
(информационно-теоретическая стойкость, не вычислительная).

Части выводятся текстом на любой из трёх письменностей — их можно разослать
разным людям, распечатать или продиктовать.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from . import armor as _armor
from ._util import CryptoError, FormatError, ct_eq

__all__ = ["Share", "split_secret", "combine_shares", "SHARE_MAGIC"]

SHARE_MAGIC = 0xA5

# --- поле GF(2^8) с полиномом 0x11B (как в AES) ----------------------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)
    _x &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    """Одна часть секрета."""

    index: int          # x-координата, 1..255
    threshold: int      # сколько частей нужно для восстановления
    total: int          # сколько всего выпущено
    payload: bytes      # y-координаты по одному байту на байт секрета

    def to_bytes(self) -> bytes:
        body = bytes([SHARE_MAGIC, self.index, self.threshold, self.total]) + self.payload
        return body + hashlib.sha3_256(b"TRIGLYPH/share|" + body).digest()[:4]

    def armored(self, kind: str = "latin") -> str:
        return _armor.encode(self.to_bytes(), kind)

    @classmethod
    def parse(cls, data: bytes | str) -> "Share":
        if isinstance(data, str):
            data = _armor.decode(data.strip())
        if len(data) < 9:
            raise FormatError("share too short")
        body, checksum = data[:-4], data[-4:]
        if not ct_eq(hashlib.sha3_256(b"TRIGLYPH/share|" + body).digest()[:4], checksum):
            raise FormatError("часть секрета повреждена (checksum) / corrupted share")
        if body[0] != SHARE_MAGIC:
            raise FormatError("not a TRIGLYPH share")
        return cls(index=body[1], threshold=body[2], total=body[3], payload=body[4:])


def split_secret(secret: bytes, threshold: int, shares: int) -> List[Share]:
    """Разрезать секрет на `shares` частей, порог восстановления `threshold`."""
    if not 2 <= threshold <= 255:
        raise ValueError("threshold must be in 2..255")
    if not threshold <= shares <= 255:
        raise ValueError("shares must be in threshold..255")
    if not secret:
        raise ValueError("secret must not be empty")

    # контрольная сумма внутри секрета — чтобы поймать подменённую часть
    guarded = secret + hashlib.sha3_256(b"TRIGLYPH/secret|" + secret).digest()[:4]

    out: List[List[int]] = [[] for _ in range(shares)]
    for byte in guarded:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for si in range(shares):
            x = si + 1
            acc = 0
            for c in reversed(coeffs):  # схема Горнера
                acc = _mul(acc, x) ^ c
            out[si].append(acc)
    return [
        Share(index=i + 1, threshold=threshold, total=shares, payload=bytes(vals))
        for i, vals in enumerate(out)
    ]


def combine_shares(shares: Sequence[Share | bytes | str]) -> bytes:
    """Восстановить секрет из частей (нужно не меньше порога)."""
    parsed: List[Share] = [s if isinstance(s, Share) else Share.parse(s) for s in shares]
    if not parsed:
        raise ValueError("no shares provided")
    threshold = parsed[0].threshold
    if len({s.threshold for s in parsed}) != 1:
        raise CryptoError("части принадлежат разным секретам (разный порог)")
    if len({s.index for s in parsed}) != len(parsed):
        raise CryptoError("повторяющиеся части: индексы должны отличаться")
    if len(parsed) < threshold:
        raise CryptoError(f"нужно минимум {threshold} частей, дано {len(parsed)}")
    if len({len(s.payload) for s in parsed}) != 1:
        raise CryptoError("части разной длины")

    parsed = parsed[:threshold]
    length = len(parsed[0].payload)
    out = bytearray()
    for pos in range(length):
        acc = 0
        for i, si in enumerate(parsed):
            num, den = 1, 1
            for j, sj in enumerate(parsed):
                if i == j:
                    continue
                num = _mul(num, sj.index)
                den = _mul(den, si.index ^ sj.index)
            acc ^= _mul(si.payload[pos], _div(num, den))
        out.append(acc)
    guarded = bytes(out)
    secret, checksum = guarded[:-4], guarded[-4:]
    if not ct_eq(hashlib.sha3_256(b"TRIGLYPH/secret|" + secret).digest()[:4], checksum):
        raise CryptoError(
            "секрет не восстановился: части не от одного секрета или повреждены"
        )
    return secret
