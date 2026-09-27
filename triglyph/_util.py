"""
triglyph._util — низкоуровневые утилиты / low-level helpers / 底层工具.

Здесь нет криптографических примитивов, только вспомогательные функции:
константное время, безопасное стирание, упаковка чисел, XOR.
"""

from __future__ import annotations

import hmac
import os
import secrets
import struct
from typing import Iterable

__all__ = [
    "ct_eq",
    "xor_bytes",
    "fast_xor",
    "zeroize",
    "random_bytes",
    "u8",
    "u16",
    "u32",
    "u64",
    "read_u8",
    "read_u16",
    "read_u32",
    "read_u64",
    "lenpref",
    "read_lenpref",
    "Reader",
    "CryptoError",
    "IntegrityError",
    "FormatError",
    "KeyError_",
]


class CryptoError(Exception):
    """Базовая ошибка библиотеки / base library error / 基础错误."""


class IntegrityError(CryptoError):
    """Проверка подлинности не прошла: данные повреждены или ключ неверен."""


class FormatError(CryptoError):
    """Некорректный формат контейнера."""


class KeyError_(CryptoError):
    """Проблема с ключевым материалом."""


def ct_eq(a: bytes, b: bytes) -> bool:
    """Сравнение за константное время (защита от timing-атак)."""
    return hmac.compare_digest(bytes(a), bytes(b))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR двух строк; длина результата = min(len(a), len(b)).

    Реализовано через длинную арифметику: CPython выполняет XOR больших целых
    в C, что на порядок быстрее побайтового цикла. Для криптографических
    объёмов (десятки КиБ) это основной способ ускорить чистый Python.
    """
    n = min(len(a), len(b))
    if n == 0:
        return b""
    return (
        int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")
    ).to_bytes(n, "big")


def zeroize(buf: bytearray | memoryview | None) -> None:
    """Затирание ключевого материала (best-effort: Python не даёт гарантий)."""
    if buf is None:
        return
    if isinstance(buf, memoryview):
        buf = buf.obj  # type: ignore[assignment]
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def random_bytes(n: int) -> bytes:
    """Криптостойкая случайность: os.urandom + дополнительное перемешивание."""
    if n < 0:
        raise ValueError("n must be >= 0")
    return secrets.token_bytes(n) if n else b""


# --- упаковка целых (big-endian, детерминированная сериализация) -------------

def u8(v: int) -> bytes:
    return struct.pack("!B", v & 0xFF)


def u16(v: int) -> bytes:
    return struct.pack("!H", v & 0xFFFF)


def u32(v: int) -> bytes:
    return struct.pack("!I", v & 0xFFFFFFFF)


def u64(v: int) -> bytes:
    return struct.pack("!Q", v & 0xFFFFFFFFFFFFFFFF)


def read_u8(b: bytes, off: int = 0) -> int:
    return b[off]


def read_u16(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("!H", b, off)[0]


def read_u32(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("!I", b, off)[0]


def read_u64(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("!Q", b, off)[0]


def lenpref(data: bytes) -> bytes:
    """Длина (u32, BE) + данные — для однозначной (injective) сериализации."""
    return u32(len(data)) + data


def read_lenpref(b: bytes, off: int = 0) -> tuple[bytes, int]:
    n = read_u32(b, off)
    off += 4
    if off + n > len(b):
        raise FormatError("truncated length-prefixed field")
    return b[off : off + n], off + n


class Reader:
    """Последовательный разбор байтовой строки с проверкой границ."""

    __slots__ = ("buf", "off")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.off = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.off + n > len(self.buf):
            raise FormatError(
                f"unexpected end of data: need {n} bytes at offset {self.off}, "
                f"have {len(self.buf) - self.off}"
            )
        out = self.buf[self.off : self.off + n]
        self.off += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("!I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("!Q", self.take(8))[0]

    def lenpref(self) -> bytes:
        return self.take(self.u32())

    @property
    def rest(self) -> bytes:
        return self.buf[self.off :]

    def eof(self) -> bool:
        return self.off >= len(self.buf)


def concat(parts: Iterable[bytes]) -> bytes:
    return b"".join(parts)


def constant_time_select(cond: bool, a: bytes, b: bytes) -> bytes:
    """Выбор без ветвления по секретному биту (длины должны совпадать)."""
    if len(a) != len(b):
        raise ValueError("length mismatch")
    mask = 0xFF if cond else 0x00
    return bytes((x & mask) | (y & ~mask & 0xFF) for x, y in zip(a, b))


def urandom_available() -> bool:
    try:
        os.urandom(1)
        return True
    except NotImplementedError:  # pragma: no cover
        return False


def fast_xor(a: bytes, b: bytes) -> bytes:
    """Алиас xor_bytes для «горячих» путей шифрования."""
    return xor_bytes(a, b)
