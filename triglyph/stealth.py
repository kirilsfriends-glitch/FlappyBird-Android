"""
triglyph.stealth — «стелс-оболочка»: контейнер без узнаваемой сигнатуры.

Обычный контейнер начинается с байтов ``TRGLYPH\\x01``. Это удобно, но по такой
сигнатуре файл находится тривиальным grep-ом. Стелс-оболочка накладывает на
весь контейнер гамму SHAKE-256, выведенную из открытого случайного префикса,
и на выходе получается строка, статистически неотличимая от случайного шума.

ЧЕСТНОЕ ПРЕДУПРЕЖДЕНИЕ. Гамма выводится из ОТКРЫТОГО префикса, то есть
снимается кем угодно. Это обфускация формата, а не дополнительный шифр:
криптостойкости она не добавляет ни бита. Она защищает лишь от
автоматического поиска по сигнатуре и от «у вас тут явно шифрованный файл».
"""

from __future__ import annotations

import hashlib

from ._util import FormatError, random_bytes, u64, xor_bytes

__all__ = ["PREFIX_SIZE", "mask_block", "wrap", "unwrap", "looks_stealth"]

PREFIX_SIZE = 32
BLOCK = 1 << 16
_DOMAIN = b"TRIGLYPH/v1|stealth|"


def mask_block(prefix: bytes, index: int, length: int = BLOCK) -> bytes:
    """Блок гаммы обфускации: SHAKE256(prefix || index)."""
    return hashlib.shake_256(_DOMAIN + prefix + u64(index)).digest(length)


def _mask(prefix: bytes, data: bytes) -> bytes:
    out = []
    for i in range(0, len(data), BLOCK):
        piece = data[i : i + BLOCK]
        out.append(xor_bytes(piece, mask_block(prefix, i // BLOCK, len(piece))))
    return b"".join(out)


def wrap(container: bytes) -> bytes:
    prefix = random_bytes(PREFIX_SIZE)
    return prefix + _mask(prefix, container)


def unwrap(blob: bytes) -> bytes:
    if len(blob) < PREFIX_SIZE:
        raise FormatError("stealth container too short")
    prefix, body = blob[:PREFIX_SIZE], blob[PREFIX_SIZE:]
    return _mask(prefix, body)


def looks_stealth(blob: bytes, magic: bytes) -> bool:
    """Проверяет, не является ли blob стелс-обёрткой над контейнером."""
    if len(blob) < PREFIX_SIZE + len(magic):
        return False
    head = xor_bytes(
        blob[PREFIX_SIZE : PREFIX_SIZE + len(magic)],
        mask_block(blob[:PREFIX_SIZE], 0, len(magic)),
    )
    return head == magic


class MaskStream:
    """Последовательная гамма обфускации с кэшем текущего блока."""

    __slots__ = ("prefix", "offset", "_blk_idx", "_blk")

    def __init__(self, prefix: bytes, offset: int = 0) -> None:
        self.prefix = prefix
        self.offset = offset
        self._blk_idx = -1
        self._blk = b""

    def apply(self, data: bytes) -> bytes:
        out = []
        pos = 0
        while pos < len(data):
            idx, within = divmod(self.offset, BLOCK)
            if idx != self._blk_idx:
                self._blk = mask_block(self.prefix, idx, BLOCK)
                self._blk_idx = idx
            take = min(BLOCK - within, len(data) - pos)
            out.append(xor_bytes(data[pos : pos + take], self._blk[within : within + take]))
            pos += take
            self.offset += take
        return b"".join(out)


class MaskedWriter:
    """Обёртка над файлом: всё записанное проходит через гамму обфускации."""

    def __init__(self, fout, prefix: bytes) -> None:
        self._f = fout
        self._m = MaskStream(prefix)

    def write(self, data: bytes) -> int:
        return self._f.write(self._m.apply(data))

    def flush(self) -> None:
        if hasattr(self._f, "flush"):
            self._f.flush()


class MaskedReader:
    """Обёртка над файлом: всё прочитанное снимается с гаммы обфускации."""

    def __init__(self, fin, prefix: bytes, pending: bytes = b"") -> None:
        self._f = fin
        self._m = MaskStream(prefix)
        self._buf = bytearray(self._m.apply(pending))

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            rest = self._f.read()
            data = bytes(self._buf) + self._m.apply(rest)
            self._buf.clear()
            return data
        while len(self._buf) < n:
            block = self._f.read(max(n - len(self._buf), BLOCK))
            if not block:
                break
            self._buf.extend(self._m.apply(block))
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out
