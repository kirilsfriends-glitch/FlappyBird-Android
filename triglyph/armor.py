"""
triglyph.armor — «броня»: представление шифртекста печатным текстом
на трёх письменностях.

Зачем. Шифртекст — это байты. Чтобы отправить их в мессенджере, почте или
на бумаге, нужен текстовый вид. Base64 всегда выглядит как base64. TRIGLYPH
умеет иначе:

  * hanzi   — 4096 иероглифов (U+4E00…U+5DFF), 12 бит на знак.
              Плотнее base64 (1.5 байта на знак) и выглядит как китайский текст.
  * cyrillic— 32 буквы русского алфавита (без «ё»), 5 бит на букву.
  * latin   — Base64URL без набивки.
  * grouped — латиница группами по 5 знаков для диктовки/переписывания от руки.

Каждая броня самоописываема: по первому символу и по алфавиту декодер
определяет тип автоматически. Контрольная сумма ловит опечатки ДО того,
как в дело вступит криптография (чтобы отличать «сломал при копировании»
от «подделка»).
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Iterable, Tuple

from ._util import FormatError, ct_eq

__all__ = [
    "ARMORS",
    "encode",
    "decode",
    "detect",
    "wrap_lines",
    "BEGIN_MARK",
    "END_MARK",
    "wrap_message",
    "unwrap_message",
]

# --- алфавиты --------------------------------------------------------------

_HANZI_BASE = 0x4E00
_HANZI_COUNT = 4096  # U+4E00 … U+5DFF
_HANZI_ALPHABET = "".join(chr(_HANZI_BASE + i) for i in range(_HANZI_COUNT))
_HANZI_INDEX = {ch: i for i, ch in enumerate(_HANZI_ALPHABET)}
# маркеры остатка длины: ㊀ ㊁ ㊂ (U+3280..) — вне диапазона алфавита
_HANZI_MARKS = ("\u3280", "\u3281", "\u3282")

_CYR_ALPHABET = "абвгдежзийклмнопрстуфхцчшщъыьэюя"  # 32 буквы, без «ё»
assert len(_CYR_ALPHABET) == 32
_CYR_INDEX = {ch: i for i, ch in enumerate(_CYR_ALPHABET)}

ARMORS = ("hanzi", "cyrillic", "latin", "grouped", "raw")

# «AAAAA-BBBBB-CC»: первая группа ровно 5 знаков, дальше группы по 1..5
_GROUPED_RE = re.compile(r"[A-Z2-7]{5}(?:-[A-Z2-7]{5})*(?:-[A-Z2-7]{1,4})?")

BEGIN_MARK = "-----TRIGLYPH BEGIN / НАЧАЛО / 开始-----"
END_MARK = "-----TRIGLYPH END / КОНЕЦ / 结束-----"


def _checksum(data: bytes, n_bytes: int = 3) -> bytes:
    return hashlib.sha3_256(b"TRIGLYPH/armor|" + data).digest()[:n_bytes]


# --- hanzi (12 бит на знак) ------------------------------------------------

def _hanzi_encode(data: bytes) -> str:
    mark = _HANZI_MARKS[len(data) % 3]
    payload = data + _checksum(data)
    out = []
    # каждые 3 байта -> 2 знака; хвост дополняется нулями
    for i in range(0, len(payload), 3):
        grp = payload[i : i + 3]
        if len(grp) == 3:
            v = (grp[0] << 16) | (grp[1] << 8) | grp[2]
            out.append(_HANZI_ALPHABET[v >> 12])
            out.append(_HANZI_ALPHABET[v & 0xFFF])
        elif len(grp) == 2:
            v = (grp[0] << 16) | (grp[1] << 8)
            out.append(_HANZI_ALPHABET[v >> 12])
            out.append(_HANZI_ALPHABET[(v >> 0) & 0xFFF])
        else:
            v = grp[0] << 4
            out.append(_HANZI_ALPHABET[v & 0xFFF])
    return mark + "".join(out)


def _hanzi_decode(text: str) -> bytes:
    text = "".join(text.split())
    if not text or text[0] not in _HANZI_MARKS:
        raise FormatError("hanzi armor: missing leading marker ㊀/㊁/㊂")
    rem = _HANZI_MARKS.index(text[0])
    body = text[1:]
    bits = 0
    acc = 0
    out = bytearray()
    for ch in body:
        idx = _HANZI_INDEX.get(ch)
        if idx is None:
            raise FormatError(f"hanzi armor: character U+{ord(ch):04X} is outside the alphabet")
        acc = (acc << 12) | idx
        bits += 12
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
        acc &= (1 << bits) - 1
    payload = bytes(out)
    # восстанавливаем точную длину: (len(data)+3) байт полезной нагрузки
    total = len(payload)
    data_len = total - 3
    # хвостовые нулевые биты могли добавить лишний байт
    while data_len >= 0 and (data_len % 3) != rem:
        data_len -= 1
    if data_len < 0:
        raise FormatError("hanzi armor: inconsistent length marker")
    data = payload[:data_len]
    got = payload[data_len : data_len + 3]
    if not ct_eq(_checksum(data), got):
        raise FormatError("hanzi armor: checksum mismatch (текст повреждён при копировании)")
    return data


# --- cyrillic (base32, 5 бит на букву) -------------------------------------

def _cyr_encode(data: bytes) -> str:
    payload = data + _checksum(data, 2)
    out = []
    acc = 0
    bits = 0
    for byte in payload:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_CYR_ALPHABET[(acc >> bits) & 31])
        acc &= (1 << bits) - 1
    if bits:
        out.append(_CYR_ALPHABET[(acc << (5 - bits)) & 31])
    return "".join(out)


def _cyr_decode(text: str) -> bytes:
    text = "".join(text.split()).lower().replace("ё", "е")
    acc = 0
    bits = 0
    out = bytearray()
    for ch in text:
        idx = _CYR_INDEX.get(ch)
        if idx is None:
            raise FormatError(f"cyrillic armor: символ «{ch}» не входит в алфавит")
        acc = (acc << 5) | idx
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
        acc &= (1 << bits) - 1
    payload = bytes(out)
    if len(payload) < 2:
        raise FormatError("cyrillic armor: слишком короткая строка")
    data, got = payload[:-2], payload[-2:]
    if not ct_eq(_checksum(data, 2), got):
        raise FormatError("cyrillic armor: не сходится контрольная сумма")
    return data


# --- latin -----------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes:
    text = "".join(text.split())
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001
        raise FormatError(f"latin armor: invalid base64 ({exc})") from exc


def _grouped_encode(data: bytes) -> str:
    payload = data + _checksum(data, 2)
    raw = base64.b32encode(payload).decode("ascii").rstrip("=")
    return "-".join(raw[i : i + 5] for i in range(0, len(raw), 5))


def _grouped_decode(text: str) -> bytes:
    raw = re.sub(r"[\s-]", "", text).upper()
    raw += "=" * (-len(raw) % 8)
    try:
        payload = base64.b32decode(raw)
    except Exception as exc:  # noqa: BLE001
        raise FormatError(f"grouped armor: invalid base32 ({exc})") from exc
    if len(payload) < 2:
        raise FormatError("grouped armor: строка слишком короткая")
    data, got = payload[:-2], payload[-2:]
    if not ct_eq(_checksum(data, 2), got):
        raise FormatError("grouped armor: не сходится контрольная сумма")
    return data


# --- публичный интерфейс ---------------------------------------------------

_ENCODERS = {
    "hanzi": _hanzi_encode,
    "cyrillic": _cyr_encode,
    "latin": _b64_encode,
    "grouped": _grouped_encode,
}
_DECODERS = {
    "hanzi": _hanzi_decode,
    "cyrillic": _cyr_decode,
    "latin": _b64_decode,
    "grouped": _grouped_decode,
}


def encode(data: bytes, kind: str = "latin", width: int = 0) -> str:
    if kind == "raw":
        raise ValueError("raw armor is binary; use bytes directly")
    if kind not in _ENCODERS:
        raise ValueError(f"unknown armor '{kind}', expected one of {ARMORS}")
    text = _ENCODERS[kind](data)
    return wrap_lines(text, width) if width else text


def decode(text: str, kind: str | None = None) -> bytes:
    """Разбор брони. Без указания вида — автоопределение с откатом.

    Короткие строки base32 и base64 в принципе неразличимы по алфавиту,
    поэтому при автоопределении мы пробуем кандидатов по очереди и берём
    первого, кто разобрался без ошибки.
    """
    if kind is not None:
        if kind not in _DECODERS:
            raise FormatError(f"unknown armor '{kind}'")
        return _DECODERS[kind](text)

    # сначала брони с контрольной суммой (они сами себя опознают),
    # base64 — последним, потому что принимает почти любую строку
    order = ["hanzi", "cyrillic", "grouped", "latin"]
    last: Exception | None = None
    for candidate in order:
        try:
            return _DECODERS[candidate](text)
        except Exception as exc:  # noqa: BLE001, PERF203
            last = exc
    raise FormatError(f"не удалось разобрать броню / cannot decode armor: {last}")


def detect(text: str) -> str:
    """Автоопределение брони по алфавиту.

    Оговорка: очень короткая `grouped`-строка (меньше одной группы, то есть
    без дефиса) неотличима от base64 — для неё указывайте вид явно.
    """
    s = "".join(text.split())
    if not s:
        raise FormatError("empty armor text")
    if s[0] in _HANZI_MARKS:
        return "hanzi"
    if any(ch in _HANZI_INDEX for ch in s[:8]):
        return "hanzi"
    head = s[:16].lower().replace("ё", "е")
    if head and all(ch in _CYR_INDEX for ch in head):
        return "cyrillic"
    # grouped: строгая структура «5-5-5…», иначе случайная base64-строка
    # с дефисом иногда принималась бы за неё
    if _GROUPED_RE.fullmatch(s.upper()):
        return "grouped"
    return "latin"


def wrap_lines(text: str, width: int = 64) -> str:
    if width <= 0:
        return text
    return "\n".join(text[i : i + width] for i in range(0, len(text), width))


def wrap_message(armored: str, headers: Iterable[Tuple[str, str]] = ()) -> str:
    """Оборачивает броню в заголовки, похожие на PEM (для файлов и почты)."""
    lines = [BEGIN_MARK]
    for key, value in headers:
        lines.append(f"{key}: {value}")
    if headers:
        lines.append("")
    lines.append(armored)
    lines.append(END_MARK)
    return "\n".join(lines) + "\n"


def unwrap_message(text: str) -> tuple[str, dict]:
    """Извлекает броню и заголовки из обёртки. Терпима к «мусору» вокруг."""
    if BEGIN_MARK not in text:
        return text.strip(), {}
    body = text.split(BEGIN_MARK, 1)[1]
    body = body.split(END_MARK, 1)[0]
    lines = [ln.strip() for ln in body.strip().splitlines()]
    headers: dict = {}
    idx = 0
    while idx < len(lines) and ":" in lines[idx] and not lines[idx].startswith("-"):
        key, _, value = lines[idx].partition(":")
        headers[key.strip()] = value.strip()
        idx += 1
    payload = "".join(ln for ln in lines[idx:] if ln)
    return payload, headers
