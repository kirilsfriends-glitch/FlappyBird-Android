"""
triglyph.text — работа с текстом трёх языков: 中文 / русский / English.

Что здесь решается:

1. Нормализация Unicode. Одна и та же фраза может быть записана разными
   последовательностями кодовых точек («й» = U+0439 или U+0438+U+0306;
   полноширинные латинские буквы в китайских IME). Без нормализации
   расшифрованный текст «тот же», а байты — разные.

2. Определение письменности (Hani / Cyrl / Latn) — нужно для выбора брони
   по умолчанию и для отчётов CLI.

3. Сокрытие длины. В UTF-8 иероглиф занимает 3 байта, кириллица 2, латиница 1.
   Поэтому ДЛИНА шифртекста сама по себе выдаёт язык сообщения. Padmé
   (Nikitin et al., PETS 2019) и «языковые корзины» устраняют эту утечку.
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass
from typing import Dict, Literal

from ._util import FormatError, read_u64, u64

__all__ = [
    "normalize_text",
    "ScriptStats",
    "analyze_script",
    "detect_language",
    "pad_plaintext",
    "unpad_plaintext",
    "padme",
    "PAD_NONE",
    "PAD_PADME",
    "PAD_BUCKET",
    "PAD_FIXED",
    "LANG_NAMES",
]

PAD_NONE = 0
PAD_PADME = 1
PAD_BUCKET = 2
PAD_FIXED = 3

LANG_NAMES = {
    "zh": {"ru": "китайский", "en": "Chinese", "zh": "中文"},
    "ru": {"ru": "русский", "en": "Russian", "zh": "俄文"},
    "en": {"ru": "английский", "en": "English", "zh": "英文"},
    "mixed": {"ru": "смешанный", "en": "mixed", "zh": "混合"},
    "unknown": {"ru": "неизвестный", "en": "unknown", "zh": "未知"},
}


def normalize_text(text: str, form: Literal["NFC", "NFD", "NFKC", "NFKD"] = "NFC") -> str:
    """Каноническая нормализация текста перед шифрованием.

    NFC — умолчание: сохраняет визуальную форму, но делает представление
    однозначным для русского (комбинирующие диакритики) и китайского.
    """
    return unicodedata.normalize(form, text)


# --------------------------------------------------------------------------
# Определение письменности
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ScriptStats:
    han: int
    cyrillic: int
    latin: int
    digits: int
    other: int
    total_letters: int

    def ratio(self, name: str) -> float:
        if self.total_letters == 0:
            return 0.0
        return getattr(self, name) / self.total_letters

    def as_dict(self) -> Dict[str, int]:
        return {
            "han": self.han,
            "cyrillic": self.cyrillic,
            "latin": self.latin,
            "digits": self.digits,
            "other": self.other,
            "letters": self.total_letters,
        }


def _is_han(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x4E00 <= cp <= 0x9FFF        # CJK Unified Ideographs
        or 0x3400 <= cp <= 0x4DBF     # Extension A
        or 0xF900 <= cp <= 0xFAFF     # Compatibility Ideographs
        or 0x20000 <= cp <= 0x2FA1F   # Extensions B..
        or 0x3000 <= cp <= 0x303F     # CJK punctuation
    )


def analyze_script(text: str) -> ScriptStats:
    han = cyr = lat = dig = oth = 0
    for ch in text:
        if ch.isdigit():
            dig += 1
            continue
        if not ch.isalpha() and not _is_han(ch):
            continue
        if _is_han(ch):
            han += 1
        else:
            cp = ord(ch)
            if 0x0400 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F:
                cyr += 1
            elif cp < 0x0250:
                lat += 1
            else:
                oth += 1
    return ScriptStats(han, cyr, lat, dig, oth, han + cyr + lat + oth)


def detect_language(text: str) -> str:
    """Грубая, но надёжная эвристика по письменности: 'zh' | 'ru' | 'en' | ..."""
    st = analyze_script(text)
    if st.total_letters == 0:
        return "unknown"
    scores = {"zh": st.ratio("han"), "ru": st.ratio("cyrillic"), "en": st.ratio("latin")}
    best = max(scores, key=lambda k: scores[k])
    if scores[best] < 0.6:
        return "mixed"
    return best


# --------------------------------------------------------------------------
# Сокрытие длины
# --------------------------------------------------------------------------

def padme(length: int) -> int:
    """Padmé: округление длины вверх с потерей ≤ ~12 % и утечкой O(log log L) бит.

    Nikitin et al., «Reducing Metadata Leakage from Encrypted Files», PETS 2019.
    """
    if length <= 1:
        return max(length, 1)
    e = int(math.floor(math.log2(length)))
    s = int(math.floor(math.log2(e))) + 1 if e > 0 else 1
    z = max(e - s, 0)
    mask = (1 << z) - 1
    return (length + mask) & ~mask


def _bucket(length: int) -> int:
    """«Языковые корзины»: одинаковая длина для zh/ru/en сообщений одного смысла.

    Китайский текст в UTF-8 втрое «тяжелее» английского, поэтому мелкие
    сообщения подтягиваются к общей сетке 256 → 512 → 1024 → 2048 …
    """
    if length <= 256:
        return 256
    n = 256
    while n < length:
        n *= 2
    return n


def pad_plaintext(data: bytes, policy: int = PAD_PADME, block: int = 0) -> bytes:
    """Добавляет длину (u64) и набивку согласно политике."""
    body = u64(len(data)) + data
    if policy == PAD_NONE:
        target = len(body)
    elif policy == PAD_PADME:
        target = padme(len(body))
    elif policy == PAD_BUCKET:
        target = _bucket(len(body))
    elif policy == PAD_FIXED:
        if block <= 0:
            raise ValueError("PAD_FIXED requires block > 0")
        target = ((len(body) + block - 1) // block) * block
    else:
        raise ValueError(f"unknown padding policy {policy}")
    return body + b"\x00" * (target - len(body))


def unpad_plaintext(padded: bytes) -> bytes:
    if len(padded) < 8:
        raise FormatError("padded plaintext too short")
    n = read_u64(padded, 0)
    if n > len(padded) - 8:
        raise FormatError("declared plaintext length exceeds container")
    return padded[8 : 8 + n]
