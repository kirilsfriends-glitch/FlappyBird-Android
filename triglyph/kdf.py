"""
triglyph.kdf — вывод ключей: HKDF-SHA512, парольная функция и ключевая схема.

Парольный KDF («TRIGLYPH-KDF/1») — трёхступенчатый:

    1. Нормализация пароля: Unicode NFKC + UTF-8.
       Критично для русского (ё/е, комбинирующие знаки) и китайского
       (полноширинные формы, совместимые иероглифы) — иначе один и тот же
       пароль, набранный в разных раскладках/IME, даст разные ключи.
    2. Память-затратная ступень: scrypt (или Argon2id, если доступен
       argon2-cffi). Дорогая по ОЗУ → защита от ASIC/GPU-перебора.
    3. Время-затратная ступень: PBKDF2-HMAC-SHA512 поверх результата.
       Вторая независимая ступень: слабость одной не обрушивает схему.

Затем HKDF-SHA512 (RFC 5869) с доменным разделением выдаёт независимые
подключи для каждого слоя каскада.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass
from typing import Dict, Optional

from ._util import CryptoError, KeyError_, u32, u64, zeroize

__all__ = [
    "hkdf_extract",
    "hkdf_expand",
    "hkdf",
    "normalize_password",
    "KdfProfile",
    "PROFILES",
    "derive_master_secret",
    "KeySchedule",
    "key_commitment",
    "ARGON2_AVAILABLE",
    "KDF_SCRYPT",
    "KDF_ARGON2ID",
    "KDF_RAW",
]

try:  # необязательное ускорение/усиление
    import argon2.low_level as _argon2_ll  # type: ignore

    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - зависит от окружения
    _argon2_ll = None
    ARGON2_AVAILABLE = False

KDF_SCRYPT = 1
KDF_ARGON2ID = 2
KDF_RAW = 3  # готовый 256-битный ключ, парольная ступень не нужна

_DOMAIN = b"TRIGLYPH/v1"


# --------------------------------------------------------------------------
# HKDF (RFC 5869)
# --------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha512") -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.new(hash_name).digest_size
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha512") -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if length > 255 * hlen:
        raise ValueError("HKDF: requested length too large")
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hash_name).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int, hash_name: str = "sha512") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm, hash_name), info, length, hash_name)


# --------------------------------------------------------------------------
# Нормализация пароля
# --------------------------------------------------------------------------

def normalize_password(password: str | bytes) -> bytes:
    """NFKC-нормализация и кодирование в UTF-8.

    Байтовые пароли (сырой ключевой материал) пропускаются без изменений.
    """
    if isinstance(password, bytes):
        return password
    if not isinstance(password, str):
        raise TypeError("password must be str or bytes")
    return unicodedata.normalize("NFKC", password).encode("utf-8")


# --------------------------------------------------------------------------
# Профили стойкости
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class KdfProfile:
    """Параметры парольной функции.

    scrypt_n/r/p — память ≈ 128 · r · N байт.
    pbkdf2_iters — вторая, независимая ступень.
    """

    name: str
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    pbkdf2_iters: int
    argon2_memory_kib: int
    argon2_time: int
    argon2_lanes: int

    @property
    def scrypt_memory_bytes(self) -> int:
        return 128 * self.scrypt_r * self.scrypt_n

    def describe(self) -> str:
        return (
            f"{self.name}: scrypt(N=2^{self.scrypt_n.bit_length()-1}, r={self.scrypt_r}, "
            f"p={self.scrypt_p}, ~{self.scrypt_memory_bytes // (1024*1024)} МиБ) "
            f"+ PBKDF2-SHA512×{self.pbkdf2_iters}"
        )


PROFILES: Dict[str, KdfProfile] = {
    # для тестов и слабых устройств
    "fast": KdfProfile("fast", 1 << 13, 8, 1, 20_000, 16 * 1024, 2, 2),
    # повседневный режим: ~64 МиБ ОЗУ
    "balanced": KdfProfile("balanced", 1 << 16, 8, 1, 210_000, 128 * 1024, 3, 4),
    # для долгосрочных секретов: ~256 МиБ
    "hard": KdfProfile("hard", 1 << 18, 8, 1, 600_000, 512 * 1024, 4, 4),
    # «государственный противник»: ~1 ГиБ, десятки секунд
    "paranoid": KdfProfile("paranoid", 1 << 20, 8, 2, 1_200_000, 1024 * 1024, 6, 8),
}

DEFAULT_PROFILE = "balanced"


def _scrypt(pw: bytes, salt: bytes, prof: KdfProfile, dklen: int = 64) -> bytes:
    maxmem = prof.scrypt_memory_bytes + (prof.scrypt_p + 2) * 128 * prof.scrypt_r + (1 << 22)
    try:
        return hashlib.scrypt(
            pw, salt=salt, n=prof.scrypt_n, r=prof.scrypt_r, p=prof.scrypt_p,
            maxmem=maxmem, dklen=dklen,
        )
    except (ValueError, MemoryError) as exc:  # pragma: no cover
        raise CryptoError(
            f"scrypt failed for profile '{prof.name}' "
            f"(~{prof.scrypt_memory_bytes // (1024*1024)} MiB required): {exc}"
        ) from exc


def _argon2id(pw: bytes, salt: bytes, prof: KdfProfile, dklen: int = 64) -> bytes:
    if not ARGON2_AVAILABLE:  # pragma: no cover
        raise CryptoError("Argon2id requested but argon2-cffi is not installed")
    return _argon2_ll.hash_secret_raw(  # type: ignore[union-attr]
        secret=pw,
        salt=salt,
        time_cost=prof.argon2_time,
        memory_cost=prof.argon2_memory_kib,
        parallelism=prof.argon2_lanes,
        hash_len=dklen,
        type=_argon2_ll.Type.ID,  # type: ignore[union-attr]
    )


def derive_master_secret(
    password: str | bytes,
    salt: bytes,
    profile: KdfProfile,
    kdf_id: int = KDF_SCRYPT,
    pepper: bytes = b"",
) -> bytes:
    """Парольный KDF → 64 байта мастер-секрета.

    pepper — необязательный «перец» (например, содержимое файла-ключа):
    смешивается с паролем, так что знание пароля без файла бесполезно.
    """
    if len(salt) < 16:
        raise KeyError_("salt must be at least 16 bytes")
    pw = normalize_password(password)
    if pepper:
        pw = hashlib.sha3_512(_DOMAIN + b"|pepper|" + pepper + b"|" + pw).digest()

    stage0 = hashlib.sha3_512(_DOMAIN + b"|pw|" + u32(len(pw)) + pw).digest()

    if kdf_id == KDF_SCRYPT:
        stage1 = _scrypt(stage0, hashlib.sha3_256(_DOMAIN + b"|salt|" + salt).digest(), profile)
    elif kdf_id == KDF_ARGON2ID:
        stage1 = _argon2id(stage0, hashlib.sha3_256(_DOMAIN + b"|salt|" + salt).digest()[:16], profile)
    elif kdf_id == KDF_RAW:
        stage1 = hkdf(pw, salt, _DOMAIN + b"|rawkey", 64)
        return stage1
    else:
        raise CryptoError(f"unknown KDF id {kdf_id}")

    stage2 = hashlib.pbkdf2_hmac(
        "sha512", stage1, salt + b"|pbkdf2", profile.pbkdf2_iters, dklen=64
    )
    # связываем обе ступени: результат зависит от обеих
    master = hashlib.sha3_512(
        _DOMAIN + b"|master|" + stage1 + stage2 + salt + u32(profile.pbkdf2_iters)
    ).digest()
    return master


# --------------------------------------------------------------------------
# Ключевое расписание каскада
# --------------------------------------------------------------------------

_LABELS = {
    "l1": b"layer1/xchacha20-poly1305",
    "l2": b"layer2/aes-256-gcm",
    "l3": b"layer3/threefish-1024-ctr",
    "mac": b"outer/hmac-sha3-512",
    "nonce": b"nonce-derivation",
    "commit": b"key-commitment",
    "header": b"header-binding",
}

_KEY_SIZES = {"l1": 32, "l2": 32, "l3": 128, "mac": 64, "nonce": 32, "commit": 32, "header": 32}


class KeySchedule:
    """Независимые подключи каскада, выведенные из мастер-секрета."""

    __slots__ = ("_keys", "_closed")

    def __init__(self, master: bytes, context: bytes = b"") -> None:
        if len(master) < 32:
            raise KeyError_("master secret must be at least 32 bytes")
        prk = hkdf_extract(_DOMAIN + b"|schedule|" + context, master)
        self._keys: Dict[str, bytes] = {}
        for name, label in _LABELS.items():
            self._keys[name] = hkdf_expand(prk, _DOMAIN + b"|" + label, _KEY_SIZES[name])
        self._closed = False

    def __getitem__(self, name: str) -> bytes:
        if self._closed:
            raise KeyError_("key schedule has been destroyed")
        return self._keys[name]

    @property
    def commitment(self) -> bytes:
        """Обязательство к ключу: привязывает шифртекст к конкретному ключу.

        Защита от атак с «мультиключевым» подбором (partitioning oracle) и от
        подделки контейнера, который расшифровывается под двумя разными ключами.
        """
        return hashlib.sha3_256(_DOMAIN + b"|commit|" + self._keys["commit"]).digest()

    def nonce_for(self, purpose: bytes, index: int, size: int) -> bytes:
        """Детерминированный нонс слоя: HKDF(nonce_key, purpose || index)."""
        return hkdf_expand(
            hkdf_extract(_DOMAIN + b"|nonce|", self._keys["nonce"]),
            purpose + b"|" + u64(index),
            size,
        )

    def destroy(self) -> None:
        for name, val in list(self._keys.items()):
            buf = bytearray(val)
            zeroize(buf)
            self._keys[name] = b""
        self._closed = True

    def __enter__(self) -> "KeySchedule":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()


def key_commitment(master: bytes, context: bytes = b"") -> bytes:
    return KeySchedule(master, context).commitment
