"""
triglyph.cipher — каскадный AEAD-контейнер TRIGLYPH/1.

Схема одного фрагмента (chunk), набор слоёв зависит от «сюиты»:

    открытый текст
        │  ① XChaCha20-Poly1305   (256-бит ключ, 192-бит нонс, тег 128 бит)
        ▼
    c1  │  ② AES-256-GCM          (256-бит ключ, 96-бит нонс, тег 128 бит)
        ▼
    c2  │  ③ Threefish-1024-CTR   (1024-бит ключ, 128-бит твик)
        ▼
    c3  │  ④ HMAC-SHA3-512 поверх всего контейнера
        ▼
    шифртекст

Ключи всех слоёв независимы (HKDF-SHA512 с доменным разделением), поэтому
каскад не слабее сильнейшего из слоёв: чтобы вскрыть сообщение, противнику
придётся сломать И ChaCha20, И AES, И Threefish одновременно.

Дополнительно:
  * key commitment — контейнер привязан к конкретному ключу (защита от
    partitioning-oracle и от «двусмысленных» шифртекстов);
  * каждый фрагмент связывается со своим индексом и признаком «последний»,
    поэтому перестановка, повтор и обрезание фрагментов обнаруживаются;
  * сокрытие длины (Padmé) — длина шифртекста не выдаёт язык сообщения;
  * заголовок целиком входит в AAD, подмена параметров невозможна.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
from dataclasses import dataclass, field
from typing import BinaryIO, Dict, Optional

from . import armor as _armor
from . import text as _text
from ._util import (
    CryptoError,
    FormatError,
    IntegrityError,
    KeyError_,
    Reader,
    ct_eq,
    lenpref,
    random_bytes,
    u16,
    u32,
    u64,
    u8,
)
from . import stealth as _stealth
from .backend import (
    BACKEND,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    xchacha_decrypt as xchacha20poly1305_decrypt,
    xchacha_encrypt as xchacha20poly1305_encrypt,
)
from .kdf import (
    KDF_ARGON2ID,
    KDF_RAW,
    KDF_SCRYPT,
    PROFILES,
    KeySchedule,
    derive_master_secret,
    hkdf,
)
from .threefish import threefish1024_ctr_xor
from .x25519 import key_exchange, public_key

__all__ = [
    "MAGIC",
    "VERSION",
    "SUITES",
    "Header",
    "encrypt",
    "decrypt",
    "encrypt_text",
    "decrypt_text",
    "encrypt_stream",
    "decrypt_stream",
    "inspect",
    "self_test",
    "BACKEND",
]

MAGIC = b"TRGLYPH\x01"
VERSION = 1

SUITE_TRIPLE = 1
SUITE_DUAL = 2
SUITE_SOLO = 3
SUITES = {"triple": SUITE_TRIPLE, "dual": SUITE_DUAL, "solo": SUITE_SOLO}
SUITE_NAMES = {v: k for k, v in SUITES.items()}
SUITE_DESCRIPTION = {
    SUITE_TRIPLE: "XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024-CTR → HMAC-SHA3-512",
    SUITE_DUAL: "XChaCha20-Poly1305 → AES-256-GCM → HMAC-SHA3-512",
    SUITE_SOLO: "XChaCha20-Poly1305 → HMAC-SHA3-512",
}

MODE_PASSWORD = 1
MODE_X25519_ANON = 2
MODE_X25519_AUTH = 3
MODE_RAWKEY = 4
MODE_NAMES = {
    MODE_PASSWORD: "password",
    MODE_X25519_ANON: "x25519-anonymous",
    MODE_X25519_AUTH: "x25519-authenticated",
    MODE_RAWKEY: "raw-key",
}

FLAG_PADDED_WHOLE = 1 << 0
FLAG_PADDED_LAST = 1 << 1
FLAG_HAS_AAD = 1 << 2
FLAG_STREAM = 1 << 3

PROFILE_IDS = {name: i for i, name in enumerate(PROFILES)}
PROFILE_BY_ID = {i: name for name, i in PROFILE_IDS.items()}

DEFAULT_CHUNK = 1 << 16  # 64 КиБ
SALT_SIZE = 32
MAC_SIZE = 64
MAX_CHUNK = 1 << 24  # защита от «бомб» при разборе чужого файла


# --------------------------------------------------------------------------
# Заголовок
# --------------------------------------------------------------------------

@dataclass
class Header:
    suite: int = SUITE_TRIPLE
    mode: int = MODE_PASSWORD
    kdf_id: int = KDF_SCRYPT
    profile_id: int = PROFILE_IDS["balanced"]
    pad_policy: int = _text.PAD_PADME
    flags: int = 0
    chunk_size: int = DEFAULT_CHUNK
    salt: bytes = b""
    eph_pub: bytes = b""
    sender_pub: bytes = b""
    recipient_hint: bytes = b""
    aad: bytes = b""
    commitment: bytes = b""
    version: int = VERSION

    def prefix_bytes(self) -> bytes:
        """Сериализация без обязательства к ключу (используется как контекст KDF)."""
        return (
            MAGIC
            + u8(self.version)
            + u8(self.suite)
            + u8(self.mode)
            + u8(self.kdf_id)
            + u8(self.profile_id)
            + u8(self.pad_policy)
            + u16(self.flags)
            + u32(self.chunk_size)
            + lenpref(self.salt)
            + lenpref(self.eph_pub)
            + lenpref(self.sender_pub)
            + lenpref(self.recipient_hint)
            + lenpref(self.aad)
        )

    def to_bytes(self) -> bytes:
        if len(self.commitment) != 32:
            raise FormatError("commitment must be 32 bytes")
        return self.prefix_bytes() + self.commitment

    @classmethod
    def parse(cls, data: bytes | Reader) -> tuple["Header", int]:
        r = data if isinstance(data, Reader) else Reader(data)
        start = r.off
        magic = r.take(8)
        if magic != MAGIC:
            raise FormatError(
                "это не контейнер TRIGLYPH (неверная сигнатура) / not a TRIGLYPH container"
            )
        h = cls()
        h.version = r.u8()
        if h.version != VERSION:
            raise FormatError(f"unsupported container version {h.version}")
        h.suite = r.u8()
        h.mode = r.u8()
        h.kdf_id = r.u8()
        h.profile_id = r.u8()
        h.pad_policy = r.u8()
        h.flags = r.u16()
        h.chunk_size = r.u32()
        if not (1 <= h.chunk_size <= MAX_CHUNK):
            raise FormatError(f"invalid chunk size {h.chunk_size}")
        h.salt = r.lenpref()
        h.eph_pub = r.lenpref()
        h.sender_pub = r.lenpref()
        h.recipient_hint = r.lenpref()
        h.aad = r.lenpref()
        h.commitment = r.take(32)
        if h.suite not in SUITE_NAMES:
            raise FormatError(f"unknown cipher suite {h.suite}")
        if h.mode not in MODE_NAMES:
            raise FormatError(f"unknown key mode {h.mode}")
        return h, r.off - start

    def describe(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "suite": SUITE_NAMES.get(self.suite, "?"),
            "layers": SUITE_DESCRIPTION.get(self.suite, "?"),
            "mode": MODE_NAMES.get(self.mode, "?"),
            "kdf": {KDF_SCRYPT: "scrypt+pbkdf2", KDF_ARGON2ID: "argon2id+pbkdf2", KDF_RAW: "hkdf"}.get(
                self.kdf_id, "?"
            ),
            "profile": PROFILE_BY_ID.get(self.profile_id, "custom"),
            "pad_policy": {
                _text.PAD_NONE: "none",
                _text.PAD_PADME: "padme",
                _text.PAD_BUCKET: "bucket",
                _text.PAD_FIXED: "fixed",
            }.get(self.pad_policy, "?"),
            "chunk_size": self.chunk_size,
            "salt": self.salt.hex(),
            "ephemeral_public_key": self.eph_pub.hex() or None,
            "sender_public_key": self.sender_pub.hex() or None,
            "recipient_hint": self.recipient_hint.hex() or None,
            "aad": self.aad.decode("utf-8", "replace") if self.aad else None,
            "key_commitment": self.commitment.hex(),
            "streaming": bool(self.flags & FLAG_STREAM),
        }


# --------------------------------------------------------------------------
# Получение мастер-секрета для всех режимов
# --------------------------------------------------------------------------

def _resolve_profile(profile: str | None) -> tuple[str, int]:
    name = profile or "balanced"
    if name not in PROFILES:
        raise ValueError(f"unknown KDF profile '{name}', expected one of {list(PROFILES)}")
    return name, PROFILE_IDS[name]


def _master_for_encrypt(
    header: Header,
    password: Optional[str | bytes],
    key: Optional[bytes],
    recipient: Optional[bytes],
    sender_private: Optional[bytes],
    pepper: bytes,
    profile_name: str,
) -> bytes:
    if header.mode == MODE_PASSWORD:
        if password is None:
            raise KeyError_("password required")
        return derive_master_secret(
            password, header.salt, PROFILES[profile_name], header.kdf_id, pepper
        )
    if header.mode == MODE_RAWKEY:
        if key is None or len(key) < 32:
            raise KeyError_("raw key must be at least 32 bytes")
        return hkdf(key, header.salt, b"TRIGLYPH/v1|rawkey", 64)
    if header.mode in (MODE_X25519_ANON, MODE_X25519_AUTH):
        if recipient is None or len(recipient) != 32:
            raise KeyError_("recipient X25519 public key (32 bytes) required")
        esk = random_bytes(32)
        epk = public_key(esk)
        header.eph_pub = epk
        ikm = key_exchange(esk, recipient) + epk + recipient
        if header.mode == MODE_X25519_AUTH:
            if sender_private is None or len(sender_private) != 32:
                raise KeyError_("sender private key required for authenticated mode")
            spk = public_key(sender_private)
            header.sender_pub = spk
            ikm += key_exchange(sender_private, recipient) + spk
        return hkdf(ikm, header.salt, b"TRIGLYPH/v1|x25519", 64)
    raise CryptoError(f"unsupported mode {header.mode}")


def _master_for_decrypt(
    header: Header,
    password: Optional[str | bytes],
    key: Optional[bytes],
    private_key: Optional[bytes],
    pepper: bytes,
) -> bytes:
    if header.mode == MODE_PASSWORD:
        if password is None:
            raise KeyError_("password required")
        profile_name = PROFILE_BY_ID.get(header.profile_id)
        if profile_name is None:
            raise FormatError(f"unknown KDF profile id {header.profile_id}")
        return derive_master_secret(
            password, header.salt, PROFILES[profile_name], header.kdf_id, pepper
        )
    if header.mode == MODE_RAWKEY:
        if key is None:
            raise KeyError_("raw key required")
        return hkdf(key, header.salt, b"TRIGLYPH/v1|rawkey", 64)
    if header.mode in (MODE_X25519_ANON, MODE_X25519_AUTH):
        if private_key is None or len(private_key) != 32:
            raise KeyError_("recipient private key (32 bytes) required")
        my_pub = public_key(private_key)
        ikm = key_exchange(private_key, header.eph_pub) + header.eph_pub + my_pub
        if header.mode == MODE_X25519_AUTH:
            if len(header.sender_pub) != 32:
                raise FormatError("authenticated mode without sender public key")
            ikm += key_exchange(private_key, header.sender_pub) + header.sender_pub
        return hkdf(ikm, header.salt, b"TRIGLYPH/v1|x25519", 64)
    raise CryptoError(f"unsupported mode {header.mode}")


# --------------------------------------------------------------------------
# Слои каскада
# --------------------------------------------------------------------------

def _seal_chunk(ks: KeySchedule, suite: int, index: int, final: bool, hdr_hash: bytes, pt: bytes) -> bytes:
    aad = hdr_hash + u64(index) + u8(1 if final else 0)
    out = xchacha20poly1305_encrypt(ks["l1"], ks.nonce_for(b"L1", index, 24), pt, aad)
    if suite in (SUITE_TRIPLE, SUITE_DUAL):
        out = aes_gcm_encrypt(ks["l2"], ks.nonce_for(b"L2", index, 12), out, aad)
    if suite == SUITE_TRIPLE:
        out = threefish1024_ctr_xor(ks["l3"], ks.nonce_for(b"L3", index, 16), out)
    return out


def _open_chunk(ks: KeySchedule, suite: int, index: int, final: bool, hdr_hash: bytes, ct: bytes) -> bytes:
    aad = hdr_hash + u64(index) + u8(1 if final else 0)
    data = ct
    if suite == SUITE_TRIPLE:
        data = threefish1024_ctr_xor(ks["l3"], ks.nonce_for(b"L3", index, 16), data)
    if suite in (SUITE_TRIPLE, SUITE_DUAL):
        data = aes_gcm_decrypt(ks["l2"], ks.nonce_for(b"L2", index, 12), data, aad)
    return xchacha20poly1305_decrypt(ks["l1"], ks.nonce_for(b"L1", index, 24), data, aad)


class _OuterMac:
    """Внешний HMAC-SHA3-512 поверх заголовка и всех фрагментов."""

    def __init__(self, key: bytes, header_bytes: bytes) -> None:
        self._h = hmac.new(key, b"TRIGLYPH/v1|outer|", "sha3_512")
        self._h.update(u32(len(header_bytes)) + header_bytes)
        self.count = 0

    def add_chunk(self, index: int, final: bool, ct: bytes) -> None:
        self._h.update(u64(index) + u8(1 if final else 0) + u32(len(ct)) + ct)
        self.count += 1

    def digest(self) -> bytes:
        return self._h.copy().digest()

    def final(self) -> bytes:
        self._h.update(b"|end|" + u64(self.count))
        return self._h.digest()


# --------------------------------------------------------------------------
# Высокоуровневый API
# --------------------------------------------------------------------------

def _build_header(
    suite: str,
    mode: int,
    profile_name: str,
    pad_policy: int,
    aad: bytes,
    chunk_size: int,
    kdf_id: int,
    recipient_hint: bytes = b"",
) -> Header:
    if suite not in SUITES:
        raise ValueError(f"unknown suite '{suite}', expected one of {list(SUITES)}")
    h = Header()
    h.suite = SUITES[suite]
    h.mode = mode
    h.kdf_id = kdf_id
    h.profile_id = PROFILE_IDS[profile_name]
    h.pad_policy = pad_policy
    h.chunk_size = chunk_size
    h.salt = random_bytes(SALT_SIZE)
    h.aad = aad
    h.recipient_hint = recipient_hint
    if aad:
        h.flags |= FLAG_HAS_AAD
    return h


def encrypt(
    data: bytes,
    *,
    password: Optional[str | bytes] = None,
    key: Optional[bytes] = None,
    recipient: Optional[bytes] = None,
    sender_private: Optional[bytes] = None,
    suite: str = "triple",
    profile: str = "balanced",
    aad: bytes = b"",
    pad: int = _text.PAD_PADME,
    chunk_size: int = DEFAULT_CHUNK,
    kdf_id: int = KDF_SCRYPT,
    pepper: bytes = b"",
    hide_recipient: bool = True,
    stealth: bool = False,
) -> bytes:
    """Зашифровать байты в контейнер TRIGLYPH.

    Ровно один способ получения ключа: password | key | recipient.
    """
    provided = [x is not None for x in (password, key, recipient)]
    if sum(provided) != 1:
        raise KeyError_("выберите ровно один источник ключа: password, key или recipient")
    profile_name, _ = _resolve_profile(profile)

    if password is not None:
        mode = MODE_PASSWORD
    elif key is not None:
        mode = MODE_RAWKEY
        kdf_id = KDF_RAW
    else:
        mode = MODE_X25519_AUTH if sender_private is not None else MODE_X25519_ANON
        kdf_id = KDF_RAW

    hint = b""
    if recipient is not None and not hide_recipient:
        hint = hashlib.sha3_256(b"TRIGLYPH/v1|recipient|" + recipient).digest()[:8]

    header = _build_header(suite, mode, profile_name, pad, aad, chunk_size, kdf_id, hint)
    master = _master_for_encrypt(
        header, password, key, recipient, sender_private, pepper, profile_name
    )

    payload = _text.pad_plaintext(data, pad) if pad != _text.PAD_NONE else data
    if pad != _text.PAD_NONE:
        header.flags |= FLAG_PADDED_WHOLE

    with KeySchedule(master, header.prefix_bytes()) as ks:
        header.commitment = ks.commitment
        header_bytes = header.to_bytes()
        hdr_hash = hashlib.sha3_256(header_bytes).digest()
        mac = _OuterMac(ks["mac"], header_bytes)

        out = bytearray(header_bytes)
        total = len(payload)
        nchunks = max(1, (total + chunk_size - 1) // chunk_size)
        for i in range(nchunks):
            piece = payload[i * chunk_size : (i + 1) * chunk_size]
            final = i == nchunks - 1
            ct = _seal_chunk(ks, header.suite, i, final, hdr_hash, piece)
            mac.add_chunk(i, final, ct)
            out += u32(len(ct)) + ct
        out += mac.final()
    return _stealth.wrap(bytes(out)) if stealth else bytes(out)


def decrypt(
    blob: bytes,
    *,
    password: Optional[str | bytes] = None,
    key: Optional[bytes] = None,
    private_key: Optional[bytes] = None,
    expect_sender: Optional[bytes] = None,
    aad: Optional[bytes] = None,
    pepper: bytes = b"",
) -> bytes:
    """Расшифровать контейнер TRIGLYPH и проверить его подлинность."""
    if not blob.startswith(MAGIC) and _stealth.looks_stealth(blob, MAGIC):
        blob = _stealth.unwrap(blob)
    header, hdr_len = Header.parse(blob)
    if aad is not None and not ct_eq(aad, header.aad):
        raise IntegrityError("associated data mismatch")
    if expect_sender is not None and not ct_eq(expect_sender, header.sender_pub):
        raise IntegrityError("sender public key does not match the expected one")

    master = _master_for_decrypt(header, password, key, private_key, pepper)
    with KeySchedule(master, header.prefix_bytes()) as ks:
        if not ct_eq(ks.commitment, header.commitment):
            raise IntegrityError(
                "неверный ключ или пароль (key commitment mismatch) / wrong key or password"
            )
        header_bytes = blob[:hdr_len]
        hdr_hash = hashlib.sha3_256(header_bytes).digest()
        mac = _OuterMac(ks["mac"], header_bytes)

        if len(blob) < hdr_len + MAC_SIZE:
            raise FormatError("container truncated")
        body = blob[hdr_len : len(blob) - MAC_SIZE]
        tail_mac = blob[len(blob) - MAC_SIZE :]

        r = Reader(body)
        chunks = []
        while not r.eof():
            ln = r.u32()
            if ln > MAX_CHUNK + 1024:
                raise FormatError("chunk length out of range")
            chunks.append(r.take(ln))
        if not chunks:
            raise FormatError("container has no chunks")

        for i, ct in enumerate(chunks):
            mac.add_chunk(i, i == len(chunks) - 1, ct)
        if not ct_eq(mac.final(), tail_mac):
            raise IntegrityError(
                "контейнер повреждён или подделан (HMAC-SHA3-512) / container tampered"
            )

        out = bytearray()
        last = len(chunks) - 1
        for i, ct in enumerate(chunks):
            piece = _open_chunk(ks, header.suite, i, i == last, hdr_hash, ct)
            if i == last and (header.flags & FLAG_PADDED_LAST):
                piece = _text.unpad_plaintext(piece)
            out += piece

    data = bytes(out)
    if header.flags & FLAG_PADDED_WHOLE:
        data = _text.unpad_plaintext(data)
    return data


# --------------------------------------------------------------------------
# Текстовый режим (три языка)
# --------------------------------------------------------------------------

def encrypt_text(
    text: str,
    *,
    armor_kind: str = "auto",
    normalize: str = "NFC",
    width: int = 0,
    **kwargs,
) -> str:
    """Зашифровать строку и вернуть её в текстовой броне.

    armor_kind='auto' выбирает броню по языку исходного текста:
    китайский → hanzi, русский → cyrillic, остальное → latin.
    """
    norm = _text.normalize_text(text, normalize)  # type: ignore[arg-type]
    lang = _text.detect_language(norm)
    if armor_kind == "auto":
        armor_kind = {"zh": "hanzi", "ru": "cyrillic"}.get(lang, "latin")
    blob = encrypt(norm.encode("utf-8"), **kwargs)
    return _armor.encode(blob, armor_kind, width=width)


def decrypt_text(armored: str, *, armor_kind: str | None = None, **kwargs) -> str:
    payload, _headers = _armor.unwrap_message(armored)
    blob = _armor.decode(payload, armor_kind)
    return decrypt(blob, **kwargs).decode("utf-8")


# --------------------------------------------------------------------------
# Потоковый режим (файлы любого размера)
# --------------------------------------------------------------------------

def encrypt_stream(
    fin: BinaryIO,
    fout: BinaryIO,
    *,
    password: Optional[str | bytes] = None,
    key: Optional[bytes] = None,
    recipient: Optional[bytes] = None,
    sender_private: Optional[bytes] = None,
    suite: str = "triple",
    profile: str = "balanced",
    aad: bytes = b"",
    pad_last: bool = True,
    chunk_size: int = DEFAULT_CHUNK,
    pepper: bytes = b"",
    stealth: bool = False,
    progress=None,
) -> int:
    """Потоковое шифрование: постоянное потребление памяти."""
    provided = [x is not None for x in (password, key, recipient)]
    if sum(provided) != 1:
        raise KeyError_("выберите ровно один источник ключа: password, key или recipient")
    profile_name, _ = _resolve_profile(profile)
    if password is not None:
        mode, kdf_id = MODE_PASSWORD, KDF_SCRYPT
    elif key is not None:
        mode, kdf_id = MODE_RAWKEY, KDF_RAW
    else:
        mode = MODE_X25519_AUTH if sender_private is not None else MODE_X25519_ANON
        kdf_id = KDF_RAW

    header = _build_header(
        suite, mode, profile_name,
        _text.PAD_PADME if pad_last else _text.PAD_NONE,
        aad, chunk_size, kdf_id,
    )
    header.flags |= FLAG_STREAM
    if pad_last:
        header.flags |= FLAG_PADDED_LAST
    master = _master_for_encrypt(
        header, password, key, recipient, sender_private, pepper, profile_name
    )

    written = 0
    if stealth:
        prefix = random_bytes(_stealth.PREFIX_SIZE)
        fout.write(prefix)
        written += len(prefix)
        fout = _stealth.MaskedWriter(fout, prefix)  # type: ignore[assignment]
    with KeySchedule(master, header.prefix_bytes()) as ks:
        header.commitment = ks.commitment
        header_bytes = header.to_bytes()
        hdr_hash = hashlib.sha3_256(header_bytes).digest()
        fout.write(header_bytes)
        written += len(header_bytes)
        mac = _OuterMac(ks["mac"], header_bytes)

        index = 0
        buf = fin.read(chunk_size)
        while True:
            nxt = fin.read(chunk_size)
            final = not nxt
            piece = buf
            if final and pad_last:
                # Padmé вместо добивки до целого фрагмента: ≤12 % вместо ≤100 %
                piece = _text.pad_plaintext(piece, _text.PAD_PADME)
            ct = _seal_chunk(ks, header.suite, index, final, hdr_hash, piece)
            mac.add_chunk(index, final, ct)
            fout.write(u32(len(ct)) + ct)
            written += 4 + len(ct)
            if progress:
                progress(len(buf))
            if final:
                break
            buf = nxt
            index += 1
        tail = mac.final()
        fout.write(tail)
        written += len(tail)
    return written


def decrypt_stream(
    fin: BinaryIO,
    fout: BinaryIO,
    *,
    password: Optional[str | bytes] = None,
    key: Optional[bytes] = None,
    private_key: Optional[bytes] = None,
    pepper: bytes = b"",
    progress=None,
) -> int:
    """Потоковое расшифрование с проверкой каждого фрагмента и финального HMAC."""
    head = bytearray(fin.read(1 << 16))
    if not head.startswith(MAGIC) and _stealth.looks_stealth(bytes(head), MAGIC):
        prefix = bytes(head[: _stealth.PREFIX_SIZE])
        fin = _stealth.MaskedReader(fin, prefix, bytes(head[_stealth.PREFIX_SIZE :]))  # type: ignore[assignment]
        head = bytearray(fin.read(1 << 16))
    while True:  # заголовок может быть длинным из-за AAD — дочитываем
        try:
            header, hdr_len = Header.parse(bytes(head))
            break
        except FormatError:
            more = fin.read(1 << 16)
            if not more or len(head) > (1 << 22):
                raise
            head.extend(more)
    header_bytes = bytes(head[:hdr_len])
    rest = bytes(head[hdr_len:])

    master = _master_for_decrypt(header, password, key, private_key, pepper)
    written = 0
    with KeySchedule(master, header.prefix_bytes()) as ks:
        if not ct_eq(ks.commitment, header.commitment):
            raise IntegrityError("неверный ключ или пароль / wrong key or password")
        hdr_hash = hashlib.sha3_256(header_bytes).digest()
        mac = _OuterMac(ks["mac"], header_bytes)

        buffer = bytearray(rest)

        def fill(n: int) -> None:
            while len(buffer) < n:
                block = fin.read(max(n - len(buffer), 1 << 16))
                if not block:
                    raise FormatError("container truncated")
                buffer.extend(block)

        whole_padded = bool(header.flags & FLAG_PADDED_WHOLE)
        remaining: Optional[int] = None
        prefix_buf = bytearray()
        index = 0
        while True:
            # читаем следующий фрагмент; последним 64 байтами идёт внешний MAC
            fill(4)
            ln = int.from_bytes(buffer[:4], "big")
            if ln > MAX_CHUNK + 1024:
                raise FormatError("chunk length out of range")
            fill(4 + ln + MAC_SIZE)
            ct = bytes(buffer[4 : 4 + ln])
            del buffer[: 4 + ln]
            # заглядываем вперёд: если дальше только MAC — этот фрагмент последний
            while len(buffer) <= MAC_SIZE:
                more = fin.read(1 << 16)
                if not more:
                    break
                buffer.extend(more)
            final = len(buffer) <= MAC_SIZE
            mac.add_chunk(index, final, ct)
            pt = _open_chunk(ks, header.suite, index, final, hdr_hash, ct)
            if final and (header.flags & FLAG_PADDED_LAST):
                pt = _text.unpad_plaintext(pt)
            if whole_padded:
                # набивка всего сообщения: длина лежит в первых 8 байтах потока
                if remaining is None:
                    prefix_buf.extend(pt)
                    if len(prefix_buf) < 8:
                        pt = b""
                    else:
                        remaining = int.from_bytes(prefix_buf[:8], "big")
                        pt = bytes(prefix_buf[8:])
                        prefix_buf.clear()
                take = min(len(pt), remaining if remaining is not None else 0)
                pt = pt[:take]
                if remaining is not None:
                    remaining -= take
            fout.write(pt)
            written += len(pt)
            if progress:
                progress(len(pt))
            if final:
                break
            index += 1

        while True:
            more = fin.read(1 << 16)
            if not more:
                break
            buffer.extend(more)
        if len(buffer) != MAC_SIZE:
            raise FormatError("trailing garbage after final chunk")
        if not ct_eq(mac.final(), bytes(buffer)):
            raise IntegrityError("контейнер повреждён или подделан / container tampered")
    return written


# --------------------------------------------------------------------------
# Интроспекция и самопроверка
# --------------------------------------------------------------------------

def inspect(blob: bytes | str) -> Dict[str, object]:
    """Разбор заголовка без ключа: что за контейнер нам дали."""
    if isinstance(blob, str):
        payload, _ = _armor.unwrap_message(blob)
        blob = _armor.decode(payload)
    stealthed = False
    if not blob.startswith(MAGIC) and _stealth.looks_stealth(blob, MAGIC):
        blob = _stealth.unwrap(blob)
        stealthed = True
    header, hdr_len = Header.parse(blob)
    info = header.describe()
    info["stealth"] = stealthed
    info["header_bytes"] = hdr_len
    info["total_bytes"] = len(blob)
    info["payload_bytes"] = max(0, len(blob) - hdr_len - MAC_SIZE)
    return info


def self_test(verbose: bool = False) -> bool:
    """Быстрая самопроверка при старте: примитивы + контейнер."""
    from .selftest import run_self_test

    return run_self_test(verbose=verbose)
