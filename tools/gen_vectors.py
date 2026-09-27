#!/usr/bin/env python3
"""
Генератор эталонных контейнеров TRIGLYPH/1.

Создаёт docs/test-vectors.json: набор готовых контейнеров вместе с ключами и
ожидаемым открытым текстом. Любая совместимая реализация (на другом языке)
должна расшифровать их все и получить ровно тот же результат.

    python3 tools/gen_vectors.py          # перегенерировать
    python3 tools/verify_vectors.py       # проверить
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import triglyph  # noqa: E402
from triglyph.text import PAD_BUCKET, PAD_NONE, PAD_PADME  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "test-vectors.json")

MESSAGES = {
    "zh": "黎明时分发起进攻，联络点已暴露，请从第三个楼梯撤离。",
    "ru": "Атака начнётся на рассвете. Явка провалена — уходи через третий подъезд.",
    "en": "The attack begins at dawn. The safe house is blown; leave by the third stairwell.",
    "mixed": "Пароль: 密码 · password. Встреча в 07:45 у 北门.",
    "empty": "",
    "binary-ish": "\x00\x01\x02 tail\u00a0space ",
}

PAD_NAMES = {PAD_NONE: "none", PAD_PADME: "padme", PAD_BUCKET: "bucket"}


def build() -> dict:
    vectors = []

    # 1. Сырой ключ — самый простой путь для сторонней реализации
    key = bytes(range(32))
    for suite in ("solo", "dual", "triple"):
        for pad in (PAD_NONE, PAD_PADME, PAD_BUCKET):
            for name, msg in MESSAGES.items():
                blob = triglyph.encrypt(
                    msg.encode("utf-8"), key=key, suite=suite, pad=pad
                )
                vectors.append({
                    "id": f"rawkey/{suite}/{PAD_NAMES[pad]}/{name}",
                    "mode": "raw-key",
                    "key_hex": key.hex(),
                    "suite": suite,
                    "padding": PAD_NAMES[pad],
                    "plaintext_utf8": msg,
                    "container_hex": blob.hex(),
                })

    # 2. Пароль (профиль fast, чтобы проверка шла быстро)
    for password in ("пароль", "密码口令", "correct horse battery staple"):
        blob = triglyph.encrypt(
            MESSAGES["mixed"].encode("utf-8"),
            password=password, profile="fast", suite="triple",
        )
        vectors.append({
            "id": f"password/fast/{password[:8]}",
            "mode": "password",
            "password": password,
            "profile": "fast",
            "suite": "triple",
            "plaintext_utf8": MESSAGES["mixed"],
            "container_hex": blob.hex(),
        })

    # 3. Связанные данные и стелс-оболочка
    blob = triglyph.encrypt(b"aad test", key=key, aad="счёт №42".encode(), suite="dual")
    vectors.append({
        "id": "rawkey/aad",
        "mode": "raw-key", "key_hex": key.hex(), "suite": "dual",
        "aad_utf8": "счёт №42", "plaintext_utf8": "aad test",
        "container_hex": blob.hex(),
    })
    blob = triglyph.encrypt(b"stealth test", key=key, suite="solo", stealth=True)
    vectors.append({
        "id": "rawkey/stealth",
        "mode": "raw-key", "key_hex": key.hex(), "suite": "solo", "stealth": True,
        "plaintext_utf8": "stealth test", "container_hex": blob.hex(),
    })

    # 4. Многофрагментный контейнер
    payload = bytes((i * 7 + 13) % 256 for i in range(20_000))
    blob = triglyph.encrypt(payload, key=key, suite="solo", pad=PAD_NONE, chunk_size=4096)
    vectors.append({
        "id": "rawkey/multichunk",
        "mode": "raw-key", "key_hex": key.hex(), "suite": "solo",
        "chunk_size": 4096,
        "plaintext_rule": "byte i = (i*7+13) mod 256, length 20000",
        "plaintext_sha3_256": __import__("hashlib").sha3_256(payload).hexdigest(),
        "container_hex": blob.hex(),
    })

    # 5. Броня
    sample = bytes(range(64))
    from triglyph import armor

    armors = {kind: armor.encode(sample, kind) for kind in ("hanzi", "cyrillic", "latin", "grouped")}

    return {
        "format": "TRIGLYPH/1",
        "library_version": triglyph.__version__,
        "note": "Каждый контейнер должен расшифроваться в plaintext_utf8 указанным ключом. "
                "A compliant implementation must decrypt every container to plaintext_utf8.",
        "armor_vectors": {"input_hex": sample.hex(), "encoded": armors},
        "vectors": vectors,
    }


def main() -> int:
    data = build()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    print(f"{OUT}: {len(data['vectors'])} векторов, {os.path.getsize(OUT)} байт")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# --------------------------------------------------------------------------
# Плоский файл векторов для порта на Java/Android (парсится без библиотек)
# --------------------------------------------------------------------------

def build_flat() -> str:
    import hashlib
    import hmac as _hmac

    from triglyph import armor
    from triglyph.aes import aes_gcm_encrypt
    from triglyph.chacha import chacha20_xor, poly1305_mac, hchacha20
    from triglyph.kdf import PROFILES, derive_master_secret, hkdf
    from triglyph.threefish import Threefish1024
    from triglyph.x25519 import x25519
    from triglyph.text import padme

    L = []
    hx = lambda b: b.hex()

    def rnd(n, seed):
        h = hashlib.shake_256(b"vecgen" + str(seed).encode()).digest(n)
        return h

    # хеши
    for alg in ("sha3_256", "sha3_512"):
        for n in (0, 1, 55, 72, 136, 200):
            data = rnd(n, f"{alg}{n}")
            L.append(f"H|{alg}|{hx(data)}|{getattr(hashlib, alg)(data).hexdigest()}")
    for n in (0, 17, 136, 300):
        data = rnd(n, f"shake{n}")
        L.append(f"H|shake_256_64|{hx(data)}|{hx(hashlib.shake_256(data).digest(64))}")
    # HMAC-SHA3-512
    for n in (0, 32, 100, 200):
        key, msg = rnd(64, f"hk{n}"), rnd(n, f"hm{n}")
        L.append(f"H|hmac_sha3_512|{hx(key)}|{hx(msg)}|{_hmac.new(key, msg, 'sha3_512').hexdigest()}")
    # ChaCha20
    for n in (0, 1, 64, 65, 200):
        key, nonce, pt = rnd(32, f"ck{n}"), rnd(12, f"cn{n}"), rnd(n, f"cp{n}")
        L.append(f"C|{hx(key)}|1|{hx(nonce)}|{hx(pt)}|{hx(chacha20_xor(key,1,nonce,pt))}")
    # HChaCha20
    for i in range(3):
        key, n16 = rnd(32, f"hc{i}"), rnd(16, f"hn{i}")
        L.append(f"HC|{hx(key)}|{hx(n16)}|{hx(hchacha20(key,n16))}")
    # Poly1305
    for n in (0, 1, 16, 17, 64, 300):
        key, msg = rnd(32, f"pk{n}"), rnd(n, f"pm{n}")
        L.append(f"M|{hx(key)}|{hx(msg)}|{hx(poly1305_mac(msg,key))}")
    # AES-GCM
    for n in (0, 16, 100):
        key, iv, aad, pt = rnd(32, f"ak{n}"), rnd(12, f"ai{n}"), rnd(n % 13, f"aa{n}"), rnd(n, f"ap{n}")
        L.append(f"G|{hx(key)}|{hx(iv)}|{hx(aad)}|{hx(pt)}|{hx(aes_gcm_encrypt(key,iv,pt,aad))}")
    # Threefish-1024
    for i in range(3):
        key, tw, blk = rnd(128, f"tk{i}"), rnd(16, f"tt{i}"), rnd(128, f"tb{i}")
        L.append(f"T|{hx(key)}|{hx(tw)}|{hx(blk)}|{hx(Threefish1024(key,tw).encrypt_block(blk))}")
    # HKDF-SHA512
    for i in range(3):
        ikm, salt, info = rnd(32, f"ii{i}"), rnd(16, f"is{i}"), rnd(10, f"if{i}")
        L.append(f"K|hkdf_sha512|{hx(ikm)}|{hx(salt)}|{hx(info)}|64|{hx(hkdf(ikm,salt,info,64))}")
    # PBKDF2-SHA512 и scrypt
    for iters in (1, 1000):
        pw, salt = b"password\xd0\xbf", b"salt\x00\x01"
        dk = hashlib.pbkdf2_hmac("sha512", pw, salt, iters, 64)
        L.append(f"K|pbkdf2_sha512|{hx(pw)}|{hx(salt)}|{iters}|64|{hx(dk)}")
    for (n, r, p) in ((16, 1, 1), (1024, 8, 1), (8192, 8, 1)):
        pw, salt = "pass🔑".encode(), "NaCl-соль".encode()
        dk = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=1 << 28, dklen=64)
        L.append(f"K|scrypt|{hx(pw)}|{hx(salt)}|{n}|{r}|{p}|64|{hx(dk)}")
    # мастер-секрет целиком (профиль fast)
    for pwd in ("пароль", "密码口令", "plain"):
        salt = rnd(32, "ms" + pwd)
        m = derive_master_secret(pwd, salt, PROFILES["fast"], 1)
        L.append(f"K|master_fast|{hx(pwd.encode())}|{hx(salt)}|{hx(m)}")
    # X25519
    for i in range(3):
        sk, u = rnd(32, f"xs{i}"), rnd(32, f"xu{i}")
        L.append(f"X|{hx(sk)}|{hx(u)}|{hx(x25519(sk,u))}")
    # Padmé
    L.append("P|padme|" + ",".join(f"{n}:{padme(n)}" for n in (1, 2, 3, 10, 100, 1000, 5000, 65537)))
    # броня
    for kind in ("hanzi", "cyrillic", "latin", "grouped"):
        for n in (0, 1, 2, 3, 5, 31, 64):
            data = rnd(n, f"ar{kind}{n}")
            L.append(f"A|{kind}|{hx(data)}|{armor.encode(data, kind)}")
    # контейнеры
    key = bytes(range(32))
    for suite in ("solo", "dual", "triple"):
        for pad, padname in ((PAD_NONE, "none"), (PAD_PADME, "padme"), (PAD_BUCKET, "bucket")):
            for name, msg in MESSAGES.items():
                blob = triglyph.encrypt(msg.encode(), key=key, suite=suite, pad=pad)
                L.append(f"V|rawkey/{suite}/{padname}/{name}|rawkey|{hx(key)}||{suite}||"
                         f"{hx(blob)}|{hx(msg.encode())}")
    for password in ("пароль", "密码口令", "correct horse battery staple"):
        blob = triglyph.encrypt(MESSAGES["mixed"].encode(), password=password,
                                profile="fast", suite="triple")
        L.append(f"V|password/{password[:6]}|password||{hx(password.encode())}|triple||"
                 f"{hx(blob)}|{hx(MESSAGES['mixed'].encode())}")
    blob = triglyph.encrypt(b"aad test", key=key, aad="счёт №42".encode(), suite="dual")
    L.append(f"V|rawkey/aad|rawkey|{hx(key)}||dual|{hx('счёт №42'.encode())}|{hx(blob)}|{hx(b'aad test')}")
    blob = triglyph.encrypt(b"stealth test", key=key, suite="solo", stealth=True)
    L.append(f"V|rawkey/stealth|rawkey|{hx(key)}||solo||{hx(blob)}|{hx(b'stealth test')}")
    payload = bytes((i * 7 + 13) % 256 for i in range(20_000))
    blob = triglyph.encrypt(payload, key=key, suite="solo", pad=PAD_NONE, chunk_size=4096)
    L.append(f"V|rawkey/multichunk|rawkey|{hx(key)}||solo||{hx(blob)}|{hx(payload)}")
    return "\n".join(L) + "\n"


def write_flat() -> None:
    path = os.path.join(os.path.dirname(OUT), "test-vectors.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_flat())
    print(f"{path}: {os.path.getsize(path)} байт")
