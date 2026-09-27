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
