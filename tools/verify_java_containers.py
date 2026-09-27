#!/usr/bin/env python3
"""Встречная проверка: контейнеры, созданные Java-ядром, открывает Python.

Формат входного файла (его пишет `SelfCheck --emit`):

    mode|key_hex|password_hex|container_hex|plaintext_hex

Проверяем не только «расшифровалось», но и то, что порча любого байта
отвергается, — то есть Java не потеряла аутентификацию по дороге.
"""

from __future__ import annotations

import sys

sys.path.insert(0, ".")

import triglyph  # noqa: E402
from triglyph import IntegrityError  # noqa: E402


def main(path: str) -> int:
    ok = 0
    bad = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            mode, key_hex, pw_hex, blob_hex, pt_hex = line.split("|")
            blob = bytes.fromhex(blob_hex)
            want = bytes.fromhex(pt_hex)
            kwargs = (
                {"key": bytes.fromhex(key_hex)}
                if mode == "rawkey"
                else {"password": bytes.fromhex(pw_hex)}
            )
            try:
                got = triglyph.decrypt(blob, **kwargs)
            except Exception as exc:  # noqa: BLE001
                print(f"line {lineno}: Python не смог открыть контейнер Java: {exc}")
                bad += 1
                continue
            if got != want:
                print(f"line {lineno}: расшифровалось не в то ({len(got)} vs {len(want)} байт)")
                bad += 1
                continue
            tampered = bytearray(blob)
            tampered[len(tampered) // 3] ^= 0x01
            try:
                triglyph.decrypt(bytes(tampered), **kwargs)
            except Exception:
                pass
            else:
                print(f"line {lineno}: порченый контейнер прошёл проверку — это провал")
                bad += 1
                continue
            ok += 1
    print(f"Java → Python: {ok} контейнеров открыто, {bad} ошибок")
    return 0 if bad == 0 and ok > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "java-containers.txt"))
