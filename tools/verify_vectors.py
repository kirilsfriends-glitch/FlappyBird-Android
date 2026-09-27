#!/usr/bin/env python3
"""
Проверка эталонных контейнеров из docs/test-vectors.json.

Эти векторы зафиксированы в репозитории: если изменение кода ломает хотя бы
один из них — значит, оно сломало совместимость формата TRIGLYPH/1.
Тот же файл позволяет проверить реализацию на другом языке.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import triglyph  # noqa: E402
from triglyph import armor  # noqa: E402

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "docs", "test-vectors.json")


def check_vector(v: dict) -> tuple[bool, str]:
    blob = bytes.fromhex(v["container_hex"])
    kwargs = {}
    if v["mode"] == "raw-key":
        kwargs["key"] = bytes.fromhex(v["key_hex"])
    else:
        kwargs["password"] = v["password"]
    if "aad_utf8" in v:
        kwargs["aad"] = v["aad_utf8"].encode("utf-8")
    try:
        data = triglyph.decrypt(blob, **kwargs)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if "plaintext_utf8" in v:
        if data.decode("utf-8") != v["plaintext_utf8"]:
            return False, "plaintext mismatch"
    if "plaintext_sha3_256" in v:
        if hashlib.sha3_256(data).hexdigest() != v["plaintext_sha3_256"]:
            return False, "plaintext digest mismatch"
    return True, ""


def run(verbose: bool = False) -> bool:
    with open(VECTORS, encoding="utf-8") as fh:
        data = json.load(fh)
    failed = 0
    for v in data["vectors"]:
        ok, err = check_vector(v)
        failed += not ok
        if verbose or not ok:
            print(f"[{'OK' if ok else 'FAIL'}] {v['id']} {err}")
    sample = bytes.fromhex(data["armor_vectors"]["input_hex"])
    for kind, encoded in data["armor_vectors"]["encoded"].items():
        ok = armor.encode(sample, kind) == encoded and armor.decode(encoded, kind) == sample
        failed += not ok
        if verbose or not ok:
            print(f"[{'OK' if ok else 'FAIL'}] armor/{kind}")
    total = len(data["vectors"]) + len(data["armor_vectors"]["encoded"])
    print(f"{total - failed}/{total} эталонных векторов совпали")
    return failed == 0


if __name__ == "__main__":
    raise SystemExit(0 if run("-v" in sys.argv) else 1)
