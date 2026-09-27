#!/usr/bin/env python3
"""
Демонстрационный веб-сервер TRIGLYPH.

    python3 web/server.py            # http://0.0.0.0:8000
    PORT=9000 python3 web/server.py

Только стандартная библиотека. Вся криптография выполняется на стороне
сервера — это демонстрация, а не защищённый сервис: пароль уходит на сервер
в теле запроса. Для настоящей работы используйте CLI или библиотеку.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import triglyph  # noqa: E402
from triglyph import armor as armor_mod  # noqa: E402
from triglyph import shamir  # noqa: E402
from triglyph import text as text_mod  # noqa: E402
from triglyph._util import CryptoError, FormatError, IntegrityError  # noqa: E402
from triglyph.backend import BACKEND, backend_info  # noqa: E402
from triglyph.cipher import SUITE_DESCRIPTION, SUITES  # noqa: E402
from triglyph.cli import _generate_password, password_entropy_bits  # noqa: E402
from triglyph.kdf import PROFILES  # noqa: E402
from triglyph.selftest import _checks  # noqa: E402

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 2 << 20  # 2 МиБ на запрос — демо, не файловое хранилище


def _api_encrypt(req: dict) -> dict:
    text = req.get("text", "")
    if not text:
        raise ValueError("empty text")
    password = req.get("password") or ""
    if not password:
        raise ValueError("empty password")
    suite = req.get("suite", "triple")
    profile = req.get("profile", "fast")
    kind = req.get("armor", "auto")
    stealth = bool(req.get("stealth"))
    hide_len = bool(req.get("hideLength", True))

    normalized = text_mod.normalize_text(text)
    lang = text_mod.detect_language(normalized)
    if kind == "auto":
        kind = {"zh": "hanzi", "ru": "cyrillic"}.get(lang, "latin")

    t0 = time.time()
    blob = triglyph.encrypt(
        normalized.encode("utf-8"),
        password=password,
        suite=suite,
        profile=profile,
        pad=text_mod.PAD_BUCKET if hide_len else text_mod.PAD_PADME,
        stealth=stealth,
    )
    elapsed = (time.time() - t0) * 1000
    armored = armor_mod.encode(blob, kind)
    return {
        "armor": armored,
        "armorKind": kind,
        "language": lang,
        "languageName": text_mod.LANG_NAMES.get(lang, {}),
        "bytes": len(blob),
        "plainBytes": len(normalized.encode("utf-8")),
        "ms": round(elapsed, 1),
        "info": triglyph.inspect(blob),
        "entropyBits": password_entropy_bits(password),
        "layers": SUITE_DESCRIPTION[SUITES[suite]],
    }


def _api_decrypt(req: dict) -> dict:
    payload = (req.get("text") or "").strip()
    password = req.get("password") or ""
    if not payload:
        raise ValueError("empty container")
    body, _headers = armor_mod.unwrap_message(payload)
    blob = armor_mod.decode(body)
    info = triglyph.inspect(blob)
    t0 = time.time()
    data = triglyph.decrypt(blob, password=password)
    elapsed = (time.time() - t0) * 1000
    text = data.decode("utf-8", "replace")
    return {
        "text": text,
        "ms": round(elapsed, 1),
        "info": info,
        "language": text_mod.detect_language(text),
        "bytes": len(blob),
    }


def _api_inspect(req: dict) -> dict:
    payload = (req.get("text") or "").strip()
    body, _headers = armor_mod.unwrap_message(payload)
    return {"info": triglyph.inspect(armor_mod.decode(body))}


def _api_passgen(req: dict) -> dict:
    style = req.get("style", "mixed")
    bits = max(32, min(int(req.get("bits", 128)), 512))
    pw, real = _generate_password(style, bits)
    return {"password": pw, "bits": int(real)}


def _api_split(req: dict) -> dict:
    secret = (req.get("secret") or "").encode("utf-8")
    k = int(req.get("threshold", 3))
    n = int(req.get("shares", 5))
    kind = req.get("armor", "hanzi")
    parts = shamir.split_secret(secret, k, n)
    return {"shares": [p.armored(kind) for p in parts], "threshold": k, "total": n}


def _api_combine(req: dict) -> dict:
    parts = [p.strip() for p in req.get("shares", []) if p.strip()]
    return {"secret": shamir.combine_shares(parts).decode("utf-8", "replace")}


def _api_selftest(_req: dict) -> dict:
    results = []
    ok_count = 0
    for name, fn in _checks():
        t0 = time.time()
        try:
            ok = bool(fn())
            err = ""
        except Exception as exc:  # noqa: BLE001
            ok, err = False, f"{type(exc).__name__}: {exc}"
        ok_count += int(ok)
        results.append({"name": name, "ok": ok, "ms": round((time.time() - t0) * 1000, 1), "error": err})
    return {"results": results, "passed": ok_count, "total": len(results)}


def _api_config(_req: dict) -> dict:
    return {
        "version": triglyph.__version__,
        "backend": BACKEND,
        "backendInfo": backend_info(),
        "suites": {name: SUITE_DESCRIPTION[sid] for name, sid in SUITES.items()},
        "profiles": {name: p.describe() for name, p in PROFILES.items()},
        "armors": [a for a in armor_mod.ARMORS if a != "raw"],
    }


ROUTES = {
    "/api/encrypt": _api_encrypt,
    "/api/decrypt": _api_decrypt,
    "/api/inspect": _api_inspect,
    "/api/passgen": _api_passgen,
    "/api/split": _api_split,
    "/api/combine": _api_combine,
    "/api/selftest": _api_selftest,
    "/api/config": _api_config,
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"TRIGLYPH/{triglyph.__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # компактный лог
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            path = "/index.html"
        elif path == "/api/config":
            self._json(200, _api_config({}))
            return
        elif path == "/healthz":
            self._json(200, {"ok": True})
            return
        rel = path.lstrip("/")
        target = os.path.normpath(os.path.join(STATIC, rel))
        if not target.startswith(STATIC) or not os.path.isfile(target):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        with open(target, "rb") as fh:
            self._send(200, fh.read(), ctype)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        handler = ROUTES.get(path)
        if handler is None:
            self._json(404, {"error": "unknown endpoint"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json(413, {"error": "payload too large"})
                return
            req = json.loads(self.rfile.read(length) or b"{}")
            self._json(200, {"ok": True, **handler(req)})
        except (IntegrityError, CryptoError, FormatError) as exc:
            self._json(200, {"ok": False, "error": str(exc), "kind": type(exc).__name__})
        except ValueError as exc:
            self._json(200, {"ok": False, "error": str(exc), "kind": "ValueError"})
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"TRIGLYPH demo → http://{host}:{port}  (backend: {BACKEND})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
