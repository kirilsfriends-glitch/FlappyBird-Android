"""
triglyph.cli — интерфейс командной строки на трёх языках.

    python -m triglyph --help
    python -m triglyph --lang en --help
    python -m triglyph --lang zh --help
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import math
import os
import secrets
import sys
import time
from typing import Optional

from . import __version__, armor, shamir
from . import text as _text
from ._util import CryptoError, FormatError, IntegrityError
from .backend import BACKEND, backend_info
from .cipher import (
    MAGIC,
    SUITES,
    decrypt,
    decrypt_stream,
    encrypt,
    encrypt_stream,
    inspect as inspect_container,
)
from .i18n import LANGS, get_lang, set_lang, t
from .kdf import PROFILES
from .selftest import run_self_test
from .stealth import looks_stealth
from .x25519 import generate_private_key, public_key

SECRET_TAG = "TRIGLYPH-SECRET-KEY-X25519"
PUBLIC_TAG = "TRIGLYPH-PUBLIC-KEY-X25519"
SYMKEY_TAG = "TRIGLYPH-SYMMETRIC-KEY"

PAD_POLICIES = {
    "padme": _text.PAD_PADME,
    "bucket": _text.PAD_BUCKET,
    "none": _text.PAD_NONE,
}


# --------------------------------------------------------------------------
# вспомогательное
# --------------------------------------------------------------------------

def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_key_text(path: str, tag: str) -> Optional[bytes]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(tag):
                    return _unb64(line[len(tag) :].strip())
    except (UnicodeDecodeError, OSError):
        return None
    return None


def load_public_key(spec: str) -> bytes:
    """Публичный ключ: путь к файлу, hex или base64url."""
    if os.path.exists(spec):
        key = _load_key_text(spec, PUBLIC_TAG)
        if key:
            return key
        with open(spec, "rb") as fh:
            raw = fh.read().strip()
        if len(raw) == 32:
            return raw
        spec = raw.decode("utf-8", "replace").strip()
    try:
        if len(spec) == 64:
            return bytes.fromhex(spec)
        key = _unb64(spec)
        if len(key) == 32:
            return key
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(f"не удалось прочитать публичный ключ / cannot read public key: {spec}")


def load_private_key(path: str) -> bytes:
    key = _load_key_text(path, SECRET_TAG)
    if key:
        return key
    with open(path, "rb") as fh:
        raw = fh.read().strip()
    if len(raw) == 32:
        return raw
    try:
        txt = raw.decode("utf-8").strip()
        if len(txt) == 64:
            return bytes.fromhex(txt)
        key = _unb64(txt)
        if len(key) == 32:
            return key
    except Exception:  # noqa: BLE001
        pass
    raise SystemExit(f"не удалось прочитать секретный ключ / cannot read private key: {path}")


def load_raw_key(path: str) -> bytes:
    key = _load_key_text(path, SYMKEY_TAG)
    if key:
        return key
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) < 32:
        raise SystemExit("ключевой файл короче 32 байт / key file shorter than 32 bytes")
    return raw


def password_entropy_bits(pw: str) -> int:
    """Грубая оценка энтропии пароля по составу алфавита."""
    classes = 0
    if any(c.islower() and c.isascii() for c in pw):
        classes += 26
    if any(c.isupper() and c.isascii() for c in pw):
        classes += 26
    if any(c.isdigit() for c in pw):
        classes += 10
    if any(not c.isalnum() for c in pw):
        classes += 32
    if any(0x0400 <= ord(c) <= 0x04FF for c in pw):
        classes += 66
    if any(0x4E00 <= ord(c) <= 0x9FFF for c in pw):
        classes += 3000
    classes = max(classes, 2)
    return int(len(pw) * math.log2(classes))


def get_password(args, confirm: bool) -> Optional[str]:
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_env", None):
        val = os.environ.get(args.password_env)
        if val is None:
            raise SystemExit(f"environment variable {args.password_env} is not set")
        return val
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as fh:
            return fh.readline().rstrip("\n")
    if getattr(args, "key_file", None) or getattr(args, "to", None) or getattr(args, "identity", None):
        return None
    pw = getpass.getpass(t("msg.password_prompt"))
    if not pw:
        raise SystemExit(t("msg.password_empty"))
    if confirm:
        again = getpass.getpass(t("msg.password_repeat"))
        if pw != again:
            raise SystemExit(t("msg.password_mismatch"))
        bits = password_entropy_bits(pw)
        if bits < 60:
            _err(t("msg.password_weak", bits=bits))
    return pw


def read_input_bytes(args) -> tuple[bytes, str]:
    if getattr(args, "message", None) is not None:
        return args.message.encode("utf-8"), "<message>"
    path = getattr(args, "infile", None)
    if path in (None, "-"):
        return sys.stdin.buffer.read(), "<stdin>"
    with open(path, "rb") as fh:
        return fh.read(), path


def write_output(data: bytes, path: Optional[str], force: bool = False) -> str:
    if path in (None, "-"):
        sys.stdout.buffer.write(data)
        if data and not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
        return "<stdout>"
    if os.path.exists(path) and not force:
        raise SystemExit(t("msg.file_exists", path=path))
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# --------------------------------------------------------------------------
# команды
# --------------------------------------------------------------------------

def cmd_encrypt(args) -> int:
    data, src_name = read_input_bytes(args)
    password = get_password(args, confirm=not (args.password or args.password_file or args.password_env))
    key = load_raw_key(args.key_file) if args.key_file else None
    recipient = load_public_key(args.to) if args.to else None
    sender_private = load_private_key(args.sign) if args.sign else None
    pepper = b""
    if args.pepper_file:
        with open(args.pepper_file, "rb") as fh:
            pepper = fh.read()
    if password is None and key is None and recipient is None:
        raise SystemExit(t("msg.no_key_source"))

    is_text = args.message is not None
    armor_kind = args.armor
    if armor_kind == "auto":
        if is_text:
            lang = _text.detect_language(args.message)
            armor_kind = {"zh": "hanzi", "ru": "cyrillic"}.get(lang, "latin")
            if args.verbose:
                _err(t("msg.detected_lang", lang=_text.LANG_NAMES[lang][get_lang()]))
        else:
            armor_kind = "raw" if args.outfile not in (None, "-") else "latin"

    if is_text:
        data = _text.normalize_text(args.message).encode("utf-8")

    pad = PAD_POLICIES[args.pad]
    if is_text and args.pad == "padme":
        pad = _text.PAD_BUCKET  # у текста прячем длину агрессивнее: язык не должен «светиться»

    if len(data) > 4 << 20 and args.suite == "triple" and args.verbose:
        _err(t("msg.large_file_hint"))

    started = time.time()
    blob = encrypt(
        data,
        password=password,
        key=key,
        recipient=recipient,
        sender_private=sender_private,
        suite=args.suite,
        profile=args.profile,
        aad=args.aad.encode("utf-8") if args.aad else b"",
        pad=pad,
        stealth=args.stealth,
        pepper=pepper,
    )
    elapsed = time.time() - started

    if armor_kind == "raw":
        out = write_output(blob, args.outfile, args.force)
    else:
        text = armor.encode(blob, armor_kind, width=args.wrap)
        if args.envelope:
            text = armor.wrap_message(
                text,
                [("Suite", args.suite), ("Armor", armor_kind), ("Version", f"TRIGLYPH/{__version__}")],
            )
        out = write_output((text + "\n").encode("utf-8"), args.outfile, args.force)

    if args.verbose or (args.outfile not in (None, "-")):
        _err(
            t("msg.encrypted", inp=src_name, out=out, size=len(blob),
              suite=args.suite, profile=args.profile)
            + f"  [{elapsed:.2f}s]"
        )
    return 0


def _decode_container(raw: bytes) -> bytes:
    if raw.startswith(MAGIC) or looks_stealth(raw, MAGIC):
        return raw
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("не похоже на контейнер TRIGLYPH / not a TRIGLYPH container") from exc
    payload, _headers = armor.unwrap_message(text)
    return armor.decode(payload)


def cmd_decrypt(args) -> int:
    raw, src_name = read_input_bytes(args)
    blob = _decode_container(raw)
    password = get_password(args, confirm=False)
    key = load_raw_key(args.key_file) if args.key_file else None
    private = load_private_key(args.identity) if args.identity else None
    expect = load_public_key(args.expect_sender) if args.expect_sender else None
    pepper = b""
    if args.pepper_file:
        with open(args.pepper_file, "rb") as fh:
            pepper = fh.read()
    try:
        data = decrypt(
            blob,
            password=password,
            key=key,
            private_key=private,
            expect_sender=expect,
            pepper=pepper,
        )
    except (IntegrityError, CryptoError, FormatError) as exc:
        _err(t("msg.integrity_fail", err=str(exc)))
        return 2

    out = write_output(data, args.outfile, args.force)
    if args.verbose or (args.outfile not in (None, "-")):
        _err(t("msg.decrypted", inp=src_name, out=out, size=len(data)))
    return 0


def cmd_encrypt_file(args) -> int:
    """Потоковое шифрование больших файлов."""
    password = get_password(args, confirm=not (args.password or args.password_file or args.password_env))
    key = load_raw_key(args.key_file) if args.key_file else None
    recipient = load_public_key(args.to) if args.to else None
    sender_private = load_private_key(args.sign) if args.sign else None
    if password is None and key is None and recipient is None:
        raise SystemExit(t("msg.no_key_source"))
    if os.path.exists(args.outfile) and not args.force:
        raise SystemExit(t("msg.file_exists", path=args.outfile))
    total = os.path.getsize(args.infile) if args.infile != "-" else 0
    done = [0]

    def progress(n: int) -> None:
        done[0] += n
        if total and args.verbose:
            pct = 100.0 * done[0] / total
            print(f"\r  {pct:5.1f} %", end="", file=sys.stderr)

    started = time.time()
    fin = sys.stdin.buffer if args.infile == "-" else open(args.infile, "rb")
    fout = sys.stdout.buffer if args.outfile == "-" else open(args.outfile, "wb")
    try:
        written = encrypt_stream(
            fin, fout,
            password=password, key=key, recipient=recipient, sender_private=sender_private,
            suite=args.suite, profile=args.profile, stealth=args.stealth, progress=progress,
        )
    finally:
        if fin is not sys.stdin.buffer:
            fin.close()
        if fout is not sys.stdout.buffer:
            fout.close()
    if args.verbose:
        print("", file=sys.stderr)
    _err(
        t("msg.encrypted", inp=args.infile, out=args.outfile, size=written,
          suite=args.suite, profile=args.profile) + f"  [{time.time()-started:.2f}s]"
    )
    return 0


def cmd_decrypt_file(args) -> int:
    password = get_password(args, confirm=False)
    key = load_raw_key(args.key_file) if args.key_file else None
    private = load_private_key(args.identity) if args.identity else None
    if os.path.exists(args.outfile) and not args.force:
        raise SystemExit(t("msg.file_exists", path=args.outfile))
    fin = sys.stdin.buffer if args.infile == "-" else open(args.infile, "rb")
    fout = sys.stdout.buffer if args.outfile == "-" else open(args.outfile, "wb")
    started = time.time()
    try:
        written = decrypt_stream(fin, fout, password=password, key=key, private_key=private)
    except (IntegrityError, CryptoError, FormatError) as exc:
        if fout is not sys.stdout.buffer:
            fout.close()
            os.unlink(args.outfile)  # не оставляем непроверенный «мусор»
        _err(t("msg.integrity_fail", err=str(exc)))
        return 2
    finally:
        if fin is not sys.stdin.buffer:
            fin.close()
        if fout is not sys.stdout.buffer and not fout.closed:
            fout.close()
    _err(t("msg.decrypted", inp=args.infile, out=args.outfile, size=written)
         + f"  [{time.time()-started:.2f}s]")
    return 0


def cmd_keygen(args) -> int:
    priv = generate_private_key()
    pub = public_key(priv)
    if args.out:
        sk_path, pk_path = f"{args.out}.key", f"{args.out}.pub"
        for p in (sk_path, pk_path):
            if os.path.exists(p) and not args.force:
                raise SystemExit(t("msg.file_exists", path=p))
        with open(sk_path, "w", encoding="utf-8") as fh:
            fh.write("# TRIGLYPH X25519 — секретный ключ / private key / 私钥\n")
            fh.write("# НИКОМУ НЕ ПОКАЗЫВАТЬ / KEEP SECRET / 请勿泄露\n")
            fh.write(f"{SECRET_TAG} {_b64(priv)}\n")
        os.chmod(sk_path, 0o600)
        with open(pk_path, "w", encoding="utf-8") as fh:
            fh.write("# TRIGLYPH X25519 — публичный ключ / public key / 公钥\n")
            fh.write(f"{PUBLIC_TAG} {_b64(pub)}\n")
        print(t("msg.keys_written", sk=sk_path, pk=pk_path, pub=f"{PUBLIC_TAG} {_b64(pub)}"))
    else:
        print(f"{SECRET_TAG} {_b64(priv)}")
        print(f"{PUBLIC_TAG} {_b64(pub)}")
    return 0


def cmd_randkey(args) -> int:
    key = secrets.token_bytes(args.bytes)
    line = f"{SYMKEY_TAG} {_b64(key)}"
    if args.out:
        if os.path.exists(args.out) and not args.force:
            raise SystemExit(t("msg.file_exists", path=args.out))
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("# TRIGLYPH — симметричный ключ / symmetric key / 对称密钥\n")
            fh.write(line + "\n")
        os.chmod(args.out, 0o600)
        print(args.out)
    else:
        print(line)
    print(t("msg.entropy", bits=args.bytes * 8), file=sys.stderr)
    return 0


def cmd_inspect(args) -> int:
    raw, _ = read_input_bytes(args)
    blob = _decode_container(raw)
    info = inspect_container(blob)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        width = max(len(k) for k in info)
        for k, v in info.items():
            print(f"{k.ljust(width)} : {v}")
    return 0


def cmd_split(args) -> int:
    if args.secret_file:
        with open(args.secret_file, "rb") as fh:
            secret = fh.read().strip()
    elif args.secret:
        secret = args.secret.encode("utf-8")
    else:
        secret = secrets.token_bytes(32)
        print(f"# случайный секрет / random secret: {SYMKEY_TAG} {_b64(secret)}", file=sys.stderr)
    parts = shamir.split_secret(secret, args.threshold, args.shares)
    for p in parts:
        print(f"{p.index}/{args.shares}: {p.armored(args.armor)}")
    _err(t("msg.shares_hint", k=args.threshold, n=args.shares, k1=args.threshold - 1))
    return 0


def cmd_combine(args) -> int:
    pieces = []
    for item in args.shares:
        if os.path.exists(item):
            with open(item, "r", encoding="utf-8") as fh:
                pieces.extend(ln.strip().split(": ")[-1] for ln in fh if ln.strip())
        else:
            pieces.append(item.split(": ")[-1])
    secret = shamir.combine_shares(pieces)
    try:
        sys.stdout.write(secret.decode("utf-8") + "\n")
    except UnicodeDecodeError:
        sys.stdout.write(f"{SYMKEY_TAG} {_b64(secret)}\n")
    return 0


def cmd_armor(args) -> int:
    raw, _ = read_input_bytes(args)
    if args.action == "encode":
        print(armor.encode(raw, args.kind, width=args.wrap))
    else:
        data = armor.decode(raw.decode("utf-8"), None if args.kind == "auto" else args.kind)
        sys.stdout.buffer.write(data)
    return 0


def cmd_selftest(args) -> int:
    ok = run_self_test(verbose=args.verbose)
    print(t("msg.selftest_ok") if ok else t("msg.selftest_fail"))
    return 0 if ok else 1


def cmd_bench(args) -> int:
    size = args.kib * 1024
    data = os.urandom(size)
    print(t("msg.bench_header", backend=BACKEND))
    print(f"{'suite':10s} {'encrypt':>12s} {'decrypt':>12s}")
    for suite in ("solo", "dual", "triple"):
        t0 = time.time()
        blob = encrypt(data, key=b"\x01" * 32, suite=suite, pad=_text.PAD_NONE)
        t1 = time.time()
        decrypt(blob, key=b"\x01" * 32)
        t2 = time.time()
        print(
            f"{suite:10s} {size/1024/1024/(t1-t0):9.2f} МБ/с {size/1024/1024/(t2-t1):9.2f} МБ/с"
        )
    print()
    for name, prof in PROFILES.items():
        from .kdf import derive_master_secret

        t0 = time.time()
        derive_master_secret("benchmark", b"0" * 32, prof)
        print(f"KDF {name:10s} {(time.time()-t0)*1000:8.0f} мс   {prof.describe()}")
    print()
    for k, v in backend_info().items():
        print(f"{k}: {v}")
    return 0


def _generate_password(style: str, bits: int) -> tuple[str, float]:
    """Возвращает (пароль, фактическая энтропия в битах)."""
    if style == "hanzi":
        alphabet = [chr(0x4E00 + i) for i in range(4096)]  # тот же набор, что у брони
        per = 12.0
        n = math.ceil(bits / per)
        return "".join(secrets.choice(alphabet) for _ in range(n)), n * per
    if style == "cyrillic":
        cons, vow = "бвгджзклмнпрстфхцчшщ", "аеиоуыэюя"
        per = math.log2(len(cons) * len(vow))
        n = math.ceil(bits / per)
        pw = "-".join(secrets.choice(cons) + secrets.choice(vow) for _ in range(n))
        return pw, n * per
    if style == "latin":
        alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?"
        per = math.log2(len(alphabet))
        n = math.ceil(bits / per)
        return "".join(secrets.choice(alphabet) for _ in range(n)), n * per
    # mixed: по куску каждой письменности — легче запомнить, труднее подобрать
    parts, total = [], 0.0
    for st in ("hanzi", "cyrillic", "latin"):
        pw, got = _generate_password(st, bits / 3)
        parts.append(pw)
        total += got
    return "·".join(parts), total


def cmd_passgen(args) -> int:
    pw, bits = _generate_password(args.style, args.bits)
    print(pw)
    print(t("msg.entropy", bits=int(bits)), file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# разбор аргументов
# --------------------------------------------------------------------------

def _add_common_key_args(p: argparse.ArgumentParser, *, decrypting: bool) -> None:
    p.add_argument("-p", "--password", help=t("opt.password"))
    p.add_argument("--password-file", help=t("opt.passfile"))
    p.add_argument("--password-env", help=t("opt.passenv"))
    p.add_argument("--key-file", help=t("opt.keyfile"))
    p.add_argument("--pepper-file", help=t("opt.keyfile2"))
    if decrypting:
        p.add_argument("--identity", help=t("opt.identity"))
        p.add_argument("--expect-sender", help=t("opt.expect"))
    else:
        p.add_argument("--to", help=t("opt.to"))
        p.add_argument("--sign", help=t("opt.sign"))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="triglyph",
        description=t("app.desc"),
        epilog=t("app.epilog"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--lang", choices=LANGS, help=t("opt.lang"))
    ap.add_argument("--version", action="version", version=f"TRIGLYPH {__version__} [{BACKEND}]")
    sub = ap.add_subparsers(dest="command", required=True)

    # encrypt
    e = sub.add_parser("encrypt", aliases=["enc", "e"], help=t("cmd.encrypt"))
    e.add_argument("-m", "--message", help=t("opt.message"))
    e.add_argument("-i", "--infile", help=t("opt.infile"))
    e.add_argument("-o", "--outfile", help=t("opt.outfile"))
    _add_common_key_args(e, decrypting=False)
    e.add_argument("--suite", choices=list(SUITES), default="triple", help=t("opt.suite"))
    e.add_argument("--profile", choices=list(PROFILES), default="balanced", help=t("opt.profile"))
    e.add_argument("--armor", choices=["auto", *armor.ARMORS], default="auto", help=t("opt.armor"))
    e.add_argument("--pad", choices=list(PAD_POLICIES), default="padme", help=t("opt.pad"))
    e.add_argument("--stealth", action="store_true", help=t("opt.stealth"))
    e.add_argument("--aad", help=t("opt.aad"))
    e.add_argument("--wrap", type=int, default=0, help=t("opt.wrap"))
    e.add_argument("--envelope", action="store_true", help=t("opt.envelope"))
    e.add_argument("-f", "--force", action="store_true", help=t("opt.force"))
    e.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))
    e.set_defaults(func=cmd_encrypt)

    # decrypt
    d = sub.add_parser("decrypt", aliases=["dec", "d"], help=t("cmd.decrypt"))
    d.add_argument("-m", "--message", help=t("opt.message"))
    d.add_argument("-i", "--infile", help=t("opt.infile"))
    d.add_argument("-o", "--outfile", help=t("opt.outfile"))
    _add_common_key_args(d, decrypting=True)
    d.add_argument("-f", "--force", action="store_true", help=t("opt.force"))
    d.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))
    d.set_defaults(func=cmd_decrypt)

    # encrypt-file / decrypt-file (потоковые)
    ef = sub.add_parser("encrypt-file", aliases=["encf"], help=t("cmd.encrypt") + " (stream)")
    ef.add_argument("infile")
    ef.add_argument("outfile")
    _add_common_key_args(ef, decrypting=False)
    ef.add_argument("--suite", choices=list(SUITES), default="dual", help=t("opt.suite"))
    ef.add_argument("--profile", choices=list(PROFILES), default="balanced", help=t("opt.profile"))
    ef.add_argument("--stealth", action="store_true", help=t("opt.stealth"))
    ef.add_argument("-f", "--force", action="store_true", help=t("opt.force"))
    ef.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))
    ef.set_defaults(func=cmd_encrypt_file)

    df = sub.add_parser("decrypt-file", aliases=["decf"], help=t("cmd.decrypt") + " (stream)")
    df.add_argument("infile")
    df.add_argument("outfile")
    _add_common_key_args(df, decrypting=True)
    df.add_argument("-f", "--force", action="store_true", help=t("opt.force"))
    df.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))
    df.set_defaults(func=cmd_decrypt_file)

    # keys
    k = sub.add_parser("keygen", help=t("cmd.keygen"))
    k.add_argument("-o", "--out", help="префикс файлов / file prefix / 文件前缀")
    k.add_argument("-f", "--force", action="store_true", help=t("opt.force"))
    k.set_defaults(func=cmd_keygen)

    rk = sub.add_parser("randkey", help=t("cmd.randkey"))
    rk.add_argument("--bytes", type=int, default=32)
    rk.add_argument("-o", "--out")
    rk.add_argument("-f", "--force", action="store_true")
    rk.set_defaults(func=cmd_randkey)

    # inspect
    i = sub.add_parser("inspect", aliases=["info"], help=t("cmd.inspect"))
    i.add_argument("-i", "--infile", help=t("opt.infile"))
    i.add_argument("-m", "--message", help=t("opt.message"))
    i.add_argument("--json", action="store_true", help=t("opt.json"))
    i.set_defaults(func=cmd_inspect)

    # shamir
    sp = sub.add_parser("split", help=t("cmd.split"))
    sp.add_argument("-k", "--threshold", type=int, default=3)
    sp.add_argument("-n", "--shares", type=int, default=5)
    sp.add_argument("--secret")
    sp.add_argument("--secret-file")
    sp.add_argument("--armor", choices=["hanzi", "cyrillic", "latin", "grouped"], default="latin")
    sp.set_defaults(func=cmd_split)

    cb = sub.add_parser("combine", help=t("cmd.combine"))
    cb.add_argument("shares", nargs="+")
    cb.set_defaults(func=cmd_combine)

    # armor
    a = sub.add_parser("armor", help=t("cmd.armor"))
    a.add_argument("action", choices=["encode", "decode"])
    a.add_argument("-i", "--infile", help=t("opt.infile"))
    a.add_argument("-m", "--message", help=t("opt.message"))
    a.add_argument("--kind", choices=["auto", "hanzi", "cyrillic", "latin", "grouped"], default="auto")
    a.add_argument("--wrap", type=int, default=0)
    a.set_defaults(func=cmd_armor)

    # selftest / bench / passgen
    st = sub.add_parser("selftest", aliases=["test"], help=t("cmd.selftest"))
    st.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))
    st.set_defaults(func=cmd_selftest)

    b = sub.add_parser("bench", help=t("cmd.bench"))
    b.add_argument("--kib", type=int, default=256)
    b.set_defaults(func=cmd_bench)

    pg = sub.add_parser("passgen", aliases=["pass"], help=t("cmd.passgen"))
    pg.add_argument("--style", choices=["hanzi", "cyrillic", "latin", "mixed"], default="mixed")
    pg.add_argument("--bits", type=int, default=128)
    pg.set_defaults(func=cmd_passgen)

    return ap


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    lang = None
    for i, a in enumerate(argv):
        if a == "--lang" and i + 1 < len(argv):
            lang = argv[i + 1]
        elif a.startswith("--lang="):
            lang = a.split("=", 1)[1]
    set_lang(lang)

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _err("\n^C")
        return 130
    except (IntegrityError, CryptoError, FormatError) as exc:
        _err(t("msg.integrity_fail", err=str(exc)))
        return 2
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
