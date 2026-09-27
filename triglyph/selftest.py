"""
triglyph.selftest — самопроверка на официальных тест-векторах.

Проверяются все криптографические примитивы по опубликованным векторам:
  * ChaCha20, Poly1305, ChaCha20-Poly1305 — RFC 8439
  * HChaCha20 — draft-irtf-cfrg-xchacha
  * AES-128/192/256 — FIPS-197 (Appendix C)
  * AES-GCM — McGrew & Viega / NIST SP 800-38D
  * HKDF — RFC 5869
  * X25519 — RFC 7748
  * Threefish-1024 — структурные свойства (обратимость, лавинный эффект)
затем — сквозные проверки контейнера: шифрование, подделка, обрезание,
неверный ключ, все брони и разделение секрета.

Запуск: ``python -m triglyph selftest -v``
"""

from __future__ import annotations

import io
import os
import time
from typing import Callable, List, Tuple

from . import armor, shamir
from ._util import CryptoError, IntegrityError

H = bytes.fromhex


# ------------------------- официальные векторы ----------------------------

KAT_CHACHA20_BLOCK = {
    "key": H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    "nonce": H("000000090000004a00000000"),
    "counter": 1,
    "out": H(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    ),
}

RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)

KAT_CHACHA20_ENCRYPT = {
    "key": H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    "nonce": H("000000000000004a00000000"),
    "counter": 1,
    "plaintext": RFC8439_PLAINTEXT,
    "ciphertext": H(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    ),
}

KAT_POLY1305 = {
    "key": H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
    "msg": b"Cryptographic Forum Research Group",
    "tag": H("a8061dc1305136c6c22b8baf0c0127a9"),
}

KAT_CHACHA20POLY1305 = {
    "key": H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    "nonce": H("070000004041424344454647"),
    "aad": H("50515253c0c1c2c3c4c5c6c7"),
    "plaintext": RFC8439_PLAINTEXT,
    "ciphertext": H(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    ),
    "tag": H("1ae10b594f09e26a7e902ecbd0600691"),
}

KAT_HCHACHA20 = {
    "key": H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    "nonce": H("000000090000004a0000000031415927"),
    "out": H("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
}

KAT_AES_ECB = [
    # FIPS-197 Appendix C.1 / C.2 / C.3
    (H("000102030405060708090a0b0c0d0e0f"), H("00112233445566778899aabbccddeeff"),
     H("69c4e0d86a7b0430d8cdb78070b4c55a")),
    (H("000102030405060708090a0b0c0d0e0f1011121314151617"), H("00112233445566778899aabbccddeeff"),
     H("dda97ca4864cdfe06eaf70a0ec0d7191")),
    (H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
     H("00112233445566778899aabbccddeeff"), H("8ea2b7ca516745bfeafc49904b496089")),
]

KAT_AES_GCM = [
    # McGrew & Viega, test cases 13 и 14 (AES-256)
    {"key": bytes(32), "iv": bytes(12), "pt": b"", "aad": b"",
     "ct": b"", "tag": H("530f8afbc74536b9a963b4f1c4cb738b")},
    {"key": bytes(32), "iv": bytes(12), "pt": bytes(16), "aad": b"",
     "ct": H("cea7403d4d606b6e074ec5d3baf39d18"), "tag": H("d0d1c8a799996bf0265b98b5d48ab919")},
]

KAT_HKDF = [
    # RFC 5869, тест-кейсы 1 и 3 (SHA-256)
    {"ikm": b"\x0b" * 22, "salt": H("000102030405060708090a0b0c"), "info": H("f0f1f2f3f4f5f6f7f8f9"),
     "len": 42,
     "okm": H("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")},
    {"ikm": b"\x0b" * 22, "salt": b"", "info": b"", "len": 42,
     "okm": H("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")},
]

KAT_X25519 = [
    # RFC 7748 §5.2
    (H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
     H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
     H("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")),
    (H("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
     H("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
     H("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")),
]

KAT_X25519_DH = {
    # RFC 7748 §6.1
    "alice_sk": H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    "alice_pk": H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    "bob_sk": H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    "bob_pk": H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
    "shared": H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
}

SAMPLE_TEXTS = {
    "zh": "黎明时分发起进攻，联络点已暴露，请从第三个楼梯撤离。密码是「三纹」。",
    "ru": "Атака начнётся на рассвете. Явка провалена — уходи через третий подъезд.",
    "en": "The attack begins at dawn. The safe house is blown; leave by the third stairwell.",
}


# ----------------------------- проверки ------------------------------------

def _checks() -> List[Tuple[str, Callable[[], bool]]]:
    from . import cipher as C
    from . import kdf as K
    from . import text as T
    from .aes import AES, aes_gcm_decrypt, aes_gcm_encrypt
    from .chacha import (
        chacha20_block,
        chacha20_xor,
        chacha20poly1305_encrypt,
        hchacha20,
        poly1305_mac,
        xchacha20poly1305_decrypt,
        xchacha20poly1305_encrypt,
    )
    from .threefish import Threefish1024, threefish1024_ctr_xor
    from .x25519 import key_exchange, public_key, x25519

    out: List[Tuple[str, Callable[[], bool]]] = []
    add = lambda name, fn: out.append((name, fn))  # noqa: E731

    v = KAT_CHACHA20_BLOCK
    add("ChaCha20 block function (RFC 8439 §2.3.2)",
        lambda: chacha20_block(v["key"], v["counter"], v["nonce"]) == v["out"])

    v2 = KAT_CHACHA20_ENCRYPT
    add("ChaCha20 encryption (RFC 8439 §2.4.2)",
        lambda: chacha20_xor(v2["key"], v2["counter"], v2["nonce"], v2["plaintext"]) == v2["ciphertext"])

    v3 = KAT_POLY1305
    add("Poly1305 (RFC 8439 §2.5.2)", lambda: poly1305_mac(v3["msg"], v3["key"]) == v3["tag"])

    v4 = KAT_CHACHA20POLY1305
    add("ChaCha20-Poly1305 AEAD (RFC 8439 §2.8.2)",
        lambda: chacha20poly1305_encrypt(v4["key"], v4["nonce"], v4["plaintext"], v4["aad"])
        == v4["ciphertext"] + v4["tag"])

    v5 = KAT_HCHACHA20
    add("HChaCha20 (draft-irtf-cfrg-xchacha §2.2.1)",
        lambda: hchacha20(v5["key"], v5["nonce"]) == v5["out"])

    def _xchacha_rt() -> bool:
        k, n = os.urandom(32), os.urandom(24)
        ct = xchacha20poly1305_encrypt(k, n, b"xchacha", b"aad")
        return xchacha20poly1305_decrypt(k, n, ct, b"aad") == b"xchacha"

    add("XChaCha20-Poly1305 roundtrip", _xchacha_rt)

    for i, (k, p, c) in enumerate(KAT_AES_ECB):
        add(f"AES-{len(k)*8} block (FIPS-197 C.{i+1})",
            lambda k=k, p=p, c=c: AES(k).encrypt_block(p) == c and AES(k).decrypt_block(c) == p)

    for i, g in enumerate(KAT_AES_GCM):
        add(f"AES-256-GCM (test case {13+i})",
            lambda g=g: aes_gcm_encrypt(g["key"], g["iv"], g["pt"], g["aad"]) == g["ct"] + g["tag"])

    def _gcm_reject() -> bool:
        ct = aes_gcm_encrypt(bytes(32), bytes(12), b"data")
        bad = bytearray(ct)
        bad[0] ^= 0x80
        try:
            aes_gcm_decrypt(bytes(32), bytes(12), bytes(bad))
        except IntegrityError:
            return True
        return False

    add("AES-GCM отвергает подделку тега", _gcm_reject)

    def _threefish() -> bool:
        key, tw, blk = os.urandom(128), os.urandom(16), os.urandom(128)
        tf = Threefish1024(key, tw)
        ct = tf.encrypt_block(blk)
        if tf.decrypt_block(ct) != blk:
            return False
        flipped = bytearray(blk)
        flipped[7] ^= 0x10
        diff = sum(bin(a ^ b).count("1") for a, b in zip(ct, tf.encrypt_block(bytes(flipped))))
        if not 400 <= diff <= 624:  # лавинный эффект ≈ 512 из 1024 бит
            return False
        data = os.urandom(1000)
        return threefish1024_ctr_xor(key, tw, threefish1024_ctr_xor(key, tw, data)) == data

    add("Threefish-1024: обратимость, лавина, режим CTR", _threefish)

    for i, g in enumerate(KAT_HKDF):
        add(f"HKDF-SHA256 (RFC 5869 TC{i+1})",
            lambda g=g: K.hkdf(g["ikm"], g["salt"], g["info"], g["len"], "sha256") == g["okm"])

    for i, (sk, u, res) in enumerate(KAT_X25519):
        add(f"X25519 scalar mult (RFC 7748 §5.2 #{i+1})", lambda sk=sk, u=u, res=res: x25519(sk, u) == res)

    d = KAT_X25519_DH
    add("X25519 Diffie-Hellman (RFC 7748 §6.1)",
        lambda: public_key(d["alice_sk"]) == d["alice_pk"]
        and public_key(d["bob_sk"]) == d["bob_pk"]
        and key_exchange(d["alice_sk"], d["bob_pk"]) == d["shared"]
        and key_exchange(d["bob_sk"], d["alice_pk"]) == d["shared"])

    add("Нормализация пароля (NFKC, полноширинные формы)",
        lambda: K.normalize_password("ｐａｓｓ密码") == K.normalize_password("pass密码"))

    add("Padmé: рост длины не больше 12 %",
        lambda: all(T.padme(n) >= n and T.padme(n) <= n * 1.12 + 2 for n in range(1, 5000, 7)))

    # --- контейнер ---
    def _roundtrip_all_suites() -> bool:
        for suite in ("triple", "dual", "solo"):
            for lang, msg in SAMPLE_TEXTS.items():
                blob = C.encrypt(msg.encode(), password="пароль密码", profile="fast", suite=suite)
                if C.decrypt(blob, password="пароль密码").decode() != msg:
                    return False
        return True

    add("Контейнер: все сюиты × три языка", _roundtrip_all_suites)

    def _wrong_password() -> bool:
        blob = C.encrypt(b"x", password="a", profile="fast")
        try:
            C.decrypt(blob, password="b")
        except IntegrityError:
            return True
        return False

    add("Контейнер: неверный пароль отвергается (key commitment)", _wrong_password)

    def _tamper() -> bool:
        blob = bytearray(C.encrypt(b"important data" * 10, password="p", profile="fast"))
        for pos in range(0, len(blob), max(1, len(blob) // 24)):
            probe = bytearray(blob)
            probe[pos] ^= 0x01
            try:
                C.decrypt(bytes(probe), password="p")
                return False
            except (IntegrityError, CryptoError):
                pass
        return True

    add("Контейнер: любая подмена байта обнаруживается", _tamper)

    def _truncate() -> bool:
        blob = C.encrypt(b"data" * 100, password="p", profile="fast")
        for cut in (1, 17, 64, len(blob) // 2):
            try:
                C.decrypt(blob[:-cut], password="p")
                return False
            except (IntegrityError, CryptoError):
                pass
        return True

    add("Контейнер: обрезание обнаруживается", _truncate)

    def _pk_modes() -> bool:
        from . import generate_keypair

        rsk, rpk = generate_keypair()
        ssk, spk = generate_keypair()
        anon = C.encrypt(b"anon", recipient=rpk)
        if C.decrypt(anon, private_key=rsk) != b"anon":
            return False
        auth = C.encrypt(b"auth", recipient=rpk, sender_private=ssk)
        if C.decrypt(auth, private_key=rsk, expect_sender=spk) != b"auth":
            return False
        wrong, _ = generate_keypair()
        try:
            C.decrypt(anon, private_key=wrong)
            return False
        except (IntegrityError, CryptoError):
            return True

    add("Асимметричный режим X25519 (анонимный и с подписью отправителя)", _pk_modes)

    def _stream() -> bool:
        data = os.urandom(200_000)
        src, dst = io.BytesIO(data), io.BytesIO()
        C.encrypt_stream(src, dst, password="p", profile="fast", suite="solo")
        dst.seek(0)
        out = io.BytesIO()
        C.decrypt_stream(dst, out, password="p")
        return out.getvalue() == data

    add("Потоковый режим (200 КиБ, несколько фрагментов)", _stream)

    def _stealth() -> bool:
        blob = C.encrypt(b"hidden", password="p", profile="fast", stealth=True)
        return not blob.startswith(C.MAGIC) and C.decrypt(blob, password="p") == b"hidden"

    add("Стелс-оболочка: сигнатура не видна", _stealth)

    def _armors() -> bool:
        for kind in ("hanzi", "cyrillic", "latin", "grouped"):
            for n in (0, 1, 2, 3, 16, 31, 32, 33, 100, 257):
                data = os.urandom(n)
                if armor.decode(armor.encode(data, kind), kind) != data:
                    return False
        return True

    add("Броня hanzi/cyrillic/latin/grouped: точный обратный разбор", _armors)

    def _armor_corrupt() -> bool:
        data = os.urandom(64)
        s = armor.encode(data, "cyrillic")
        broken = s[:10] + ("б" if s[10] != "б" else "в") + s[11:]
        try:
            armor.decode(broken, "cyrillic")
            return False
        except Exception:
            return True

    add("Броня: контрольная сумма ловит опечатку", _armor_corrupt)

    def _shamir() -> bool:
        secret = os.urandom(32)
        parts = shamir.split_secret(secret, 3, 5)
        if shamir.combine_shares([parts[3], parts[0], parts[4]]) != secret:
            return False
        try:
            shamir.combine_shares(parts[:2])
            return False
        except CryptoError:
            return True

    add("Схема Шамира 3-из-5 (и отказ при 2 частях)", _shamir)

    def _lang_detect() -> bool:
        return (
            T.detect_language(SAMPLE_TEXTS["zh"]) == "zh"
            and T.detect_language(SAMPLE_TEXTS["ru"]) == "ru"
            and T.detect_language(SAMPLE_TEXTS["en"]) == "en"
        )

    add("Определение языка: 中文 / русский / English", _lang_detect)

    def _length_hiding() -> bool:
        sizes = {
            lang: len(C.encrypt(msg.encode(), password="p", profile="fast", pad=T.PAD_BUCKET))
            for lang, msg in SAMPLE_TEXTS.items()
        }
        return len(set(sizes.values())) == 1

    add("Сокрытие длины: zh/ru/en дают одинаковый размер", _length_hiding)

    return out


def run_self_test(verbose: bool = False, writer=None) -> bool:
    """Выполняет все проверки. Возвращает True, если всё прошло."""
    import sys

    w = writer or sys.stdout
    checks = _checks()
    failed = 0
    started = time.time()
    for name, fn in checks:
        t0 = time.time()
        try:
            ok = bool(fn())
            err = ""
        except Exception as exc:  # noqa: BLE001
            ok = False
            err = f" [{type(exc).__name__}: {exc}]"
        dt = (time.time() - t0) * 1000
        if not ok:
            failed += 1
        if verbose or not ok:
            mark = "  OK  " if ok else " FAIL "
            print(f"[{mark}] {name}{err}  ({dt:.0f} ms)", file=w)
    total = time.time() - started
    print(
        f"\n{len(checks) - failed}/{len(checks)} проверок пройдено за {total:.2f} с"
        f" / checks passed / 项检查通过",
        file=w,
    )
    return failed == 0
