"""Сквозные проверки контейнера TRIGLYPH: стойкость к подделке и все режимы."""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import triglyph  # noqa: E402
from triglyph._util import CryptoError, FormatError, IntegrityError  # noqa: E402
from triglyph.cipher import (  # noqa: E402
    MAGIC,
    Header,
    decrypt,
    decrypt_stream,
    encrypt,
    encrypt_stream,
    inspect,
)
from triglyph.text import PAD_BUCKET, PAD_NONE, PAD_PADME  # noqa: E402

FAST = {"profile": "fast"}
TEXTS = {
    "zh": "黎明时分发起进攻，联络点已暴露。",
    "ru": "Атака на рассвете. Явка провалена.",
    "en": "Attack at dawn. The safe house is blown.",
}


class TestRoundtrip(unittest.TestCase):
    def test_all_suites_all_languages(self):
        for suite in ("triple", "dual", "solo"):
            for lang, msg in TEXTS.items():
                blob = encrypt(msg.encode(), password="пароль", suite=suite, **FAST)
                self.assertEqual(decrypt(blob, password="пароль").decode(), msg, f"{suite}/{lang}")

    def test_sizes_from_zero_to_multichunk(self):
        pw = "p"
        for n in (0, 1, 15, 16, 17, 255, 65535, 65536, 65537, 150000):
            data = os.urandom(n)
            blob = encrypt(data, password=pw, suite="solo", **FAST)
            self.assertEqual(decrypt(blob, password=pw), data, f"size {n}")

    def test_binary_data_untouched(self):
        data = bytes(range(256)) * 4
        blob = encrypt(data, password="p", **FAST)
        self.assertEqual(decrypt(blob, password="p"), data)

    def test_unicode_text_api(self):
        for msg in TEXTS.values():
            armored = triglyph.encrypt_text(msg, password="пароль密码", **FAST)
            self.assertEqual(triglyph.decrypt_text(armored, password="пароль密码"), msg)

    def test_normalisation_is_applied(self):
        composed = "\u0439"           # й
        decomposed = "\u0438\u0306"   # и + краткая
        a = triglyph.decrypt_text(triglyph.encrypt_text(decomposed, password="p", **FAST), password="p")
        self.assertEqual(a, composed)

    def test_ciphertext_differs_every_time(self):
        blobs = {encrypt(b"same", password="p", **FAST) for _ in range(5)}
        self.assertEqual(len(blobs), 5)

    def test_aad_is_authenticated(self):
        blob = encrypt(b"msg", password="p", aad="счёт №42".encode(), **FAST)
        self.assertEqual(decrypt(blob, password="p", aad="счёт №42".encode()), b"msg")
        with self.assertRaises(IntegrityError):
            decrypt(blob, password="p", aad=b"another")

    def test_raw_key_mode(self):
        key = os.urandom(32)
        blob = encrypt(b"raw", key=key)
        self.assertEqual(decrypt(blob, key=key), b"raw")
        with self.assertRaises(IntegrityError):
            decrypt(blob, key=os.urandom(32))

    def test_pepper_required(self):
        blob = encrypt(b"x", password="p", pepper=b"keyfile-bytes", **FAST)
        self.assertEqual(decrypt(blob, password="p", pepper=b"keyfile-bytes"), b"x")
        with self.assertRaises(IntegrityError):
            decrypt(blob, password="p")


class TestTamperResistance(unittest.TestCase):
    def setUp(self):
        self.pw = "пароль"
        self.blob = encrypt(b"important payload" * 20, password=self.pw, **FAST)

    def test_every_byte_flip_detected(self):
        for pos in range(0, len(self.blob), 7):
            probe = bytearray(self.blob)
            probe[pos] ^= 0x01
            with self.assertRaises((IntegrityError, FormatError, CryptoError), msg=f"pos {pos}"):
                decrypt(bytes(probe), password=self.pw)

    def test_truncation_detected(self):
        for cut in (1, 2, 33, 64, 65, len(self.blob) // 2):
            with self.assertRaises((IntegrityError, FormatError, CryptoError)):
                decrypt(self.blob[:-cut], password=self.pw)

    def test_appending_detected(self):
        with self.assertRaises((IntegrityError, FormatError, CryptoError)):
            decrypt(self.blob + b"\x00", password=self.pw)

    def test_wrong_password(self):
        with self.assertRaises(IntegrityError):
            decrypt(self.blob, password="Пароль")

    def test_key_commitment_blocks_second_key(self):
        """Ни один другой пароль не должен «успешно» открыть контейнер."""
        for pw in ("p", "пароль ", " пароль", "密码", ""):
            with self.assertRaises((IntegrityError, CryptoError)):
                decrypt(self.blob, password=pw)

    def test_chunk_reordering_detected(self):
        data = os.urandom(150000)
        blob = bytearray(encrypt(data, password="p", suite="solo", chunk_size=1024, **FAST))
        header, hlen = Header.parse(bytes(blob))
        body = bytes(blob[hlen:-64])
        # меняем местами два первых фрагмента
        n1 = int.from_bytes(body[:4], "big")
        c1 = body[4 : 4 + n1]
        rest = body[4 + n1 :]
        n2 = int.from_bytes(rest[:4], "big")
        c2 = rest[4 : 4 + n2]
        swapped = (
            n2.to_bytes(4, "big") + c2 + n1.to_bytes(4, "big") + c1 + rest[4 + n2 :]
        )
        forged = bytes(blob[:hlen]) + swapped + bytes(blob[-64:])
        with self.assertRaises((IntegrityError, FormatError, CryptoError)):
            decrypt(forged, password="p")

    def test_header_downgrade_detected(self):
        """Попытка подменить сюиту в заголовке на более слабую."""
        blob = bytearray(encrypt(b"secret", password="p", **FAST))
        self.assertEqual(blob[9], 1)  # suite = triple
        blob[9] = 3                   # -> solo
        with self.assertRaises((IntegrityError, CryptoError, FormatError)):
            decrypt(bytes(blob), password="p")

    def test_not_a_container(self):
        with self.assertRaises(FormatError):
            decrypt(b"hello world, definitely not a container", password="p")


class TestPublicKeyModes(unittest.TestCase):
    def setUp(self):
        self.rsk, self.rpk = triglyph.generate_keypair()
        self.ssk, self.spk = triglyph.generate_keypair()

    def test_anonymous(self):
        blob = encrypt("для получателя 给收件人".encode(), recipient=self.rpk)
        self.assertEqual(decrypt(blob, private_key=self.rsk).decode(), "для получателя 给收件人")

    def test_authenticated(self):
        blob = encrypt(b"signed", recipient=self.rpk, sender_private=self.ssk)
        self.assertEqual(decrypt(blob, private_key=self.rsk, expect_sender=self.spk), b"signed")

    def test_wrong_sender_expectation(self):
        blob = encrypt(b"signed", recipient=self.rpk, sender_private=self.ssk)
        with self.assertRaises(IntegrityError):
            decrypt(blob, private_key=self.rsk, expect_sender=self.rpk)

    def test_wrong_recipient(self):
        other, _ = triglyph.generate_keypair()
        blob = encrypt(b"x", recipient=self.rpk)
        with self.assertRaises((IntegrityError, CryptoError)):
            decrypt(blob, private_key=other)

    def test_ephemeral_key_is_fresh(self):
        a = inspect(encrypt(b"x", recipient=self.rpk))["ephemeral_public_key"]
        b = inspect(encrypt(b"x", recipient=self.rpk))["ephemeral_public_key"]
        self.assertNotEqual(a, b)

    def test_recipient_hidden_by_default(self):
        self.assertIsNone(inspect(encrypt(b"x", recipient=self.rpk))["recipient_hint"])
        self.assertIsNotNone(
            inspect(encrypt(b"x", recipient=self.rpk, hide_recipient=False))["recipient_hint"]
        )


class TestLengthHiding(unittest.TestCase):
    def test_bucket_equalises_languages(self):
        sizes = {
            lang: len(encrypt(msg.encode(), password="p", pad=PAD_BUCKET, **FAST))
            for lang, msg in TEXTS.items()
        }
        self.assertEqual(len(set(sizes.values())), 1, sizes)

    def test_padme_overhead_is_small(self):
        data = os.urandom(10_000)
        padded = len(encrypt(data, password="p", pad=PAD_PADME, suite="solo", **FAST))
        plain = len(encrypt(data, password="p", pad=PAD_NONE, suite="solo", **FAST))
        self.assertLess(padded - plain, len(data) * 0.13 + 16)

    def test_no_padding_is_exact(self):
        data = os.urandom(1000)
        blob = encrypt(data, password="p", pad=PAD_NONE, suite="solo", **FAST)
        self.assertEqual(decrypt(blob, password="p"), data)


class TestStealth(unittest.TestCase):
    def test_signature_hidden_and_recoverable(self):
        blob = encrypt(b"hidden message", password="p", stealth=True, **FAST)
        self.assertFalse(blob.startswith(MAGIC))
        self.assertEqual(decrypt(blob, password="p"), b"hidden message")

    def test_inspect_reports_stealth(self):
        self.assertTrue(inspect(encrypt(b"x", password="p", stealth=True, **FAST))["stealth"])
        self.assertFalse(inspect(encrypt(b"x", password="p", **FAST))["stealth"])

    def test_stealth_output_looks_random(self):
        blob = encrypt(os.urandom(5000), password="p", stealth=True, suite="solo", **FAST)
        # доля нулевых байтов у случайной строки ≈ 1/256
        zeros = blob.count(0) / len(blob)
        self.assertLess(zeros, 0.02)


class TestStreaming(unittest.TestCase):
    def test_roundtrip(self):
        for size in (0, 1, 1000, 65536, 200_000):
            data = os.urandom(size)
            dst = io.BytesIO()
            encrypt_stream(io.BytesIO(data), dst, password="p", suite="solo", **FAST)
            dst.seek(0)
            out = io.BytesIO()
            decrypt_stream(dst, out, password="p")
            self.assertEqual(out.getvalue(), data, f"size {size}")

    def test_small_chunks_multiple_frames(self):
        data = os.urandom(20_000)
        dst = io.BytesIO()
        encrypt_stream(io.BytesIO(data), dst, password="p", suite="solo", chunk_size=1024, **FAST)
        dst.seek(0)
        out = io.BytesIO()
        decrypt_stream(dst, out, password="p")
        self.assertEqual(out.getvalue(), data)

    def test_tamper_in_stream_detected(self):
        data = os.urandom(50_000)
        dst = io.BytesIO()
        encrypt_stream(io.BytesIO(data), dst, password="p", suite="solo", **FAST)
        blob = bytearray(dst.getvalue())
        blob[len(blob) // 2] ^= 0x20
        with self.assertRaises((IntegrityError, FormatError, CryptoError)):
            decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), password="p")

    def test_truncated_stream_detected(self):
        data = os.urandom(50_000)
        dst = io.BytesIO()
        encrypt_stream(io.BytesIO(data), dst, password="p", suite="solo", **FAST)
        blob = dst.getvalue()[:-100]
        with self.assertRaises((IntegrityError, FormatError, CryptoError)):
            decrypt_stream(io.BytesIO(blob), io.BytesIO(), password="p")

    def test_stealth_stream(self):
        data = os.urandom(70_000)
        dst = io.BytesIO()
        encrypt_stream(io.BytesIO(data), dst, password="p", suite="solo", stealth=True, **FAST)
        self.assertFalse(dst.getvalue().startswith(MAGIC))
        dst.seek(0)
        out = io.BytesIO()
        decrypt_stream(dst, out, password="p")
        self.assertEqual(out.getvalue(), data)

    def test_stream_output_readable_by_inmemory_api(self):
        data = b"cross-mode compatibility check" * 10
        dst = io.BytesIO()
        encrypt_stream(io.BytesIO(data), dst, password="p", suite="dual", **FAST)
        self.assertEqual(decrypt(dst.getvalue(), password="p"), data)

    def test_inmemory_output_readable_by_stream_api(self):
        for size in (0, 10, 70_000, 200_000):
            data = os.urandom(size)
            blob = encrypt(data, password="p", suite="solo", chunk_size=4096, **FAST)
            out = io.BytesIO()
            decrypt_stream(io.BytesIO(blob), out, password="p")
            self.assertEqual(out.getvalue(), data, f"size {size}")


class TestInspect(unittest.TestCase):
    def test_header_fields(self):
        blob = encrypt(b"x", password="p", suite="dual", aad=b"meta", **FAST)
        info = inspect(blob)
        self.assertEqual(info["suite"], "dual")
        self.assertEqual(info["mode"], "password")
        self.assertEqual(info["profile"], "fast")
        self.assertEqual(info["aad"], "meta")
        self.assertEqual(len(info["salt"]), 64)
        self.assertEqual(info["version"], 1)

    def test_inspect_armored_text(self):
        armored = triglyph.encrypt_text("中文消息", password="p", **FAST)
        self.assertEqual(inspect(armored)["suite"], "triple")

    def test_inspect_reveals_no_plaintext(self):
        secret = "совершенно секретно"
        info = inspect(encrypt(secret.encode(), password="p", **FAST))
        self.assertNotIn(secret, str(info))


if __name__ == "__main__":
    unittest.main(verbosity=2)
