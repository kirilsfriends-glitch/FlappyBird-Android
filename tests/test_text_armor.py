"""Броня, работа с текстом трёх языков и схема Шамира."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triglyph import armor, shamir  # noqa: E402
from triglyph._util import CryptoError, FormatError  # noqa: E402
from triglyph.text import (  # noqa: E402
    PAD_BUCKET,
    PAD_FIXED,
    PAD_NONE,
    PAD_PADME,
    analyze_script,
    detect_language,
    normalize_text,
    pad_plaintext,
    padme,
    unpad_plaintext,
)


class TestArmor(unittest.TestCase):
    KINDS = ("hanzi", "cyrillic", "latin", "grouped")

    def test_roundtrip_exhaustive_small(self):
        for kind in self.KINDS:
            for n in range(0, 96):
                data = os.urandom(n)
                self.assertEqual(armor.decode(armor.encode(data, kind), kind), data, f"{kind}/{n}")

    def test_roundtrip_large(self):
        for kind in self.KINDS:
            data = os.urandom(10_000)
            self.assertEqual(armor.decode(armor.encode(data, kind), kind), data)

    def test_autodetect(self):
        for kind in self.KINDS:
            data = os.urandom(64)
            self.assertEqual(armor.detect(armor.encode(data, kind)), kind)
            self.assertEqual(armor.decode(armor.encode(data, kind)), data)

    def test_hanzi_alphabet_is_cjk(self):
        s = armor.encode(os.urandom(300), "hanzi")
        for ch in s[1:]:
            self.assertTrue(0x4E00 <= ord(ch) <= 0x5DFF, f"U+{ord(ch):04X} вне алфавита")

    def test_hanzi_density(self):
        """12 бит на знак — плотнее base64 (6 бит на знак)."""
        data = os.urandom(300)
        self.assertLess(len(armor.encode(data, "hanzi")), len(armor.encode(data, "latin")))

    def test_cyrillic_alphabet(self):
        s = armor.encode(os.urandom(300), "cyrillic")
        self.assertTrue(all("а" <= ch <= "я" for ch in s), s[:20])

    def test_cyrillic_is_case_and_yo_tolerant(self):
        data = os.urandom(50)
        s = armor.encode(data, "cyrillic")
        self.assertEqual(armor.decode(s.upper(), "cyrillic"), data)

    def test_checksum_catches_typo(self):
        data = os.urandom(64)
        s = armor.encode(data, "cyrillic")
        broken = s[:5] + ("б" if s[5] != "б" else "в") + s[6:]
        with self.assertRaises(FormatError):
            armor.decode(broken, "cyrillic")

    def test_checksum_catches_lost_character(self):
        data = os.urandom(64)
        s = armor.encode(data, "hanzi")
        with self.assertRaises(FormatError):
            armor.decode(s[:10] + s[11:], "hanzi")

    def test_foreign_characters_rejected(self):
        with self.assertRaises(FormatError):
            armor.decode("абвг?где", "cyrillic")

    def test_whitespace_and_wrapping_tolerated(self):
        data = os.urandom(200)
        wrapped = armor.encode(data, "hanzi", width=20)
        self.assertIn("\n", wrapped)
        self.assertEqual(armor.decode(wrapped, "hanzi"), data)

    def test_autodetect_is_unambiguous_fuzz(self):
        """Алфавиты Base32 и Base64 пересекаются — проверяем, что это не ломает разбор."""
        for n in range(1, 60):
            for kind in self.KINDS:
                data = os.urandom(n)
                s = armor.encode(data, kind)
                self.assertEqual(armor.decode(s), data, f"{kind}/{n}: {s[:24]}")

    def test_envelope_headers(self):
        data = os.urandom(32)
        msg = armor.wrap_message(armor.encode(data, "latin"), [("Suite", "triple")])
        payload, headers = armor.unwrap_message(msg)
        self.assertEqual(headers["Suite"], "triple")
        self.assertEqual(armor.decode(payload), data)

    def test_envelope_ignores_surrounding_noise(self):
        data = os.urandom(32)
        msg = "привет!\n" + armor.wrap_message(armor.encode(data, "latin")) + "\n-- подпись"
        payload, _ = armor.unwrap_message(msg)
        self.assertEqual(armor.decode(payload), data)


class TestTextAnalysis(unittest.TestCase):
    def test_detect_language(self):
        self.assertEqual(detect_language("黎明时分发起进攻，联络点已暴露。"), "zh")
        self.assertEqual(detect_language("Атака начнётся на рассвете"), "ru")
        self.assertEqual(detect_language("Attack begins at dawn"), "en")
        self.assertEqual(detect_language("1234 !!! ???"), "unknown")

    def test_mixed_language(self):
        self.assertEqual(detect_language("Привет hello 你好 world мир 世界 test"), "mixed")

    def test_script_stats(self):
        st = analyze_script("Аа Bb 汉字 12")
        self.assertEqual(st.cyrillic, 2)
        self.assertEqual(st.latin, 2)
        self.assertEqual(st.han, 2)
        self.assertEqual(st.digits, 2)

    def test_normalisation(self):
        self.assertEqual(normalize_text("\u0438\u0306"), "\u0439")
        self.assertEqual(len(normalize_text("\u0438\u0306")), 1)

    def test_padme_bounds(self):
        for n in range(1, 20000, 13):
            p = padme(n)
            self.assertGreaterEqual(p, n)
            self.assertLessEqual(p, n * 1.12 + 2)

    def test_padding_roundtrip(self):
        for policy, extra in ((PAD_NONE, 0), (PAD_PADME, 0), (PAD_BUCKET, 0), (PAD_FIXED, 64)):
            for n in (0, 1, 100, 1000):
                data = os.urandom(n)
                padded = pad_plaintext(data, policy, extra)
                self.assertEqual(unpad_plaintext(padded), data)

    def test_bucket_equalises(self):
        a = pad_plaintext(b"x" * 10, PAD_BUCKET)
        b = pad_plaintext(b"x" * 200, PAD_BUCKET)
        self.assertEqual(len(a), len(b))

    def test_unpad_rejects_garbage(self):
        with self.assertRaises(FormatError):
            unpad_plaintext(b"\xff" * 16)


class TestShamir(unittest.TestCase):
    def test_threshold_combinations(self):
        secret = os.urandom(32)
        parts = shamir.split_secret(secret, 3, 5)
        self.assertEqual(len(parts), 5)
        import itertools

        for combo in itertools.combinations(parts, 3):
            self.assertEqual(shamir.combine_shares(list(combo)), secret)

    def test_below_threshold_fails(self):
        secret = os.urandom(32)
        parts = shamir.split_secret(secret, 3, 5)
        for combo in ((parts[0],), (parts[0], parts[1])):
            with self.assertRaises(CryptoError):
                shamir.combine_shares(list(combo))

    def test_armored_shares_all_scripts(self):
        secret = b"\xde\xad\xbe\xef" * 8
        parts = shamir.split_secret(secret, 2, 3)
        for kind in ("hanzi", "cyrillic", "latin", "grouped"):
            texts = [p.armored(kind) for p in parts[:2]]
            self.assertEqual(shamir.combine_shares(texts), secret)

    def test_corrupted_share_detected(self):
        parts = shamir.split_secret(os.urandom(16), 2, 3)
        raw = bytearray(parts[0].to_bytes())
        raw[6] ^= 0xFF
        with self.assertRaises(FormatError):
            shamir.Share.parse(bytes(raw))

    def test_mixed_secrets_detected(self):
        a = shamir.split_secret(os.urandom(16), 2, 3)
        b = shamir.split_secret(os.urandom(16), 2, 3)
        with self.assertRaises(CryptoError):
            shamir.combine_shares([a[0], b[1]])

    def test_duplicate_shares_rejected(self):
        parts = shamir.split_secret(os.urandom(16), 2, 3)
        with self.assertRaises(CryptoError):
            shamir.combine_shares([parts[0], parts[0]])

    def test_long_secret(self):
        secret = os.urandom(1024)
        parts = shamir.split_secret(secret, 4, 7)
        self.assertEqual(shamir.combine_shares(parts[2:6]), secret)

    def test_text_secret_in_three_languages(self):
        secret = "ключ 密钥 key".encode()
        parts = shamir.split_secret(secret, 2, 2)
        self.assertEqual(shamir.combine_shares(parts).decode(), "ключ 密钥 key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
