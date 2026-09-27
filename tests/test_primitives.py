"""Тест-векторы примитивов: RFC 8439, FIPS-197, NIST GCM, RFC 5869, RFC 7748."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triglyph import selftest as V  # noqa: E402
from triglyph._util import IntegrityError, xor_bytes  # noqa: E402
from triglyph.aes import AES, aes_ctr_xor, aes_gcm_decrypt, aes_gcm_encrypt  # noqa: E402
from triglyph.chacha import (  # noqa: E402
    chacha20_block,
    chacha20_xor,
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
    hchacha20,
    poly1305_mac,
    xchacha20_xor,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)
from triglyph.kdf import KeySchedule, derive_master_secret, hkdf, normalize_password, PROFILES  # noqa: E402
from triglyph.threefish import Threefish1024, threefish1024_ctr_xor  # noqa: E402
from triglyph.x25519 import key_exchange, public_key, x25519  # noqa: E402


class TestChaCha(unittest.TestCase):
    def test_block_rfc8439(self):
        v = V.KAT_CHACHA20_BLOCK
        self.assertEqual(chacha20_block(v["key"], v["counter"], v["nonce"]), v["out"])

    def test_encrypt_rfc8439(self):
        v = V.KAT_CHACHA20_ENCRYPT
        ct = chacha20_xor(v["key"], v["counter"], v["nonce"], v["plaintext"])
        self.assertEqual(ct, v["ciphertext"])
        self.assertEqual(chacha20_xor(v["key"], v["counter"], v["nonce"], ct), v["plaintext"])

    def test_poly1305_rfc8439(self):
        v = V.KAT_POLY1305
        self.assertEqual(poly1305_mac(v["msg"], v["key"]), v["tag"])

    def test_aead_rfc8439(self):
        v = V.KAT_CHACHA20POLY1305
        out = chacha20poly1305_encrypt(v["key"], v["nonce"], v["plaintext"], v["aad"])
        self.assertEqual(out, v["ciphertext"] + v["tag"])
        self.assertEqual(
            chacha20poly1305_decrypt(v["key"], v["nonce"], out, v["aad"]), v["plaintext"]
        )

    def test_aead_rejects_tamper(self):
        v = V.KAT_CHACHA20POLY1305
        out = bytearray(chacha20poly1305_encrypt(v["key"], v["nonce"], b"abc", b""))
        out[1] ^= 0x40
        with self.assertRaises(IntegrityError):
            chacha20poly1305_decrypt(v["key"], v["nonce"], bytes(out), b"")

    def test_aead_rejects_wrong_aad(self):
        key, nonce = os.urandom(32), os.urandom(12)
        ct = chacha20poly1305_encrypt(key, nonce, b"msg", b"aad-1")
        with self.assertRaises(IntegrityError):
            chacha20poly1305_decrypt(key, nonce, ct, b"aad-2")

    def test_hchacha20(self):
        v = V.KAT_HCHACHA20
        self.assertEqual(hchacha20(v["key"], v["nonce"]), v["out"])

    def test_xchacha_roundtrip_all_sizes(self):
        key = os.urandom(32)
        for n in (0, 1, 63, 64, 65, 1000):
            nonce = os.urandom(24)
            data = os.urandom(n)
            ct = xchacha20poly1305_encrypt(key, nonce, data, b"a")
            self.assertEqual(xchacha20poly1305_decrypt(key, nonce, ct, b"a"), data)
            self.assertEqual(xchacha20_xor(key, 1, nonce, xchacha20_xor(key, 1, nonce, data)), data)

    def test_keystream_is_key_dependent(self):
        a = chacha20_xor(b"\x00" * 32, 0, b"\x00" * 12, b"\x00" * 64)
        b = chacha20_xor(b"\x01" + b"\x00" * 31, 0, b"\x00" * 12, b"\x00" * 64)
        self.assertNotEqual(a, b)


class TestAES(unittest.TestCase):
    def test_fips197_blocks(self):
        for key, pt, ct in V.KAT_AES_ECB:
            self.assertEqual(AES(key).encrypt_block(pt), ct)
            self.assertEqual(AES(key).decrypt_block(ct), pt)

    def test_gcm_vectors(self):
        for g in V.KAT_AES_GCM:
            self.assertEqual(
                aes_gcm_encrypt(g["key"], g["iv"], g["pt"], g["aad"]), g["ct"] + g["tag"]
            )

    def test_gcm_roundtrip_and_tamper(self):
        key = os.urandom(32)
        for n in (0, 1, 15, 16, 17, 4096):
            iv, data, aad = os.urandom(12), os.urandom(n), os.urandom(n % 7)
            ct = aes_gcm_encrypt(key, iv, data, aad)
            self.assertEqual(aes_gcm_decrypt(key, iv, ct, aad), data)
            if n:
                bad = bytearray(ct)
                bad[0] ^= 1
                with self.assertRaises(IntegrityError):
                    aes_gcm_decrypt(key, iv, bytes(bad), aad)

    def test_gcm_long_iv(self):
        key, iv = os.urandom(32), os.urandom(29)
        ct = aes_gcm_encrypt(key, iv, b"non-96-bit IV path")
        self.assertEqual(aes_gcm_decrypt(key, iv, ct), b"non-96-bit IV path")

    def test_ctr_is_involution(self):
        key, ctr, data = os.urandom(32), os.urandom(16), os.urandom(333)
        self.assertEqual(aes_ctr_xor(key, ctr, aes_ctr_xor(key, ctr, data)), data)

    def test_key_sizes_rejected(self):
        with self.assertRaises(ValueError):
            AES(b"short")


class TestThreefish(unittest.TestCase):
    def test_inverse(self):
        for _ in range(4):
            key, tweak, blk = os.urandom(128), os.urandom(16), os.urandom(128)
            tf = Threefish1024(key, tweak)
            self.assertEqual(tf.decrypt_block(tf.encrypt_block(blk)), blk)

    def test_avalanche(self):
        key, tweak, blk = os.urandom(128), os.urandom(16), os.urandom(128)
        tf = Threefish1024(key, tweak)
        base = tf.encrypt_block(blk)
        for bit in (0, 37, 511, 1023):
            flip = bytearray(blk)
            flip[bit // 8] ^= 1 << (bit % 8)
            diff = sum(bin(a ^ b).count("1") for a, b in zip(base, tf.encrypt_block(bytes(flip))))
            self.assertGreater(diff, 380)
            self.assertLess(diff, 644)

    def test_tweak_matters(self):
        key, blk = os.urandom(128), os.urandom(128)
        a = Threefish1024(key, b"\x00" * 16).encrypt_block(blk)
        b = Threefish1024(key, b"\x01" + b"\x00" * 15).encrypt_block(blk)
        self.assertNotEqual(a, b)

    def test_ctr_roundtrip(self):
        key, nonce = os.urandom(128), os.urandom(16)
        for n in (0, 1, 127, 128, 129, 5000):
            data = os.urandom(n)
            enc = threefish1024_ctr_xor(key, nonce, data)
            self.assertEqual(len(enc), n)
            self.assertEqual(threefish1024_ctr_xor(key, nonce, enc), data)


class TestKDF(unittest.TestCase):
    def test_hkdf_rfc5869(self):
        for g in V.KAT_HKDF:
            self.assertEqual(hkdf(g["ikm"], g["salt"], g["info"], g["len"], "sha256"), g["okm"])

    def test_password_normalisation(self):
        self.assertEqual(normalize_password("ｐａｓｓ"), normalize_password("pass"))
        self.assertEqual(normalize_password("пароль"), "пароль".encode())
        self.assertNotEqual(normalize_password("пароль"), normalize_password("пaроль"))  # 'a' латинская

    def test_master_secret_is_deterministic_and_salt_bound(self):
        prof = PROFILES["fast"]
        salt = os.urandom(32)
        a = derive_master_secret("пароль密码", salt, prof)
        b = derive_master_secret("пароль密码", salt, prof)
        c = derive_master_secret("пароль密码", os.urandom(32), prof)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 64)

    def test_pepper_changes_result(self):
        prof, salt = PROFILES["fast"], os.urandom(32)
        a = derive_master_secret("pw", salt, prof)
        b = derive_master_secret("pw", salt, prof, pepper=b"keyfile")
        self.assertNotEqual(a, b)

    def test_subkeys_are_independent(self):
        ks = KeySchedule(os.urandom(64), b"ctx")
        keys = [ks["l1"], ks["l2"], ks["l3"][:32], ks["mac"][:32], ks["nonce"]]
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(len(ks["l3"]), 128)
        self.assertEqual(len(ks["mac"]), 64)

    def test_context_separation(self):
        master = os.urandom(64)
        self.assertNotEqual(KeySchedule(master, b"a")["l1"], KeySchedule(master, b"b")["l1"])

    def test_nonces_unique_per_index(self):
        ks = KeySchedule(os.urandom(64))
        nonces = {ks.nonce_for(b"L1", i, 24) for i in range(200)}
        self.assertEqual(len(nonces), 200)

    def test_destroy(self):
        ks = KeySchedule(os.urandom(64))
        ks.destroy()
        with self.assertRaises(Exception):
            ks["l1"]


class TestX25519(unittest.TestCase):
    def test_rfc7748_vectors(self):
        for sk, u, expected in V.KAT_X25519:
            self.assertEqual(x25519(sk, u), expected)

    def test_rfc7748_diffie_hellman(self):
        d = V.KAT_X25519_DH
        self.assertEqual(public_key(d["alice_sk"]), d["alice_pk"])
        self.assertEqual(public_key(d["bob_sk"]), d["bob_pk"])
        self.assertEqual(key_exchange(d["alice_sk"], d["bob_pk"]), d["shared"])
        self.assertEqual(key_exchange(d["bob_sk"], d["alice_pk"]), d["shared"])

    def test_low_order_point_rejected(self):
        with self.assertRaises(Exception):
            key_exchange(os.urandom(32), b"\x00" * 32)


class TestUtil(unittest.TestCase):
    def test_xor(self):
        self.assertEqual(xor_bytes(b"\xff\x00", b"\x0f\x0f"), b"\xf0\x0f")
        self.assertEqual(xor_bytes(b"", b"abc"), b"")
        data, mask = os.urandom(1000), os.urandom(1000)
        self.assertEqual(xor_bytes(xor_bytes(data, mask), mask), data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
