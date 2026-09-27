"""Проверки интерфейса командной строки (запуск настоящего процесса)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args, stdin: bytes = b"", check: bool = True):
    env = dict(os.environ, PYTHONPATH=ROOT, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "triglyph", *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=tempfile.gettempdir(),
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command failed: {args}\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
        )
    return proc


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def test_help_in_three_languages(self):
        for lang, needle in (("ru", "шифр"), ("en", "cascade cipher"), ("zh", "级联密码")):
            out = run("--lang", lang, "--help").stdout.decode()
            self.assertIn(needle, out)

    def test_version(self):
        self.assertIn("TRIGLYPH", run("--version").stdout.decode())

    def test_text_roundtrip_three_languages(self):
        for msg in ("Атака на рассвете", "黎明时分进攻", "Attack at dawn"):
            armored = run("enc", "-m", msg, "-p", "pw", "--profile", "fast").stdout.decode().strip()
            back = run("dec", "-i", "-", "-p", "pw", stdin=armored.encode()).stdout.decode().strip()
            self.assertEqual(back, msg)

    def test_armor_selection_by_language(self):
        zh = run("enc", "-m", "黎明时分进攻", "-p", "pw", "--profile", "fast").stdout.decode()
        ru = run("enc", "-m", "Атака на рассвете", "-p", "pw", "--profile", "fast").stdout.decode()
        en = run("enc", "-m", "Attack at dawn", "-p", "pw", "--profile", "fast").stdout.decode()
        self.assertTrue(0x4E00 <= ord(zh.strip()[1]) <= 0x5DFF)
        self.assertTrue("а" <= ru.strip()[0] <= "я")
        self.assertTrue(en.strip()[0].isascii())

    def test_wrong_password_exit_code_2(self):
        armored = run("enc", "-m", "секрет", "-p", "pw", "--profile", "fast").stdout
        proc = run("dec", "-i", "-", "-p", "nope", stdin=armored, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(b"\xd1\x81\xd0\xb5\xd0\xba\xd1\x80\xd0\xb5\xd1\x82", proc.stdout)

    def test_file_roundtrip(self):
        src, enc, dec = self.path("a.bin"), self.path("a.tgl"), self.path("a.out")
        data = os.urandom(120_000)
        with open(src, "wb") as fh:
            fh.write(data)
        run("encf", src, enc, "-p", "pw", "--profile", "fast", "--suite", "solo")
        run("decf", enc, dec, "-p", "pw")
        with open(dec, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_corrupted_file_leaves_no_output(self):
        src, enc, dec = self.path("b.bin"), self.path("b.tgl"), self.path("b.out")
        with open(src, "wb") as fh:
            fh.write(os.urandom(70_000))
        run("encf", src, enc, "-p", "pw", "--profile", "fast", "--suite", "solo")
        with open(enc, "r+b") as fh:
            fh.seek(3000)
            fh.write(b"\xff")
        proc = run("decf", enc, dec, "-p", "pw", check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(os.path.exists(dec))

    def test_keygen_and_public_key_mode(self):
        prefix = self.path("alice")
        run("keygen", "-o", prefix)
        self.assertTrue(os.path.exists(prefix + ".key"))
        self.assertTrue(os.path.exists(prefix + ".pub"))
        self.assertEqual(oct(os.stat(prefix + ".key").st_mode)[-3:], "600")
        armored = run("enc", "-m", "для Алисы", "--to", prefix + ".pub", "--armor", "latin").stdout
        out = run("dec", "-i", "-", "--identity", prefix + ".key", stdin=armored).stdout
        self.assertEqual(out.decode().strip(), "для Алисы")

    def test_authenticated_sender(self):
        a, b = self.path("a"), self.path("b")
        run("keygen", "-o", a)
        run("keygen", "-o", b)
        armored = run("enc", "-m", "подписано", "--to", a + ".pub", "--sign", b + ".key",
                      "--armor", "latin").stdout
        ok = run("dec", "-i", "-", "--identity", a + ".key", "--expect-sender", b + ".pub",
                 stdin=armored).stdout
        self.assertEqual(ok.decode().strip(), "подписано")
        bad = run("dec", "-i", "-", "--identity", a + ".key", "--expect-sender", a + ".pub",
                  stdin=armored, check=False)
        self.assertEqual(bad.returncode, 2)

    def test_inspect_json(self):
        armored = run("enc", "-m", "x", "-p", "pw", "--profile", "fast", "--suite", "dual").stdout
        info = json.loads(run("inspect", "-i", "-", "--json", stdin=armored).stdout.decode())
        self.assertEqual(info["suite"], "dual")
        self.assertEqual(info["mode"], "password")

    def test_shamir_cli(self):
        out = run("split", "-k", "2", "-n", "3", "--secret", "мой ключ", "--armor", "hanzi").stdout
        lines = [ln for ln in out.decode().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        back = run("combine", lines[0], lines[2]).stdout.decode().strip()
        self.assertEqual(back, "мой ключ")

    def test_armor_command(self):
        enc = run("armor", "encode", "-m", "привет 你好", "--kind", "hanzi").stdout.decode().strip()
        dec = run("armor", "decode", "-i", "-", stdin=enc.encode()).stdout.decode()
        self.assertEqual(dec, "привет 你好")

    def test_passgen_entropy(self):
        for style in ("hanzi", "cyrillic", "latin", "mixed"):
            proc = run("passgen", "--style", style, "--bits", "128")
            self.assertTrue(proc.stdout.decode().strip())
            bits = int("".join(c for c in proc.stderr.decode() if c.isdigit()))
            self.assertGreaterEqual(bits, 128, f"{style}: {bits} бит")

    def test_stealth_file_has_no_magic(self):
        out = self.path("st.bin")
        run("enc", "-m", "невидимо", "-p", "pw", "--profile", "fast", "--stealth",
            "--armor", "raw", "-o", out)
        with open(out, "rb") as fh:
            self.assertFalse(fh.read(8).startswith(b"TRGLYPH"))
        back = run("dec", "-i", out, "-p", "pw").stdout.decode().strip()
        self.assertEqual(back, "невидимо")

    def test_refuses_to_overwrite(self):
        target = self.path("exists.tgl")
        with open(target, "w") as fh:
            fh.write("keep me")
        proc = run("enc", "-m", "x", "-p", "pw", "--profile", "fast", "-o", target, check=False)
        self.assertNotEqual(proc.returncode, 0)
        with open(target) as fh:
            self.assertEqual(fh.read(), "keep me")

    def test_pipe_workflow(self):
        """echo | triglyph enc | triglyph dec — как в настоящем скрипте."""
        enc = run("enc", "-i", "-", "-p", "pw", "--profile", "fast", stdin="секрет 秘密".encode())
        dec = run("dec", "-i", "-", "-p", "pw", stdin=enc.stdout)
        self.assertEqual(dec.stdout.decode().strip(), "секрет 秘密")

    def test_selftest_command(self):
        out = run("selftest").stdout.decode()
        self.assertIn("32/32", out.replace("\n", " ") if "32/32" in out else out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
