# TRIGLYPH · ТРИГЛИФ · 三纹密码

**A cascade cipher built for Chinese, Russian and English text.**
Pure Python, zero dependencies, every primitive checked against official test vectors.

[🇷🇺 Русский](README.md) · 🇬🇧 English · [🇨🇳 中文](README.zh.md) · [Format spec](docs/SPEC.md) · [Threat model](docs/THREAT_MODEL.md)

```
                 plaintext
                     │
   ①  XChaCha20-Poly1305 │  256-bit key, 192-bit nonce, 128-bit tag
                     ▼
   ②  AES-256-GCM        │  independent 256-bit key, 128-bit tag
                     ▼
   ③  Threefish-1024-CTR │  independent 1024-bit key, 80 rounds
                     ▼
   ④  HMAC-SHA3-512      │  authenticates the whole container
                     ▼
                ciphertext
```

Every layer has an independent key derived by HKDF-SHA512 with domain
separation. Recovering the plaintext requires breaking **all three ciphers at
once**: a total break of any single algorithm still leaves the message sealed.

---

## Why not just AES

General-purpose libraries encrypt *bytes*. Multilingual text leaks through
channels a byte cipher never looks at:

| Leak | What the adversary learns | What TRIGLYPH does |
|---|---|---|
| **Length** | A Han character is 3 UTF-8 bytes, Cyrillic 2, Latin 1 — the ciphertext length announces the language | Padmé padding plus language buckets: `黎明时分进攻`, `Атака на рассвете` and `Attack at dawn` all produce the **same** container size |
| **Normalisation** | `й` is either U+0439 or U+0438+U+0306; Chinese IMEs emit full-width Latin. Same password, different key | NFC for text, NFKC for passwords — applied before any crypto |
| **Transport** | Base64 always looks like Base64 | Armor in Han characters (12 bits/char), Cyrillic (5 bits/letter) or Latin |
| **Signature** | Magic bytes make containers greppable | Stealth wrapper: output is statistically indistinguishable from noise |
| **Password cracking** | Non-Latin passwords lose entropy without normalisation | Three-stage KDF: SHA3-512 → scrypt (memory) → PBKDF2-SHA512 (time) |

---

## Quick start

Python 3.9+, nothing to install.

```bash
git clone https://github.com/kirilsfriends-glitch/FlappyBird-Android.git
cd FlappyBird-Android
python3 -m triglyph --lang en selftest -v     # 32 checks against official vectors
```

```bash
# text in, armored text out — armor follows the detected language
$ python3 -m triglyph --lang en enc -m "Attack at dawn" -p secret
VFJHTFlQSAEBAQEBAAIAAQABAAAAAAAg...

$ python3 -m triglyph enc -m "黎明时分发起进攻" -p 密码
㊁卅假勅坐劀企丐企一倀丐丁一一一丠剏孧坤埢坿修哚圯厀凹寥妎嫊争噉咬仭伙咓借嬫夀…

# files of any size, streamed with constant memory
$ python3 -m triglyph encf report.pdf report.tgl -p secret --profile hard
$ python3 -m triglyph decf report.tgl report.pdf -p secret

# public-key mode with sender authentication
$ python3 -m triglyph keygen -o alice
$ python3 -m triglyph enc -m "hi" --to alice.pub --sign bob.key -o msg.tgl
$ python3 -m triglyph dec -i msg.tgl --identity alice.key --expect-sender bob.pub

# split a key into 5 shares, any 3 restore it
$ python3 -m triglyph split -k 3 -n 5 --secret "master key" --armor hanzi

# read the header of a container without knowing the password
$ python3 -m triglyph inspect -i report.tgl --json
```

The whole CLI is translated: `--lang en`, `--lang ru`, `--lang zh`.

```python
import triglyph

armored = triglyph.encrypt_text("Attack at dawn 黎明时分进攻", password="secret")
print(triglyph.decrypt_text(armored, password="secret"))

blob = triglyph.encrypt(data, password="secret", suite="triple",
                        profile="hard", aad=b"invoice 42", stealth=True)
data = triglyph.decrypt(blob, password="secret", aad=b"invoice 42")

priv, pub = triglyph.generate_keypair()
box = triglyph.encrypt(b"for the recipient", recipient=pub)
assert triglyph.decrypt(box, private_key=priv) == b"for the recipient"
```

Web demo (trilingual UI, runs the full self-test in the browser):

```bash
python3 web/server.py     # http://localhost:8000
```

---

## What is inside

| Component | Implementation | Verified against |
|---|---|---|
| Stream cipher | ChaCha20, HChaCha20, **XChaCha20** | RFC 8439 §2.3.2, §2.4.2; draft-irtf-cfrg-xchacha §2.2.1 |
| Authenticator | Poly1305 | RFC 8439 §2.5.2 |
| AEAD | ChaCha20-Poly1305, XChaCha20-Poly1305 | RFC 8439 §2.8.2 |
| Block cipher | AES-128/192/256 (S-box derived from GF(2⁸), never hard-coded) | FIPS-197 Appendix C.1–C.3 |
| AEAD mode | AES-GCM (GHASH with 4-bit window tables) | McGrew & Viega test cases 13–14 |
| Third layer | Threefish-1024-CTR, 80 rounds | invertibility, avalanche, tweak sensitivity |
| Key derivation | HKDF-SHA512 | RFC 5869 TC1, TC3 |
| Password KDF | SHA3-512 → scrypt → PBKDF2-SHA512 | determinism, salt and pepper binding |
| Asymmetric | X25519 (Montgomery ladder) | RFC 7748 §5.2, §6.1 |
| Secret sharing | Shamir over GF(2⁸) | all K-of-N combinations, refusal at K−1 |
| Key commitment | SHA3-256 over a dedicated subkey | container cannot open under a second key |

An optional accelerator uses `cryptography` (OpenSSL, AES-NI) for layers ① and
② — but only after it matches the built-in reference byte-for-byte on random
vectors at import time. The container format never depends on the backend.

---

## Security properties

* **Confidentiality** — three independently keyed ciphers in cascade.
* **Integrity** — Poly1305, GCM tag and HMAC-SHA3-512; reordering, replay,
  truncation and header downgrades are all detected.
* **Key commitment** — no second key can open a container.
* **Nonce safety** — nonces derive from a fresh 32-byte random salt per message.
* **Metadata** — length (hence language) hidden; recipient hidden by default;
  the format signature can be hidden too.

Honest limitations: no independent audit; not constant-time with respect to CPU
caches; stealth is obfuscation, not encryption; X25519 is not post-quantum;
Python cannot guarantee key erasure. Details in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Performance

Measured on 2 cores in a container, pure Python, no accelerator:

| Suite | Layers | Encrypt | Decrypt |
|---|---|---|---|
| `solo` | XChaCha20-Poly1305 + HMAC | 1.06 MB/s | 1.10 MB/s |
| `dual` | + AES-256-GCM | 0.47 MB/s | 0.46 MB/s |
| `triple` | + Threefish-1024 | 0.21 MB/s | 0.20 MB/s |

| KDF profile | Memory | Time |
|---|---|---|
| `fast` | 8 MiB | 39 ms |
| `balanced` | 64 MiB | 365 ms |
| `hard` | 256 MiB | 1.4 s |
| `paranoid` | 1 GiB | 7.5 s |

For messages the KDF dominates, not the cipher. For multi-gigabyte files use
`--suite dual` or `solo`, or install `cryptography`.

## Reference vectors

`docs/test-vectors.json` holds 60 ready-made containers with their keys and
expected plaintexts. They are pinned in the repository: `tests/test_vectors_file.py`
fails whenever a change breaks format compatibility, and an implementation in
another language can validate itself against the same file.

```bash
python3 tools/verify_vectors.py -v
```

## Tests

```bash
python3 -m unittest discover -s tests -v    # 116 tests
python3 -m triglyph selftest -v             # 32 official-vector checks
python3 -m triglyph bench                   # throughput on your machine
```

The suite verifies what must *fail*, too: every byte of a container flipped,
truncation, appending, chunk reordering, suite downgrade, wrong sender, a lost
armor character, K−1 secret shares.

## License

MIT — see [LICENSE](LICENSE).

> **Warning.** This is an independent cryptographic implementation that has not
> been audited. It builds on standard, publicly analysed algorithms and matches
> official test vectors, but if lives depend on it, use audited tools
> (age, GnuPG, libsodium).
