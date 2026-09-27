package ai.triglyph.core;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Самопроверка: прогоняет плоский файл эталонных векторов (docs/test-vectors.txt),
 * созданный Python-версией TRIGLYPH, и сверяет каждый байт.
 *
 * <p>Тот же класс используется и в приложении (кнопка «Самопроверка»), и в CI
 * как обычная программа с {@code main()}.
 */
public final class SelfCheck {

    /** Результат прогона. */
    public static final class Report {
        public int passed;
        public int failed;
        public final List<String> failures = new ArrayList<String>();
        public final List<String> groups = new ArrayList<String>();
        public long millis;

        public boolean ok() {
            return failed == 0 && passed > 0;
        }

        public String summary() {
            return (ok() ? "OK" : "FAIL") + ": " + passed + " passed, " + failed + " failed, "
                    + millis + " ms";
        }
    }

    private final Report report = new Report();
    private String group = "";
    private int groupPassed;
    private int groupFailed;

    private SelfCheck() {
    }

    private void check(boolean cond, String what) {
        if (cond) {
            report.passed++;
            groupPassed++;
        } else {
            report.failed++;
            groupFailed++;
            if (report.failures.size() < 40) {
                report.failures.add(what);
            }
        }
    }

    private void checkHex(byte[] got, String wantHex, String what) {
        String gotHex = Util.hex(got);
        boolean ok = gotHex.equals(wantHex);
        check(ok, ok ? what : what + "\n    want " + shorten(wantHex) + "\n    got  " + shorten(gotHex));
    }

    private static String shorten(String s) {
        return s.length() <= 96 ? s : s.substring(0, 93) + "...";
    }

    private void startGroup(String name) {
        flushGroup();
        group = name;
        groupPassed = 0;
        groupFailed = 0;
    }

    private void flushGroup() {
        if (group.length() > 0 && (groupPassed + groupFailed) > 0) {
            report.groups.add(group + ": " + groupPassed + "/" + (groupPassed + groupFailed));
        }
    }

    // --------------------------------------------------------------- проверки

    /** Проверяет примитивы на встроенных векторах RFC (без файла). */
    private void builtinVectors() throws TriglyphException {
        startGroup("RFC vectors");
        // RFC 8439 §2.3.2 — блок ChaCha20
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = Util.unhex("000000090000004a00000000");
        checkHex(Chacha.block(key, 1, nonce),
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                        + "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
                "RFC 8439 §2.3.2 ChaCha20 block");
        // RFC 8439 §2.5.2 — Poly1305
        checkHex(Chacha.poly1305(Kdf.ascii("Cryptographic Forum Research Group"),
                        Util.unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")),
                "a8061dc1305136c6c22b8baf0c0127a9", "RFC 8439 §2.5.2 Poly1305");
        // draft-irtf-cfrg-xchacha §2.2.1 — HChaCha20
        checkHex(Chacha.hchacha20(
                        Util.unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                        Util.unhex("000000090000004a0000000031415927")),
                "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
                "XChaCha draft §2.2.1 HChaCha20");
        // RFC 7748 §6.1 — X25519 обмен
        byte[] alicePriv = Util.unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPub = Util.unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        checkHex(X25519.scalarMult(alicePriv, bobPub),
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                "RFC 7748 §6.1 X25519");
        // RFC 5869 TC1 — HKDF-SHA256 недоступен (у нас SHA-512), проверяем длину и стабильность
        byte[] okm = Kdf.hkdf(Kdf.ascii("ikm"), Kdf.ascii("salt"), Kdf.ascii("info"), 137);
        check(okm.length == 137, "HKDF-SHA512 output length");
        // SHA3 по NIST (пустая строка)
        checkHex(Keccak.sha3_256(new byte[0]),
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "SHA3-256(\"\")");
        checkHex(Keccak.sha3_512(new byte[0]),
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", "SHA3-512(\"\")");
    }

    /** Полный прогон по файлу векторов. */
    public static Report run(BufferedReader reader) throws IOException {
        SelfCheck sc = new SelfCheck();
        long t0 = System.currentTimeMillis();
        try {
            sc.builtinVectors();
            sc.selfConsistency();
            sc.startGroup("file vectors");
            String line;
            String lastType = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] f = line.split("\\|", -1);
                if (!f[0].equals(lastType)) {
                    sc.startGroup(typeName(f[0]));
                    lastType = f[0];
                }
                try {
                    sc.checkLine(f);
                } catch (TriglyphException exc) {
                    sc.check(false, f[0] + " raised " + exc);
                } catch (RuntimeException exc) {
                    sc.check(false, f[0] + " raised " + exc);
                }
            }
        } catch (TriglyphException exc) {
            sc.check(false, "self-check aborted: " + exc);
        }
        sc.flushGroup();
        sc.report.millis = System.currentTimeMillis() - t0;
        return sc.report;
    }

    private static String typeName(String t) {
        if (t.equals("H")) {
            return "hashes";
        }
        if (t.equals("C")) {
            return "chacha20";
        }
        if (t.equals("HC")) {
            return "hchacha20";
        }
        if (t.equals("M")) {
            return "poly1305";
        }
        if (t.equals("G")) {
            return "aes-gcm";
        }
        if (t.equals("T")) {
            return "threefish-1024";
        }
        if (t.equals("K")) {
            return "kdf";
        }
        if (t.equals("X")) {
            return "x25519";
        }
        if (t.equals("P")) {
            return "padme";
        }
        if (t.equals("A")) {
            return "armor";
        }
        if (t.equals("V")) {
            return "containers";
        }
        return t;
    }

    private void checkLine(String[] f) throws TriglyphException {
        String t = f[0];
        if (t.equals("H")) {
            String alg = f[1];
            if (alg.equals("sha3_256")) {
                checkHex(Keccak.sha3_256(Util.unhex(f[2])), f[3], "SHA3-256 len=" + f[2].length() / 2);
            } else if (alg.equals("sha3_512")) {
                checkHex(Keccak.sha3_512(Util.unhex(f[2])), f[3], "SHA3-512 len=" + f[2].length() / 2);
            } else if (alg.equals("shake_256_64")) {
                checkHex(Keccak.shake256(Util.unhex(f[2]), 64), f[3], "SHAKE256 len=" + f[2].length() / 2);
            } else if (alg.equals("hmac_sha3_512")) {
                checkHex(Keccak.hmacSha3_512(Util.unhex(f[1 + 1]), Util.unhex(f[3])), f[4],
                        "HMAC-SHA3-512 msg=" + f[3].length() / 2);
            } else {
                check(false, "unknown hash vector " + alg);
            }
        } else if (t.equals("C")) {
            checkHex(Chacha.xor(Util.unhex(f[1]), Integer.parseInt(f[2]), Util.unhex(f[3]), Util.unhex(f[4])),
                    f[5], "ChaCha20 len=" + f[4].length() / 2);
        } else if (t.equals("HC")) {
            checkHex(Chacha.hchacha20(Util.unhex(f[1]), Util.unhex(f[2])), f[3], "HChaCha20");
        } else if (t.equals("M")) {
            checkHex(Chacha.poly1305(Util.unhex(f[2]), Util.unhex(f[1])), f[3],
                    "Poly1305 len=" + f[2].length() / 2);
        } else if (t.equals("G")) {
            checkHex(Aes.gcmEncrypt(Util.unhex(f[1]), Util.unhex(f[2]), Util.unhex(f[4]), Util.unhex(f[3])),
                    f[5], "AES-256-GCM len=" + f[4].length() / 2);
            byte[] back = Aes.gcmDecrypt(Util.unhex(f[1]), Util.unhex(f[2]), Util.unhex(f[5]), Util.unhex(f[3]));
            checkHex(back, f[4], "AES-256-GCM decrypt");
        } else if (t.equals("T")) {
            Threefish tf = new Threefish(Util.unhex(f[1]), Util.unhex(f[2]));
            checkHex(tf.encryptBlock(Util.unhex(f[3])), f[4], "Threefish-1024 encrypt");
            checkHex(tf.decryptBlock(Util.unhex(f[4])), f[3], "Threefish-1024 decrypt");
        } else if (t.equals("K")) {
            String kind = f[1];
            if (kind.equals("hkdf_sha512")) {
                checkHex(Kdf.hkdf(Util.unhex(f[2]), Util.unhex(f[3]), Util.unhex(f[4]), Integer.parseInt(f[5])),
                        f[6], "HKDF-SHA512");
            } else if (kind.equals("pbkdf2_sha512")) {
                checkHex(Kdf.pbkdf2Sha512(Util.unhex(f[2]), Util.unhex(f[3]),
                        Integer.parseInt(f[4]), Integer.parseInt(f[5])), f[6], "PBKDF2-SHA512 x" + f[4]);
            } else if (kind.equals("scrypt")) {
                checkHex(Kdf.scrypt(Util.unhex(f[2]), Util.unhex(f[3]), Integer.parseInt(f[4]),
                                Integer.parseInt(f[5]), Integer.parseInt(f[6]), Integer.parseInt(f[7])),
                        f[8], "scrypt N=" + f[4] + " r=" + f[5] + " p=" + f[6]);
            } else if (kind.equals("master_fast")) {
                checkHex(Kdf.deriveMasterSecret(Util.unhex(f[2]), Util.unhex(f[3]),
                        Kdf.profile("fast"), Kdf.KDF_SCRYPT, new byte[0]), f[4], "master secret (fast)");
            } else {
                check(false, "unknown KDF vector " + kind);
            }
        } else if (t.equals("X")) {
            checkHex(X25519.scalarMult(Util.unhex(f[1]), Util.unhex(f[2])), f[3], "X25519 scalarmult");
        } else if (t.equals("P")) {
            boolean ok = true;
            for (String pair : f[2].split(",")) {
                String[] kv = pair.split(":");
                if (TextUtil.padme(Long.parseLong(kv[0])) != Long.parseLong(kv[1])) {
                    ok = false;
                }
            }
            check(ok, "padme table");
        } else if (t.equals("A")) {
            String kind = f[1];
            byte[] data = Util.unhex(f[2]);
            String want = f[3];
            String got = Armor.encode(data, kind);
            check(got.equals(want), "armor " + kind + " encode len=" + data.length
                    + (got.equals(want) ? "" : "\n    want " + want + "\n    got  " + got));
            checkHex(Armor.decode(want, kind), f[2], "armor " + kind + " decode");
            if (data.length > 2) {
                checkHex(Armor.decode(want), f[2], "armor " + kind + " autodetect");
            }
        } else if (t.equals("V")) {
            String name = f[1];
            String mode = f[2];
            Triglyph.KeyMaterial km = mode.equals("rawkey")
                    ? Triglyph.KeyMaterial.rawKey(Util.unhex(f[3]))
                    : Triglyph.KeyMaterial.passwordBytes(Util.unhex(f[4]));
            byte[] blob = Util.unhex(f[7]);
            byte[] want = Util.unhex(f[8]);
            byte[] got = Triglyph.decrypt(blob, km);
            check(Arrays.equals(got, want), "container " + name + " decrypt");
            // порча: любой перевёрнутый бит должен ломать расшифровку
            byte[] bad = blob.clone();
            bad[bad.length / 2] ^= 0x40;
            boolean rejected = false;
            try {
                Triglyph.decrypt(bad, km);
            } catch (TriglyphException exc) {
                rejected = true;
            } catch (RuntimeException exc) {
                rejected = true;
            }
            check(rejected, "container " + name + " rejects tampering");
        } else {
            check(false, "unknown vector type " + t);
        }
    }

    /** Кольцевые проверки: то, что нельзя взять из файла. */
    private void selfConsistency() throws TriglyphException {
        startGroup("round-trip");
        byte[] key = Util.random(32);
        String[] texts = {
                "Съешь ещё этих мягких французских булок, да выпей чаю.",
                "敏捷的棕色狐狸跳过了懒惰的狗，密码学保护每一个人。",
                "The quick brown fox jumps over the lazy dog. 0123456789",
                "",
                "Смешанный mixed 混合 текст 42",
        };
        String[] suites = {"solo", "dual", "triple"};
        for (String suite : suites) {
            for (String text : texts) {
                Triglyph.Options opt = new Triglyph.Options().suite(suite).profile("fast");
                byte[] blob = Triglyph.encrypt(Triglyph.utf8(text), Triglyph.KeyMaterial.rawKey(key), opt);
                String back = Triglyph.fromUtf8(Triglyph.decrypt(blob, Triglyph.KeyMaterial.rawKey(key)));
                check(back.equals(text), "round-trip " + suite + " len=" + text.length());
            }
        }
        // пароль
        Triglyph.Options fast = new Triglyph.Options().suite("triple").profile("fast");
        byte[] blob = Triglyph.encrypt(Triglyph.utf8("пароль 密码 password"),
                Triglyph.KeyMaterial.password("Пароль-密码-42"), fast);
        check(Triglyph.fromUtf8(Triglyph.decrypt(blob, Triglyph.KeyMaterial.password("Пароль-密码-42")))
                .equals("пароль 密码 password"), "password round-trip");
        boolean rejected = false;
        try {
            Triglyph.decrypt(blob, Triglyph.KeyMaterial.password("Пароль-密码-43"));
        } catch (TriglyphException exc) {
            rejected = true;
        }
        check(rejected, "wrong password rejected");

        // X25519 переписка
        byte[] bobPriv = X25519.generatePrivateKey();
        byte[] bobPub = X25519.basePointMult(bobPriv);
        byte[] alicePriv = X25519.generatePrivateKey();
        byte[] alicePub = X25519.basePointMult(alicePriv);
        byte[] sealed = Triglyph.encrypt(Triglyph.utf8("секрет для Боба 给鲍勃"),
                Triglyph.KeyMaterial.recipient(bobPub).signedBy(alicePriv), new Triglyph.Options());
        String opened = Triglyph.fromUtf8(Triglyph.decrypt(sealed,
                Triglyph.KeyMaterial.privateKey(bobPriv).expectSender(alicePub)));
        check(opened.equals("секрет для Боба 给鲍勃"), "X25519 authenticated round-trip");

        // стелс
        byte[] st = Triglyph.encrypt(Triglyph.utf8("stealth"), Triglyph.KeyMaterial.rawKey(key),
                new Triglyph.Options().suite("solo").stealth(true));
        check(!Util.ctEquals(Util.slice(st, 0, 8), Triglyph.MAGIC), "stealth hides magic");
        check(Triglyph.fromUtf8(Triglyph.decrypt(st, Triglyph.KeyMaterial.rawKey(key))).equals("stealth"),
                "stealth round-trip");

        // длина не выдаёт язык
        int[] lens = new int[3];
        String[] sameMeaning = {"Встретимся завтра в шесть у моста.",
                "明天六点在桥边见面。", "Let us meet tomorrow at six by the bridge."};
        for (int i = 0; i < 3; i++) {
            lens[i] = Triglyph.encrypt(Triglyph.utf8(sameMeaning[i]), Triglyph.KeyMaterial.rawKey(key),
                    new Triglyph.Options().pad(TextUtil.PAD_BUCKET).suite("triple")).length;
        }
        check(lens[0] == lens[1] && lens[1] == lens[2], "bucket padding equalises zh/ru/en length");

        // Шамир
        byte[] secret = Util.random(32);
        List<Shamir.Share> shares = Shamir.split(secret, 3, 5);
        List<Shamir.Share> subset = new ArrayList<Shamir.Share>();
        subset.add(Shamir.Share.parse(shares.get(4).armored("cyrillic")));
        subset.add(Shamir.Share.parse(shares.get(0).armored("hanzi")));
        subset.add(Shamir.Share.parse(shares.get(2).armored("latin")));
        check(Arrays.equals(Shamir.combine(subset), secret), "Shamir 3-of-5 across three armors");

        // текстовый режим с автоподбором брони
        startGroup("text mode");
        String[][] cases = {
                {"今天天气很好，我们去公园散步吧。", "hanzi"},
                {"Совершенно секретно: встреча в полночь.", "cyrillic"},
                {"Top secret: the meeting is at midnight.", "latin"},
        };
        for (String[] c : cases) {
            String armored = Triglyph.encryptText(c[0], Triglyph.KeyMaterial.rawKey(key),
                    new Triglyph.Options().suite("dual"), "auto");
            check(Armor.detect(armored).equals(c[1]), "auto armor for " + c[1]);
            check(Triglyph.decryptText(armored, Triglyph.KeyMaterial.rawKey(key)).equals(c[0]),
                    "text round-trip " + c[1]);
        }
    }

    // -------------------------------------------------------------------- main

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "docs/test-vectors.txt";
        String emit = null;
        for (int i = 1; i < args.length - 1; i++) {
            if (args[i].equals("--emit")) {
                emit = args[i + 1];
            }
        }
        InputStream in = new FileInputStream(path);
        Report rep;
        try {
            rep = run(new BufferedReader(new InputStreamReader(in, "UTF-8")));
        } finally {
            in.close();
        }
        for (String g : rep.groups) {
            System.out.println("  " + g);
        }
        for (String f : rep.failures) {
            System.out.println("FAIL " + f);
        }
        System.out.println(rep.summary());
        if (emit != null) {
            emitForPython(emit);
            System.out.println("emitted Java-made containers to " + emit);
        }
        System.exit(rep.ok() ? 0 : 1);
    }

    /** Пишет контейнеры, созданные Java, чтобы Python проверил их встречно. */
    private static void emitForPython(String path) throws IOException, TriglyphException {
        Writer w = new OutputStreamWriter(new FileOutputStream(path), "UTF-8");
        try {
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) {
                key[i] = (byte) (i * 3 + 1);
            }
            String[] suites = {"solo", "dual", "triple"};
            String[] msgs = {
                    "Проверка встречной совместимости Java → Python.",
                    "跨语言互操作性检查：Java 生成，Python 解密。",
                    "Cross-implementation check: made in Java, opened in Python.",
            };
            int[] pads = {TextUtil.PAD_NONE, TextUtil.PAD_PADME, TextUtil.PAD_BUCKET};
            for (String suite : suites) {
                for (int pad : pads) {
                    for (String m : msgs) {
                        byte[] blob = Triglyph.encrypt(Triglyph.utf8(m),
                                Triglyph.KeyMaterial.rawKey(key),
                                new Triglyph.Options().suite(suite).pad(pad));
                        w.write("rawkey|" + Util.hex(key) + "||" + Util.hex(blob) + "|"
                                + Util.hex(Triglyph.utf8(m)) + "\n");
                    }
                }
            }
            String pw = "пароль-密码-password";
            byte[] blob = Triglyph.encrypt(Triglyph.utf8("password mode from Java"),
                    Triglyph.KeyMaterial.password(pw),
                    new Triglyph.Options().profile("fast").suite("triple"));
            w.write("password||" + Util.hex(Kdf.normalizePassword(pw)) + "|" + Util.hex(blob) + "|"
                    + Util.hex(Triglyph.utf8("password mode from Java")) + "\n");
            byte[] big = new byte[50000];
            for (int i = 0; i < big.length; i++) {
                big[i] = (byte) ((i * 31 + 7) % 256);
            }
            byte[] multi = Triglyph.encrypt(big, Triglyph.KeyMaterial.rawKey(key),
                    new Triglyph.Options().suite("dual").pad(TextUtil.PAD_NONE));
            w.write("rawkey|" + Util.hex(key) + "||" + Util.hex(multi) + "|" + Util.hex(big) + "\n");
            byte[] stealth = Triglyph.encrypt(Triglyph.utf8("stealth from Java"),
                    Triglyph.KeyMaterial.rawKey(key),
                    new Triglyph.Options().suite("triple").stealth(true));
            w.write("rawkey|" + Util.hex(key) + "||" + Util.hex(stealth) + "|"
                    + Util.hex(Triglyph.utf8("stealth from Java")) + "\n");
        } finally {
            w.close();
        }
    }
}
