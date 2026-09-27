package ai.triglyph.core;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Вывод ключей: HKDF-SHA512, парольная функция «TRIGLYPH-KDF/1» и расписание ключей.
 *
 * <p>PBKDF2-HMAC-SHA512 и scrypt реализованы вручную: {@code SecretKeyFactory}
 * с PBKDF2WithHmacSHA512 есть только с API 26, а scrypt в платформе Android
 * отсутствует вовсе. Байты совпадают с {@code hashlib} из Python.
 */
public final class Kdf {

    public static final byte[] DOMAIN = ascii("TRIGLYPH/v1");

    public static final int KDF_SCRYPT = 1;
    public static final int KDF_ARGON2ID = 2;
    public static final int KDF_RAW = 3;

    private Kdf() {
    }

    static byte[] ascii(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException exc) {
            throw new IllegalStateException(exc);
        }
    }

    // ------------------------------------------------------------------ HMAC

    private static byte[] hmac(String alg, byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, alg));
            return mac.doFinal(data);
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException(alg + " unavailable", exc);
        }
    }

    public static byte[] hmacSha512(byte[] key, byte[] data) {
        return hmac("HmacSHA512", key, data);
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        return hmac("HmacSHA256", key, data);
    }

    // ------------------------------------------------------------------ HKDF

    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        byte[] s = (salt == null || salt.length == 0) ? new byte[64] : salt;
        return hmacSha512(s, ikm);
    }

    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        if (length > 255 * 64) {
            throw new IllegalArgumentException("HKDF: requested length too large");
        }
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int counter = 1;
        int done = 0;
        while (done < length) {
            byte[] input = Util.concat(t, info, new byte[]{(byte) counter});
            t = hmacSha512(prk, input);
            int take = Math.min(t.length, length - done);
            System.arraycopy(t, 0, out, done, take);
            done += take;
            counter++;
        }
        return out;
    }

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        return hkdfExpand(hkdfExtract(salt, ikm), info, length);
    }

    // ---------------------------------------------------------------- PBKDF2

    /** PBKDF2-HMAC-SHA512 (RFC 8018). */
    public static byte[] pbkdf2Sha512(byte[] password, byte[] salt, int iterations, int dkLen) {
        return pbkdf2(password, salt, iterations, dkLen, "HmacSHA512", 64);
    }

    /** PBKDF2-HMAC-SHA256, нужен внутри scrypt. */
    public static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int dkLen) {
        return pbkdf2(password, salt, iterations, dkLen, "HmacSHA256", 32);
    }

    private static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int dkLen,
                                 String alg, int hLen) {
        try {
            Mac mac = Mac.getInstance(alg);
            mac.init(new SecretKeySpec(password.length == 0 ? new byte[1] : password, alg));
            byte[] out = new byte[dkLen];
            int blocks = (dkLen + hLen - 1) / hLen;
            byte[] block = new byte[salt.length + 4];
            System.arraycopy(salt, 0, block, 0, salt.length);
            for (int i = 1; i <= blocks; i++) {
                block[salt.length] = (byte) (i >>> 24);
                block[salt.length + 1] = (byte) (i >>> 16);
                block[salt.length + 2] = (byte) (i >>> 8);
                block[salt.length + 3] = (byte) i;
                byte[] u = mac.doFinal(block);
                byte[] acc = u.clone();
                for (int j = 1; j < iterations; j++) {
                    u = mac.doFinal(u);
                    for (int k = 0; k < hLen; k++) {
                        acc[k] ^= u[k];
                    }
                }
                int off = (i - 1) * hLen;
                System.arraycopy(acc, 0, out, off, Math.min(hLen, dkLen - off));
            }
            return out;
        } catch (GeneralSecurityException exc) {
            throw new IllegalStateException("PBKDF2 unavailable: " + alg, exc);
        }
    }

    // ---------------------------------------------------------------- scrypt

    /** scrypt (RFC 7914). Требует 128·r·N байт оперативной памяти. */
    public static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p, int dkLen)
            throws TriglyphException {
        if (n < 2 || (n & (n - 1)) != 0) {
            throw new TriglyphException.Crypto("scrypt: N must be a power of 2 > 1");
        }
        long need = 128L * r * n;
        if (need > Integer.MAX_VALUE) {
            throw new TriglyphException.Crypto("scrypt: parameters too large for this device");
        }
        try {
            byte[] b = pbkdf2Sha256(password, salt, 1, p * 128 * r);
            byte[] v = new byte[(int) need];
            for (int i = 0; i < p; i++) {
                roMix(b, i * 128 * r, r, n, v);
            }
            return pbkdf2Sha256(password, b, 1, dkLen);
        } catch (OutOfMemoryError err) {
            throw new TriglyphException.Crypto(
                    "scrypt: not enough memory (" + (need / (1024 * 1024)) + " MiB required)");
        }
    }

    private static void roMix(byte[] b, int bOff, int r, int n, byte[] v) {
        final int blockLen = 128 * r;
        byte[] x = new byte[blockLen];
        byte[] tmp = new byte[blockLen];
        System.arraycopy(b, bOff, x, 0, blockLen);
        for (int i = 0; i < n; i++) {
            System.arraycopy(x, 0, v, i * blockLen, blockLen);
            blockMix(x, tmp, r);
            System.arraycopy(tmp, 0, x, 0, blockLen);
        }
        for (int i = 0; i < n; i++) {
            int j = (int) (Util.leInt(x, blockLen - 64) & 0xFFFFFFFFL) & (n - 1);
            Util.xorInto(x, 0, v, j * blockLen, blockLen);
            blockMix(x, tmp, r);
            System.arraycopy(tmp, 0, x, 0, blockLen);
        }
        System.arraycopy(x, 0, b, bOff, blockLen);
    }

    private static void blockMix(byte[] in, byte[] out, int r) {
        byte[] x = new byte[64];
        System.arraycopy(in, (2 * r - 1) * 64, x, 0, 64);
        for (int i = 0; i < 2 * r; i++) {
            Util.xorInto(x, 0, in, i * 64, 64);
            salsa20_8(x);
            int dst = (i % 2 == 0) ? (i / 2) * 64 : (r + i / 2) * 64;
            System.arraycopy(x, 0, out, dst, 64);
        }
    }

    private static void salsa20_8(byte[] block) {
        int[] x = new int[16];
        int[] in = new int[16];
        for (int i = 0; i < 16; i++) {
            in[i] = Util.leInt(block, i * 4);
            x[i] = in[i];
        }
        for (int round = 0; round < 4; round++) {
            x[4] ^= Integer.rotateLeft(x[0] + x[12], 7);
            x[8] ^= Integer.rotateLeft(x[4] + x[0], 9);
            x[12] ^= Integer.rotateLeft(x[8] + x[4], 13);
            x[0] ^= Integer.rotateLeft(x[12] + x[8], 18);
            x[9] ^= Integer.rotateLeft(x[5] + x[1], 7);
            x[13] ^= Integer.rotateLeft(x[9] + x[5], 9);
            x[1] ^= Integer.rotateLeft(x[13] + x[9], 13);
            x[5] ^= Integer.rotateLeft(x[1] + x[13], 18);
            x[14] ^= Integer.rotateLeft(x[10] + x[6], 7);
            x[2] ^= Integer.rotateLeft(x[14] + x[10], 9);
            x[6] ^= Integer.rotateLeft(x[2] + x[14], 13);
            x[10] ^= Integer.rotateLeft(x[6] + x[2], 18);
            x[3] ^= Integer.rotateLeft(x[15] + x[11], 7);
            x[7] ^= Integer.rotateLeft(x[3] + x[15], 9);
            x[11] ^= Integer.rotateLeft(x[7] + x[3], 13);
            x[15] ^= Integer.rotateLeft(x[11] + x[7], 18);

            x[1] ^= Integer.rotateLeft(x[0] + x[3], 7);
            x[2] ^= Integer.rotateLeft(x[1] + x[0], 9);
            x[3] ^= Integer.rotateLeft(x[2] + x[1], 13);
            x[0] ^= Integer.rotateLeft(x[3] + x[2], 18);
            x[6] ^= Integer.rotateLeft(x[5] + x[4], 7);
            x[7] ^= Integer.rotateLeft(x[6] + x[5], 9);
            x[4] ^= Integer.rotateLeft(x[7] + x[6], 13);
            x[5] ^= Integer.rotateLeft(x[4] + x[7], 18);
            x[11] ^= Integer.rotateLeft(x[10] + x[9], 7);
            x[8] ^= Integer.rotateLeft(x[11] + x[10], 9);
            x[9] ^= Integer.rotateLeft(x[8] + x[11], 13);
            x[10] ^= Integer.rotateLeft(x[9] + x[8], 18);
            x[12] ^= Integer.rotateLeft(x[15] + x[14], 7);
            x[13] ^= Integer.rotateLeft(x[12] + x[15], 9);
            x[14] ^= Integer.rotateLeft(x[13] + x[12], 13);
            x[15] ^= Integer.rotateLeft(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++) {
            Util.putLeInt(block, i * 4, x[i] + in[i]);
        }
    }

    // ---------------------------------------------------------------- профили

    /** Параметры парольной функции. */
    public static final class Profile {
        public final String name;
        public final int scryptN;
        public final int scryptR;
        public final int scryptP;
        public final int pbkdf2Iters;

        Profile(String name, int n, int r, int p, int iters) {
            this.name = name;
            this.scryptN = n;
            this.scryptR = r;
            this.scryptP = p;
            this.pbkdf2Iters = iters;
        }

        public long memoryBytes() {
            return 128L * scryptR * scryptN;
        }

        public String describe() {
            return name + ": scrypt(N=2^" + (31 - Integer.numberOfLeadingZeros(scryptN))
                    + ", r=" + scryptR + ", p=" + scryptP + ", ~" + (memoryBytes() / (1024 * 1024))
                    + " MiB) + PBKDF2-SHA512x" + pbkdf2Iters;
        }
    }

    public static final Map<String, Profile> PROFILES = new LinkedHashMap<String, Profile>();

    static {
        PROFILES.put("fast", new Profile("fast", 1 << 13, 8, 1, 20000));
        PROFILES.put("balanced", new Profile("balanced", 1 << 16, 8, 1, 210000));
        PROFILES.put("hard", new Profile("hard", 1 << 18, 8, 1, 600000));
        PROFILES.put("paranoid", new Profile("paranoid", 1 << 20, 8, 2, 1200000));
    }

    public static Profile profile(String name) throws TriglyphException {
        Profile p = PROFILES.get(name);
        if (p == null) {
            throw new TriglyphException.Crypto("unknown KDF profile: " + name);
        }
        return p;
    }

    /** NFKC-нормализация пароля и кодирование в UTF-8. */
    public static byte[] normalizePassword(String password) {
        return ascii(Normalizer.normalize(password, Normalizer.Form.NFKC));
    }

    /** Парольный KDF → 64 байта мастер-секрета. */
    public static byte[] deriveMasterSecret(byte[] password, byte[] salt, Profile prof,
                                            int kdfId, byte[] pepper) throws TriglyphException {
        if (salt.length < 16) {
            throw new TriglyphException.Crypto("salt must be at least 16 bytes");
        }
        byte[] pw = password;
        if (pepper != null && pepper.length > 0) {
            pw = Keccak.sha3_512(Util.concat(DOMAIN, ascii("|pepper|"), pepper, ascii("|"), pw));
        }
        byte[] stage0 = Keccak.sha3_512(Util.concat(DOMAIN, ascii("|pw|"), Util.u32(pw.length), pw));

        if (kdfId == KDF_RAW) {
            return hkdf(pw, salt, Util.concat(DOMAIN, ascii("|rawkey")), 64);
        }
        if (kdfId != KDF_SCRYPT) {
            throw new TriglyphException.Crypto(
                    kdfId == KDF_ARGON2ID
                            ? "Argon2id containers are not supported by the Android build"
                            : "unknown KDF id " + kdfId);
        }
        byte[] scryptSalt = Keccak.sha3_256(Util.concat(DOMAIN, ascii("|salt|"), salt));
        byte[] stage1 = scrypt(stage0, scryptSalt, prof.scryptN, prof.scryptR, prof.scryptP, 64);
        byte[] stage2 = pbkdf2Sha512(stage1, Util.concat(salt, ascii("|pbkdf2")), prof.pbkdf2Iters, 64);
        return Keccak.sha3_512(Util.concat(DOMAIN, ascii("|master|"), stage1, stage2, salt,
                Util.u32(prof.pbkdf2Iters)));
    }

    // --------------------------------------------------------- расписание ключей

    /** Независимые подключи каскада, выведенные из мастер-секрета. */
    public static final class KeySchedule {
        private static final String[] NAMES = {"l1", "l2", "l3", "mac", "nonce", "commit", "header"};
        private static final String[] LABELS = {
                "layer1/xchacha20-poly1305",
                "layer2/aes-256-gcm",
                "layer3/threefish-1024-ctr",
                "outer/hmac-sha3-512",
                "nonce-derivation",
                "key-commitment",
                "header-binding",
        };
        private static final int[] SIZES = {32, 32, 128, 64, 32, 32, 32};

        private final Map<String, byte[]> keys = new LinkedHashMap<String, byte[]>();

        public KeySchedule(byte[] master, byte[] context) throws TriglyphException {
            if (master.length < 32) {
                throw new TriglyphException.Crypto("master secret must be at least 32 bytes");
            }
            byte[] prk = hkdfExtract(Util.concat(DOMAIN, ascii("|schedule|"), context), master);
            for (int i = 0; i < NAMES.length; i++) {
                keys.put(NAMES[i], hkdfExpand(prk, Util.concat(DOMAIN, ascii("|"), ascii(LABELS[i])), SIZES[i]));
            }
        }

        public byte[] get(String name) {
            byte[] k = keys.get(name);
            if (k == null) {
                throw new IllegalArgumentException("unknown subkey " + name);
            }
            return k;
        }

        public byte[] commitment() {
            return Keccak.sha3_256(Util.concat(DOMAIN, ascii("|commit|"), get("commit")));
        }

        public byte[] nonceFor(String purpose, long index, int size) {
            return hkdfExpand(
                    hkdfExtract(Util.concat(DOMAIN, ascii("|nonce|")), get("nonce")),
                    Util.concat(ascii(purpose), ascii("|"), Util.u64(index)),
                    size);
        }

        public void destroy() {
            for (Map.Entry<String, byte[]> e : keys.entrySet()) {
                Util.wipe(e.getValue());
            }
            keys.clear();
        }
    }
}
