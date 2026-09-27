package ai.triglyph.core;

import java.math.BigInteger;

/**
 * ChaCha20 / HChaCha20 / XChaCha20 / Poly1305 / AEAD.
 *
 * <p>Строго по RFC 8439 и draft-irtf-cfrg-xchacha. Байт в байт совпадает
 * с Python-реализацией TRIGLYPH (проверяется в SelfCheck по общим векторам).
 */
public final class Chacha {

    private static final int[] SIGMA = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

    private Chacha() {
    }

    private static void core(int[] x, int[] st) {
        System.arraycopy(st, 0, x, 0, 16);
        for (int i = 0; i < 10; i++) {
            quarter(x, 0, 4, 8, 12);
            quarter(x, 1, 5, 9, 13);
            quarter(x, 2, 6, 10, 14);
            quarter(x, 3, 7, 11, 15);
            quarter(x, 0, 5, 10, 15);
            quarter(x, 1, 6, 11, 12);
            quarter(x, 2, 7, 8, 13);
            quarter(x, 3, 4, 9, 14);
        }
    }

    private static void quarter(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    private static int[] initialState(byte[] key, int counter, byte[] nonce12) {
        if (key.length != 32) {
            throw new IllegalArgumentException("ChaCha20 key must be 32 bytes");
        }
        if (nonce12.length != 12) {
            throw new IllegalArgumentException("ChaCha20 nonce must be 12 bytes");
        }
        int[] st = new int[16];
        System.arraycopy(SIGMA, 0, st, 0, 4);
        for (int i = 0; i < 8; i++) {
            st[4 + i] = Util.leInt(key, i * 4);
        }
        st[12] = counter;
        for (int i = 0; i < 3; i++) {
            st[13 + i] = Util.leInt(nonce12, i * 4);
        }
        return st;
    }

    /** Один 64-байтовый блок гаммы (RFC 8439 §2.3). */
    public static byte[] block(byte[] key, int counter, byte[] nonce12) {
        int[] st = initialState(key, counter, nonce12);
        int[] x = new int[16];
        core(x, st);
        byte[] out = new byte[64];
        for (int i = 0; i < 16; i++) {
            Util.putLeInt(out, i * 4, x[i] + st[i]);
        }
        return out;
    }

    /** Шифрование/расшифрование ChaCha20 (XOR с гаммой). */
    public static byte[] xor(byte[] key, int counter, byte[] nonce12, byte[] data) {
        byte[] out = new byte[data.length];
        xorInto(key, counter, nonce12, data, 0, data.length, out, 0);
        return out;
    }

    public static void xorInto(byte[] key, int counter, byte[] nonce12,
                               byte[] src, int srcOff, int len, byte[] dst, int dstOff) {
        int[] st = initialState(key, counter, nonce12);
        int[] x = new int[16];
        byte[] ks = new byte[64];
        int done = 0;
        while (done < len) {
            core(x, st);
            for (int i = 0; i < 16; i++) {
                Util.putLeInt(ks, i * 4, x[i] + st[i]);
            }
            st[12] += 1;
            int take = Math.min(64, len - done);
            for (int i = 0; i < take; i++) {
                dst[dstOff + done + i] = (byte) (src[srcOff + done + i] ^ ks[i]);
            }
            done += take;
        }
    }

    /** HChaCha20 — расширение нонса до 192 бит. */
    public static byte[] hchacha20(byte[] key, byte[] nonce16) {
        if (key.length != 32) {
            throw new IllegalArgumentException("HChaCha20 key must be 32 bytes");
        }
        if (nonce16.length != 16) {
            throw new IllegalArgumentException("HChaCha20 nonce must be 16 bytes");
        }
        int[] st = new int[16];
        System.arraycopy(SIGMA, 0, st, 0, 4);
        for (int i = 0; i < 8; i++) {
            st[4 + i] = Util.leInt(key, i * 4);
        }
        for (int i = 0; i < 4; i++) {
            st[12 + i] = Util.leInt(nonce16, i * 4);
        }
        int[] x = new int[16];
        core(x, st);
        byte[] out = new byte[32];
        for (int i = 0; i < 4; i++) {
            Util.putLeInt(out, i * 4, x[i]);
            Util.putLeInt(out, 16 + i * 4, x[12 + i]);
        }
        return out;
    }

    public static byte[] xchacha20Xor(byte[] key, int counter, byte[] nonce24, byte[] data) {
        byte[] subkey = hchacha20(key, Util.slice(nonce24, 0, 16));
        byte[] n12 = Util.concat(new byte[4], Util.slice(nonce24, 16, 24));
        return xor(subkey, counter, n12, data);
    }

    // ---------------------------------------------------------------- Poly1305

    private static final BigInteger P1305 = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger CLAMP =
            new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    private static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private static BigInteger leToBig(byte[] data, int off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) {
            be[i] = data[off + len - 1 - i];
        }
        return new BigInteger(1, be);
    }

    /** Одноразовый аутентификатор Poly1305 (RFC 8439 §2.5). */
    public static byte[] poly1305(byte[] msg, byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 32 bytes");
        }
        BigInteger r = leToBig(key, 0, 16).and(CLAMP);
        BigInteger s = leToBig(key, 16, 16);
        BigInteger acc = BigInteger.ZERO;
        byte[] blk = new byte[17];
        for (int i = 0; i < msg.length; i += 16) {
            int len = Math.min(16, msg.length - i);
            System.arraycopy(msg, i, blk, 0, len);
            blk[len] = 1;
            for (int j = len + 1; j < 17; j++) {
                blk[j] = 0;
            }
            acc = acc.add(leToBig(blk, 0, len + 1)).multiply(r).mod(P1305);
        }
        acc = acc.add(s).and(MASK128);
        byte[] be = acc.toByteArray();
        byte[] out = new byte[16];
        int n = Math.min(16, be.length);
        for (int i = 0; i < n; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static byte[] macData(byte[] aad, byte[] ct) {
        int pad1 = (16 - aad.length % 16) % 16;
        int pad2 = (16 - ct.length % 16) % 16;
        byte[] out = new byte[aad.length + pad1 + ct.length + pad2 + 16];
        int off = 0;
        System.arraycopy(aad, 0, out, off, aad.length);
        off += aad.length + pad1;
        System.arraycopy(ct, 0, out, off, ct.length);
        off += ct.length + pad2;
        Util.putLeLong(out, off, aad.length);
        Util.putLeLong(out, off + 8, ct.length);
        return out;
    }

    public static byte[] aeadEncrypt(byte[] key, byte[] nonce12, byte[] plaintext, byte[] aad) {
        byte[] otk = Util.slice(block(key, 0, nonce12), 0, 32);
        byte[] ct = xor(key, 1, nonce12, plaintext);
        byte[] tag = poly1305(macData(aad, ct), otk);
        return Util.concat(ct, tag);
    }

    public static byte[] aeadDecrypt(byte[] key, byte[] nonce12, byte[] ctAndTag, byte[] aad)
            throws TriglyphException {
        if (ctAndTag.length < 16) {
            throw new TriglyphException.Integrity("ciphertext too short for Poly1305 tag");
        }
        byte[] ct = Util.slice(ctAndTag, 0, ctAndTag.length - 16);
        byte[] tag = Util.slice(ctAndTag, ctAndTag.length - 16);
        byte[] otk = Util.slice(block(key, 0, nonce12), 0, 32);
        if (!Util.ctEquals(poly1305(macData(aad, ct), otk), tag)) {
            throw new TriglyphException.Integrity("ChaCha20-Poly1305: authentication failed");
        }
        return xor(key, 1, nonce12, ct);
    }

    public static byte[] xAeadEncrypt(byte[] key, byte[] nonce24, byte[] plaintext, byte[] aad) {
        byte[] subkey = hchacha20(key, Util.slice(nonce24, 0, 16));
        byte[] n12 = Util.concat(new byte[4], Util.slice(nonce24, 16, 24));
        return aeadEncrypt(subkey, n12, plaintext, aad);
    }

    public static byte[] xAeadDecrypt(byte[] key, byte[] nonce24, byte[] ctAndTag, byte[] aad)
            throws TriglyphException {
        byte[] subkey = hchacha20(key, Util.slice(nonce24, 0, 16));
        byte[] n12 = Util.concat(new byte[4], Util.slice(nonce24, 16, 24));
        return aeadDecrypt(subkey, n12, ctAndTag, aad);
    }
}
