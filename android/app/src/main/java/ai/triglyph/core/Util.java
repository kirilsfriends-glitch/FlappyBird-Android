package ai.triglyph.core;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

/** Байтовые утилиты: hex, XOR, сравнение за константное время, упаковка чисел. */
public final class Util {

    private static final SecureRandom RNG = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Util() {
    }

    public static byte[] random(int n) {
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    public static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    public static byte[] unhex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Сравнение за константное время. */
    public static boolean ctEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    public static byte[] xor(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    public static void xorInto(byte[] dst, int dstOff, byte[] src, int srcOff, int len) {
        for (int i = 0; i < len; i++) {
            dst[dstOff + i] ^= src[srcOff + i];
        }
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    public static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, to - from);
        return out;
    }

    public static byte[] slice(byte[] data, int from) {
        return slice(data, from, data.length);
    }

    // --- big-endian ---

    public static byte[] u8(int v) {
        return new byte[]{(byte) v};
    }

    public static byte[] u16(int v) {
        return new byte[]{(byte) (v >>> 8), (byte) v};
    }

    public static byte[] u32(long v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    public static byte[] u64(long v) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (v >>> (56 - 8 * i));
        }
        return out;
    }

    public static int readU16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    public static long readU32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    public static long readU64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[off + i] & 0xFF);
        }
        return v;
    }

    /** Поле с префиксом длины (u32 ‖ данные). */
    public static byte[] lenPrefixed(byte[] data) {
        return concat(u32(data.length), data);
    }

    // --- little-endian 32/64 ---

    public static int leInt(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    public static void putLeInt(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }

    public static long leLong(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (b[off + i] & 0xFF);
        }
        return v;
    }

    public static void putLeLong(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (8 * i));
        }
    }

    public static void wipe(byte[] data) {
        if (data != null) {
            java.util.Arrays.fill(data, (byte) 0);
        }
    }

    /** Простой накопитель байтов. */
    public static final class Buf {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        public Buf add(byte[] data) {
            out.write(data, 0, data.length);
            return this;
        }

        public Buf add(byte[] data, int off, int len) {
            out.write(data, off, len);
            return this;
        }

        public int size() {
            return out.size();
        }

        public byte[] toBytes() {
            return out.toByteArray();
        }
    }
}
