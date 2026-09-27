package ai.triglyph.core;

/**
 * Threefish-1024 (ARX-шифр из Skein 1.3) и режим счётчика.
 *
 * <p>Блок и ключ по 1024 бита, твик 128 бит, 80 раундов. Третий (внешний)
 * слой каскада TRIGLYPH.
 */
public final class Threefish {

    private static final long C240 = 0x1BD11BDAA9FC1A22L;
    private static final int NW = 16;
    private static final int ROUNDS = 80;

    private static final int[][] ROT = {
            {24, 13, 8, 47, 8, 17, 22, 37},
            {38, 19, 10, 55, 49, 18, 23, 52},
            {33, 4, 51, 13, 34, 41, 59, 17},
            {5, 20, 48, 41, 47, 28, 16, 25},
            {41, 9, 37, 31, 12, 47, 44, 30},
            {16, 34, 56, 51, 4, 53, 42, 41},
            {31, 44, 47, 46, 19, 42, 44, 25},
            {9, 48, 35, 52, 23, 31, 37, 20},
    };

    private static final int[] PERM = {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};
    private static final int[] INV_PERM = new int[16];

    static {
        for (int i = 0; i < 16; i++) {
            INV_PERM[PERM[i]] = i;
        }
    }

    private final long[][] ks = new long[ROUNDS / 4 + 1][NW];

    public Threefish(byte[] key, byte[] tweak) {
        if (key.length != 128) {
            throw new IllegalArgumentException("Threefish-1024 key must be 128 bytes");
        }
        if (tweak.length != 16) {
            throw new IllegalArgumentException("tweak must be 16 bytes");
        }
        long[] k = new long[NW + 1];
        long parity = C240;
        for (int i = 0; i < NW; i++) {
            k[i] = Util.leLong(key, i * 8);
            parity ^= k[i];
        }
        k[NW] = parity;
        long[] t = new long[3];
        t[0] = Util.leLong(tweak, 0);
        t[1] = Util.leLong(tweak, 8);
        t[2] = t[0] ^ t[1];

        for (int s = 0; s <= ROUNDS / 4; s++) {
            for (int i = 0; i < NW; i++) {
                ks[s][i] = k[(s + i) % (NW + 1)];
            }
            ks[s][NW - 3] += t[s % 3];
            ks[s][NW - 2] += t[(s + 1) % 3];
            ks[s][NW - 1] += s;
        }
    }

    public void encryptBlock(byte[] src, int srcOff, byte[] dst, int dstOff) {
        long[] v = new long[NW];
        long[] nv = new long[NW];
        for (int i = 0; i < NW; i++) {
            v[i] = Util.leLong(src, srcOff + i * 8);
        }
        for (int d = 0; d < ROUNDS; d++) {
            if (d % 4 == 0) {
                long[] sub = ks[d / 4];
                for (int i = 0; i < NW; i++) {
                    v[i] += sub[i];
                }
            }
            int[] rot = ROT[d % 8];
            for (int j = 0; j < NW / 2; j++) {
                long x0 = v[2 * j];
                long x1 = v[2 * j + 1];
                long y0 = x0 + x1;
                long y1 = Long.rotateLeft(x1, rot[j]) ^ y0;
                nv[2 * j] = y0;
                nv[2 * j + 1] = y1;
            }
            for (int i = 0; i < NW; i++) {
                v[i] = nv[PERM[i]];
            }
        }
        long[] sub = ks[ROUNDS / 4];
        for (int i = 0; i < NW; i++) {
            Util.putLeLong(dst, dstOff + i * 8, v[i] + sub[i]);
        }
    }

    public byte[] encryptBlock(byte[] block) {
        byte[] out = new byte[128];
        encryptBlock(block, 0, out, 0);
        return out;
    }

    public byte[] decryptBlock(byte[] block) {
        if (block.length != 128) {
            throw new IllegalArgumentException("Threefish-1024 block must be 128 bytes");
        }
        long[] v = new long[NW];
        long[] pv = new long[NW];
        for (int i = 0; i < NW; i++) {
            v[i] = Util.leLong(block, i * 8);
        }
        long[] sub = ks[ROUNDS / 4];
        for (int i = 0; i < NW; i++) {
            v[i] -= sub[i];
        }
        for (int d = ROUNDS - 1; d >= 0; d--) {
            for (int i = 0; i < NW; i++) {
                pv[i] = v[INV_PERM[i]];
            }
            int[] rot = ROT[d % 8];
            for (int j = 0; j < NW / 2; j++) {
                long y0 = pv[2 * j];
                long y1 = pv[2 * j + 1];
                long x1 = Long.rotateLeft(y1 ^ y0, 64 - rot[j]);
                long x0 = y0 - x1;
                v[2 * j] = x0;
                v[2 * j + 1] = x1;
            }
            if (d % 4 == 0) {
                long[] s = ks[d / 4];
                for (int i = 0; i < NW; i++) {
                    v[i] -= s[i];
                }
            }
        }
        byte[] out = new byte[128];
        for (int i = 0; i < NW; i++) {
            Util.putLeLong(out, i * 8, v[i]);
        }
        return out;
    }

    /** Режим счётчика: гамма = E_K(nonce ‖ u128(counter+i)), твик = nonce. */
    public static byte[] ctrXor(byte[] key, byte[] nonce16, byte[] data, long counter) {
        if (nonce16.length != 16) {
            throw new IllegalArgumentException("nonce must be 16 bytes");
        }
        if (data.length == 0) {
            return new byte[0];
        }
        Threefish tf = new Threefish(key, nonce16);
        byte[] out = new byte[data.length];
        byte[] inBlock = new byte[128];
        byte[] ks = new byte[128];
        System.arraycopy(nonce16, 0, inBlock, 0, 16);
        int blocks = (data.length + 127) / 128;
        for (int i = 0; i < blocks; i++) {
            long c = counter + i;
            for (int b = 0; b < 8; b++) {
                inBlock[16 + b] = 0;                       // старшая половина u128 = 0
                inBlock[24 + b] = (byte) (c >>> (56 - 8 * b)); // младшая, big-endian
            }
            tf.encryptBlock(inBlock, 0, ks, 0);
            int off = i * 128;
            int take = Math.min(128, data.length - off);
            for (int j = 0; j < take; j++) {
                out[off + j] = (byte) (data[off + j] ^ ks[j]);
            }
        }
        return out;
    }

    public static byte[] ctrXor(byte[] key, byte[] nonce16, byte[] data) {
        return ctrXor(key, nonce16, data, 0);
    }
}
