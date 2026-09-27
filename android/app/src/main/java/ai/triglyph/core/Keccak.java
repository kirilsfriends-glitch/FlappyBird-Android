package ai.triglyph.core;

/**
 * Keccak-f[1600]: SHA3-256, SHA3-512, SHAKE-256 и HMAC-SHA3-512.
 *
 * <p>Собственная реализация нужна потому, что {@code MessageDigest("SHA3-256")}
 * появился в Android только с API 29, а TRIGLYPH обязан работать с API 21
 * и выдавать те же байты, что и Python-версия.
 */
public final class Keccak {

    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    /** Смещения ρ, индекс = x + 5y. */
    private static final int[] ROT = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
    };

    private Keccak() {
    }

    private static void permute(long[] a) {
        long[] b = new long[25];
        long[] c = new long[5];
        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 5; y++) {
                    a[x + 5 * y] ^= d;
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[x + 5 * y], ROT[x + 5 * y]);
                }
            }
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
                }
            }
            a[0] ^= RC[round];
        }
    }

    /**
     * Губка Keccak.
     *
     * @param rate      скорость в байтах (136 для 256 бит, 72 для 512 бит)
     * @param padByte   0x06 для SHA-3, 0x1F для SHAKE
     * @param outputLen длина результата в байтах
     */
    private static byte[] sponge(byte[] input, int rate, int padByte, int outputLen) {
        long[] state = new long[25];
        int off = 0;
        byte[] block = new byte[rate];

        while (input.length - off >= rate) {
            absorb(state, input, off, rate);
            off += rate;
        }
        int rem = input.length - off;
        System.arraycopy(input, off, block, 0, rem);
        java.util.Arrays.fill(block, rem, rate, (byte) 0);
        block[rem] = (byte) padByte;
        block[rate - 1] |= (byte) 0x80;
        absorb(state, block, 0, rate);

        byte[] out = new byte[outputLen];
        int produced = 0;
        while (produced < outputLen) {
            int take = Math.min(rate, outputLen - produced);
            for (int i = 0; i < take; i++) {
                out[produced + i] = (byte) (state[(i / 8)] >>> (8 * (i % 8)));
            }
            produced += take;
            if (produced < outputLen) {
                permute(state);
            }
        }
        return out;
    }

    private static void absorb(long[] state, byte[] data, int off, int rate) {
        for (int i = 0; i < rate / 8; i++) {
            state[i] ^= Util.leLong(data, off + i * 8);
        }
        permute(state);
    }

    public static byte[] sha3_256(byte[] input) {
        return sponge(input, 136, 0x06, 32);
    }

    public static byte[] sha3_512(byte[] input) {
        return sponge(input, 72, 0x06, 64);
    }

    public static byte[] shake256(byte[] input, int outputLen) {
        return sponge(input, 136, 0x1F, outputLen);
    }

    /** HMAC поверх SHA3-512 (размер блока 72 байта). */
    public static byte[] hmacSha3_512(byte[] key, byte[] message) {
        final int blockSize = 72;
        byte[] k = key.length > blockSize ? sha3_512(key) : key;
        byte[] pad = new byte[blockSize];
        System.arraycopy(k, 0, pad, 0, k.length);

        byte[] inner = new byte[blockSize];
        byte[] outer = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            inner[i] = (byte) (pad[i] ^ 0x36);
            outer[i] = (byte) (pad[i] ^ 0x5C);
        }
        byte[] innerHash = sha3_512(Util.concat(inner, message));
        return sha3_512(Util.concat(outer, innerHash));
    }
}
