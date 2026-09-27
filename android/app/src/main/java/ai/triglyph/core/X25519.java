package ai.triglyph.core;

import java.math.BigInteger;

/**
 * X25519 (RFC 7748) на {@link BigInteger}.
 *
 * <p>Штатный {@code XDH} появился в Android только с API 33, поэтому здесь
 * своя лестница Монтгомери. Число шагов постоянно (255), ветвление по битам
 * скаляра заменено условным обменом через маску.
 */
public final class X25519 {

    private static final BigInteger P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);
    private static final int BITS = 255;

    private X25519() {
    }

    private static BigInteger decodeLittleEndian(byte[] b) {
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = b[31 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] encodeLittleEndian(BigInteger v) {
        byte[] be = v.mod(P).toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(32, be.length);
        for (int i = 0; i < n; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static BigInteger clampScalar(byte[] k) {
        byte[] c = k.clone();
        c[0] &= (byte) 248;
        c[31] &= (byte) 127;
        c[31] |= (byte) 64;
        return decodeLittleEndian(c);
    }

    /** Умножение точки Монтгомери на скаляр (RFC 7748 §5). */
    public static byte[] scalarMult(byte[] scalar, byte[] uCoord) throws TriglyphException {
        if (scalar.length != 32 || uCoord.length != 32) {
            throw new TriglyphException.Crypto("X25519 requires 32-byte inputs");
        }
        byte[] u = uCoord.clone();
        u[31] &= (byte) 127; // старший бит игнорируется
        BigInteger k = clampScalar(scalar);
        BigInteger x1 = decodeLittleEndian(u).mod(P);

        BigInteger x2 = BigInteger.ONE;
        BigInteger z2 = BigInteger.ZERO;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.ONE;
        int swap = 0;

        for (int t = BITS - 1; t >= 0; t--) {
            int kt = k.testBit(t) ? 1 : 0;
            if ((swap ^ kt) == 1) {
                BigInteger tmp = x2;
                x2 = x3;
                x3 = tmp;
                tmp = z2;
                z2 = z3;
                z3 = tmp;
            }
            swap = kt;

            BigInteger a = x2.add(z2).mod(P);
            BigInteger aa = a.multiply(a).mod(P);
            BigInteger b = x2.subtract(z2).mod(P);
            BigInteger bb = b.multiply(b).mod(P);
            BigInteger e = aa.subtract(bb).mod(P);
            BigInteger c = x3.add(z3).mod(P);
            BigInteger d = x3.subtract(z3).mod(P);
            BigInteger da = d.multiply(a).mod(P);
            BigInteger cb = c.multiply(b).mod(P);
            BigInteger t0 = da.add(cb).mod(P);
            x3 = t0.multiply(t0).mod(P);
            BigInteger t1 = da.subtract(cb).mod(P);
            z3 = x1.multiply(t1.multiply(t1).mod(P)).mod(P);
            x2 = aa.multiply(bb).mod(P);
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P);
        }
        if (swap == 1) {
            BigInteger tmp = x2;
            x2 = x3;
            x3 = tmp;
            tmp = z2;
            z2 = z3;
            z3 = tmp;
        }
        BigInteger inv = z2.modPow(P.subtract(BigInteger.valueOf(2)), P);
        return encodeLittleEndian(x2.multiply(inv).mod(P));
    }

    private static final byte[] BASE_POINT = {
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };

    public static byte[] basePointMult(byte[] scalar) throws TriglyphException {
        return scalarMult(scalar, BASE_POINT);
    }

    public static byte[] generatePrivateKey() {
        byte[] sk = Util.random(32);
        sk[0] &= (byte) 248;
        sk[31] &= (byte) 127;
        sk[31] |= (byte) 64;
        return sk;
    }

    /** Общий секрет с проверкой на точки малого порядка. */
    public static byte[] sharedSecret(byte[] privateKey, byte[] peerPublic) throws TriglyphException {
        byte[] shared = scalarMult(privateKey, peerPublic);
        boolean allZero = true;
        for (byte b : shared) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new TriglyphException.Crypto("X25519: peer public key has small order");
        }
        return shared;
    }
}
