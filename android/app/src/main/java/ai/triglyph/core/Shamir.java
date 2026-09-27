package ai.triglyph.core;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Разделение секрета по схеме Шамира над GF(2^8) (полином 0x11B, как в AES).
 *
 * <p>Любые {@code threshold} частей восстанавливают секрет, любые
 * {@code threshold − 1} не дают о нём ни бита информации.
 */
public final class Shamir {

    public static final int SHARE_MAGIC = 0xA5;

    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];

    static {
        int x = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            x ^= (x << 1) ^ ((x & 0x80) != 0 ? 0x11B : 0);
            x &= 0xFF;
        }
        for (int i = 255; i < 512; i++) {
            EXP[i] = EXP[i - 255];
        }
    }

    private Shamir() {
    }

    private static int mul(int a, int b) {
        if (a == 0 || b == 0) {
            return 0;
        }
        return EXP[LOG[a] + LOG[b]];
    }

    private static int div(int a, int b) throws TriglyphException {
        if (b == 0) {
            throw new TriglyphException.Crypto("GF(256) division by zero");
        }
        if (a == 0) {
            return 0;
        }
        return EXP[((LOG[a] - LOG[b]) % 255 + 255) % 255];
    }

    /** Одна часть секрета. */
    public static final class Share {
        public final int index;
        public final int threshold;
        public final int total;
        public final byte[] payload;

        public Share(int index, int threshold, int total, byte[] payload) {
            this.index = index;
            this.threshold = threshold;
            this.total = total;
            this.payload = payload;
        }

        public byte[] toBytes() {
            byte[] body = Util.concat(
                    new byte[]{(byte) SHARE_MAGIC, (byte) index, (byte) threshold, (byte) total},
                    payload);
            byte[] sum = Util.slice(Keccak.sha3_256(Util.concat(Kdf.ascii("TRIGLYPH/share|"), body)), 0, 4);
            return Util.concat(body, sum);
        }

        public String armored(String kind) throws TriglyphException {
            return Armor.encode(toBytes(), kind);
        }

        public static Share parse(byte[] data) throws TriglyphException {
            if (data.length < 9) {
                throw new TriglyphException.Format("share too short");
            }
            byte[] body = Util.slice(data, 0, data.length - 4);
            byte[] sum = Util.slice(data, data.length - 4);
            byte[] want = Util.slice(Keccak.sha3_256(Util.concat(Kdf.ascii("TRIGLYPH/share|"), body)), 0, 4);
            if (!Util.ctEquals(want, sum)) {
                throw new TriglyphException.Format("часть секрета повреждена / corrupted share");
            }
            if ((body[0] & 0xFF) != SHARE_MAGIC) {
                throw new TriglyphException.Format("not a TRIGLYPH share");
            }
            return new Share(body[1] & 0xFF, body[2] & 0xFF, body[3] & 0xFF, Util.slice(body, 4));
        }

        public static Share parse(String armored) throws TriglyphException {
            return parse(Armor.decode(armored.trim()));
        }
    }

    public static List<Share> split(byte[] secret, int threshold, int shares) throws TriglyphException {
        if (threshold < 2 || threshold > 255) {
            throw new TriglyphException.Crypto("threshold must be in 2..255");
        }
        if (shares < threshold || shares > 255) {
            throw new TriglyphException.Crypto("shares must be in threshold..255");
        }
        if (secret.length == 0) {
            throw new TriglyphException.Crypto("secret must not be empty");
        }
        byte[] guarded = Util.concat(secret,
                Util.slice(Keccak.sha3_256(Util.concat(Kdf.ascii("TRIGLYPH/secret|"), secret)), 0, 4));

        byte[][] out = new byte[shares][guarded.length];
        byte[] coeffs = new byte[threshold];
        for (int pos = 0; pos < guarded.length; pos++) {
            byte[] rnd = Util.random(threshold - 1);
            coeffs[0] = guarded[pos];
            System.arraycopy(rnd, 0, coeffs, 1, threshold - 1);
            for (int si = 0; si < shares; si++) {
                int x = si + 1;
                int acc = 0;
                for (int c = threshold - 1; c >= 0; c--) {
                    acc = mul(acc, x) ^ (coeffs[c] & 0xFF);
                }
                out[si][pos] = (byte) acc;
            }
        }
        List<Share> result = new ArrayList<Share>();
        for (int i = 0; i < shares; i++) {
            result.add(new Share(i + 1, threshold, shares, out[i]));
        }
        return result;
    }

    public static byte[] combine(List<Share> sharesIn) throws TriglyphException {
        if (sharesIn.isEmpty()) {
            throw new TriglyphException.Crypto("no shares provided");
        }
        int threshold = sharesIn.get(0).threshold;
        Set<Integer> indices = new HashSet<Integer>();
        int len = sharesIn.get(0).payload.length;
        for (Share s : sharesIn) {
            if (s.threshold != threshold) {
                throw new TriglyphException.Crypto("части принадлежат разным секретам (разный порог)");
            }
            if (!indices.add(s.index)) {
                throw new TriglyphException.Crypto("повторяющиеся части: индексы должны отличаться");
            }
            if (s.payload.length != len) {
                throw new TriglyphException.Crypto("части разной длины");
            }
        }
        if (sharesIn.size() < threshold) {
            throw new TriglyphException.Crypto(
                    "нужно минимум " + threshold + " частей, дано " + sharesIn.size());
        }
        List<Share> parsed = sharesIn.subList(0, threshold);
        byte[] guarded = new byte[len];
        for (int pos = 0; pos < len; pos++) {
            int acc = 0;
            for (int i = 0; i < parsed.size(); i++) {
                Share si = parsed.get(i);
                int num = 1;
                int den = 1;
                for (int j = 0; j < parsed.size(); j++) {
                    if (i == j) {
                        continue;
                    }
                    Share sj = parsed.get(j);
                    num = mul(num, sj.index);
                    den = mul(den, si.index ^ sj.index);
                }
                acc ^= mul(si.payload[pos] & 0xFF, div(num, den));
            }
            guarded[pos] = (byte) acc;
        }
        if (guarded.length < 4) {
            throw new TriglyphException.Crypto("secret too short");
        }
        byte[] secret = Util.slice(guarded, 0, guarded.length - 4);
        byte[] sum = Util.slice(guarded, guarded.length - 4);
        byte[] want = Util.slice(Keccak.sha3_256(Util.concat(Kdf.ascii("TRIGLYPH/secret|"), secret)), 0, 4);
        if (!Util.ctEquals(want, sum)) {
            throw new TriglyphException.Crypto(
                    "секрет не восстановился: части не от одного секрета или повреждены");
        }
        return secret;
    }
}
