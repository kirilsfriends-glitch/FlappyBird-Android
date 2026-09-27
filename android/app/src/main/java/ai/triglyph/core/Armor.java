package ai.triglyph.core;

/**
 * «Броня» — печатное представление шифртекста на трёх письменностях.
 *
 * <ul>
 *   <li>{@code hanzi} — 4096 иероглифов U+4E00…U+5DFF, 12 бит на знак;</li>
 *   <li>{@code cyrillic} — 32 русские буквы (без «ё»), 5 бит на букву;</li>
 *   <li>{@code latin} — Base64URL без набивки;</li>
 *   <li>{@code grouped} — Base32 группами по 5 знаков, для диктовки.</li>
 * </ul>
 */
public final class Armor {

    public static final String BEGIN_MARK = "-----TRIGLYPH BEGIN / НАЧАЛО / 开始-----";
    public static final String END_MARK = "-----TRIGLYPH END / КОНЕЦ / 结束-----";

    public static final String[] KINDS = {"hanzi", "cyrillic", "latin", "grouped"};

    private static final int HANZI_BASE = 0x4E00;
    private static final int HANZI_COUNT = 4096;
    private static final char[] HANZI_MARKS = {'\u3280', '\u3281', '\u3282'};
    private static final String CYR = "абвгдежзийклмнопрстуфхцчшщъыьэюя";
    private static final String B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Armor() {
    }

    private static byte[] checksum(byte[] data, int n) {
        return Util.slice(Keccak.sha3_256(Util.concat(Kdf.ascii("TRIGLYPH/armor|"), data)), 0, n);
    }

    private static String strip(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isWhitespace(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ hanzi

    private static String hanziEncode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append(HANZI_MARKS[data.length % 3]);
        byte[] payload = Util.concat(data, checksum(data, 3));
        for (int i = 0; i < payload.length; i += 3) {
            int left = payload.length - i;
            if (left >= 3) {
                int v = ((payload[i] & 0xFF) << 16) | ((payload[i + 1] & 0xFF) << 8) | (payload[i + 2] & 0xFF);
                sb.append((char) (HANZI_BASE + (v >> 12)));
                sb.append((char) (HANZI_BASE + (v & 0xFFF)));
            } else if (left == 2) {
                int v = ((payload[i] & 0xFF) << 16) | ((payload[i + 1] & 0xFF) << 8);
                sb.append((char) (HANZI_BASE + (v >> 12)));
                sb.append((char) (HANZI_BASE + (v & 0xFFF)));
            } else {
                int v = (payload[i] & 0xFF) << 4;
                sb.append((char) (HANZI_BASE + (v & 0xFFF)));
            }
        }
        return sb.toString();
    }

    private static byte[] hanziDecode(String text) throws TriglyphException {
        String s = strip(text);
        if (s.isEmpty()) {
            throw new TriglyphException.Format("hanzi armor: empty");
        }
        int rem = -1;
        for (int i = 0; i < 3; i++) {
            if (s.charAt(0) == HANZI_MARKS[i]) {
                rem = i;
            }
        }
        if (rem < 0) {
            throw new TriglyphException.Format("hanzi armor: missing leading marker ㊀/㊁/㊂");
        }
        Util.Buf out = new Util.Buf();
        int acc = 0;
        int bits = 0;
        byte[] one = new byte[1];
        for (int i = 1; i < s.length(); i++) {
            int idx = s.charAt(i) - HANZI_BASE;
            if (idx < 0 || idx >= HANZI_COUNT) {
                throw new TriglyphException.Format(
                        "hanzi armor: character U+" + Integer.toHexString(s.charAt(i)).toUpperCase()
                                + " is outside the alphabet");
            }
            acc = (acc << 12) | idx;
            bits += 12;
            while (bits >= 8) {
                bits -= 8;
                one[0] = (byte) ((acc >> bits) & 0xFF);
                out.add(one);
            }
            acc &= (1 << bits) - 1;
        }
        byte[] payload = out.toBytes();
        int dataLen = payload.length - 3;
        while (dataLen >= 0 && (dataLen % 3) != rem) {
            dataLen--;
        }
        if (dataLen < 0) {
            throw new TriglyphException.Format("hanzi armor: inconsistent length marker");
        }
        byte[] data = Util.slice(payload, 0, dataLen);
        byte[] got = Util.slice(payload, dataLen, dataLen + 3);
        if (!Util.ctEquals(checksum(data, 3), got)) {
            throw new TriglyphException.Format("hanzi armor: checksum mismatch");
        }
        return data;
    }

    // --------------------------------------------------------------- cyrillic

    private static String cyrEncode(byte[] data) {
        byte[] payload = Util.concat(data, checksum(data, 2));
        StringBuilder sb = new StringBuilder();
        int acc = 0;
        int bits = 0;
        for (byte b : payload) {
            acc = (acc << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(CYR.charAt((acc >> bits) & 31));
            }
            acc &= (1 << bits) - 1;
        }
        if (bits > 0) {
            sb.append(CYR.charAt((acc << (5 - bits)) & 31));
        }
        return sb.toString();
    }

    private static byte[] cyrDecode(String text) throws TriglyphException {
        String s = strip(text).toLowerCase().replace('ё', 'е');
        Util.Buf out = new Util.Buf();
        int acc = 0;
        int bits = 0;
        byte[] one = new byte[1];
        for (int i = 0; i < s.length(); i++) {
            int idx = CYR.indexOf(s.charAt(i));
            if (idx < 0) {
                throw new TriglyphException.Format("cyrillic armor: «" + s.charAt(i) + "» is not in the alphabet");
            }
            acc = (acc << 5) | idx;
            bits += 5;
            while (bits >= 8) {
                bits -= 8;
                one[0] = (byte) ((acc >> bits) & 0xFF);
                out.add(one);
            }
            acc &= (1 << bits) - 1;
        }
        byte[] payload = out.toBytes();
        if (payload.length < 2) {
            throw new TriglyphException.Format("cyrillic armor: too short");
        }
        byte[] data = Util.slice(payload, 0, payload.length - 2);
        byte[] got = Util.slice(payload, payload.length - 2);
        if (!Util.ctEquals(checksum(data, 2), got)) {
            throw new TriglyphException.Format("cyrillic armor: checksum mismatch");
        }
        return data;
    }

    // ------------------------------------------------------------------ latin

    public static String base64UrlEncode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i + 3 <= data.length) {
            int v = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8) | (data[i + 2] & 0xFF);
            sb.append(B64.charAt(v >> 18)).append(B64.charAt((v >> 12) & 63))
                    .append(B64.charAt((v >> 6) & 63)).append(B64.charAt(v & 63));
            i += 3;
        }
        int left = data.length - i;
        if (left == 1) {
            int v = (data[i] & 0xFF) << 16;
            sb.append(B64.charAt(v >> 18)).append(B64.charAt((v >> 12) & 63));
        } else if (left == 2) {
            int v = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8);
            sb.append(B64.charAt(v >> 18)).append(B64.charAt((v >> 12) & 63)).append(B64.charAt((v >> 6) & 63));
        }
        return sb.toString();
    }

    public static byte[] base64UrlDecode(String text) throws TriglyphException {
        String s = strip(text);
        Util.Buf out = new Util.Buf();
        int acc = 0;
        int bits = 0;
        byte[] one = new byte[1];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=') {
                continue;
            }
            if (c == '+') {
                c = '-';
            }
            if (c == '/') {
                c = '_';
            }
            int idx = B64.indexOf(c);
            if (idx < 0) {
                throw new TriglyphException.Format("latin armor: invalid base64 character '" + c + "'");
            }
            acc = (acc << 6) | idx;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                one[0] = (byte) ((acc >> bits) & 0xFF);
                out.add(one);
            }
            acc &= (1 << bits) - 1;
        }
        return out.toBytes();
    }

    // ---------------------------------------------------------------- grouped

    private static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int acc = 0;
        int bits = 0;
        for (byte b : data) {
            acc = (acc << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(B32.charAt((acc >> bits) & 31));
            }
            acc &= (1 << bits) - 1;
        }
        if (bits > 0) {
            sb.append(B32.charAt((acc << (5 - bits)) & 31));
        }
        return sb.toString();
    }

    private static byte[] base32Decode(String text) throws TriglyphException {
        String s = strip(text).replace("-", "").toUpperCase();
        Util.Buf out = new Util.Buf();
        int acc = 0;
        int bits = 0;
        byte[] one = new byte[1];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=') {
                continue;
            }
            int idx = B32.indexOf(c);
            if (idx < 0) {
                throw new TriglyphException.Format("grouped armor: invalid base32 character '" + c + "'");
            }
            acc = (acc << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                one[0] = (byte) ((acc >> bits) & 0xFF);
                out.add(one);
            }
            acc &= (1 << bits) - 1;
        }
        return out.toBytes();
    }

    private static String groupedEncode(byte[] data) {
        String raw = base32Encode(Util.concat(data, checksum(data, 2)));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i += 5) {
            if (i > 0) {
                sb.append('-');
            }
            sb.append(raw, i, Math.min(i + 5, raw.length()));
        }
        return sb.toString();
    }

    private static byte[] groupedDecode(String text) throws TriglyphException {
        byte[] payload = base32Decode(text);
        if (payload.length < 2) {
            throw new TriglyphException.Format("grouped armor: too short");
        }
        byte[] data = Util.slice(payload, 0, payload.length - 2);
        byte[] got = Util.slice(payload, payload.length - 2);
        if (!Util.ctEquals(checksum(data, 2), got)) {
            throw new TriglyphException.Format("grouped armor: checksum mismatch");
        }
        return data;
    }

    // ------------------------------------------------------- открытый интерфейс

    public static String encode(byte[] data, String kind) throws TriglyphException {
        if ("hanzi".equals(kind)) {
            return hanziEncode(data);
        }
        if ("cyrillic".equals(kind)) {
            return cyrEncode(data);
        }
        if ("latin".equals(kind)) {
            return base64UrlEncode(data);
        }
        if ("grouped".equals(kind)) {
            return groupedEncode(data);
        }
        throw new TriglyphException.Format("unknown armor '" + kind + "'");
    }

    public static byte[] decode(String text, String kind) throws TriglyphException {
        if ("hanzi".equals(kind)) {
            return hanziDecode(text);
        }
        if ("cyrillic".equals(kind)) {
            return cyrDecode(text);
        }
        if ("latin".equals(kind)) {
            return base64UrlDecode(text);
        }
        if ("grouped".equals(kind)) {
            return groupedDecode(text);
        }
        throw new TriglyphException.Format("unknown armor '" + kind + "'");
    }

    /** Автоопределение: сначала брони с контрольной суммой, base64 — последней. */
    public static byte[] decode(String text) throws TriglyphException {
        String[] order = {"hanzi", "cyrillic", "grouped", "latin"};
        TriglyphException last = null;
        for (String kind : order) {
            try {
                return decode(text, kind);
            } catch (TriglyphException exc) {
                last = exc;
            } catch (RuntimeException exc) {
                last = new TriglyphException.Format(String.valueOf(exc.getMessage()));
            }
        }
        throw new TriglyphException.Format(
                "cannot decode armor / не удалось разобрать броню: "
                        + (last == null ? "?" : last.getMessage()));
    }

    /** Определение вида брони по алфавиту (для подсказок в интерфейсе). */
    public static String detect(String text) {
        String s = strip(text);
        if (s.isEmpty()) {
            return "latin";
        }
        for (char m : HANZI_MARKS) {
            if (s.charAt(0) == m) {
                return "hanzi";
            }
        }
        int probe = Math.min(8, s.length());
        for (int i = 0; i < probe; i++) {
            int idx = s.charAt(i) - HANZI_BASE;
            if (idx >= 0 && idx < HANZI_COUNT) {
                return "hanzi";
            }
        }
        String head = s.substring(0, Math.min(16, s.length())).toLowerCase().replace('ё', 'е');
        boolean allCyr = head.length() > 0;
        for (int i = 0; i < head.length(); i++) {
            if (CYR.indexOf(head.charAt(i)) < 0) {
                allCyr = false;
                break;
            }
        }
        if (allCyr) {
            return "cyrillic";
        }
        if (s.indexOf('-') > 0 && s.toUpperCase().matches("[A-Z2-7]{5}(-[A-Z2-7]{5})*(-[A-Z2-7]{1,4})?")) {
            return "grouped";
        }
        return "latin";
    }

    public static String wrapLines(String text, int width) {
        if (width <= 0) {
            return text;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i += width) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append(text, i, Math.min(i + width, text.length()));
        }
        return sb.toString();
    }

    public static String wrapMessage(String armored) {
        return BEGIN_MARK + "\n" + armored + "\n" + END_MARK + "\n";
    }

    /** Извлекает броню из обёртки; терпима к «мусору» вокруг. */
    public static String unwrapMessage(String text) {
        if (!text.contains(BEGIN_MARK)) {
            return text.trim();
        }
        String body = text.substring(text.indexOf(BEGIN_MARK) + BEGIN_MARK.length());
        int end = body.indexOf(END_MARK);
        if (end >= 0) {
            body = body.substring(0, end);
        }
        StringBuilder sb = new StringBuilder();
        for (String line : body.trim().split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) {
                continue;
            }
            if (t.contains(":") && !t.startsWith("-") && sb.length() == 0 && t.indexOf(':') < 24) {
                continue; // заголовок вида «Ключ: значение»
            }
            sb.append(t);
        }
        return sb.toString();
    }
}
