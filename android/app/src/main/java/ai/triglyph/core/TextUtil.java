package ai.triglyph.core;

import java.text.Normalizer;

/** Работа с текстом: нормализация, определение письменности, сокрытие длины. */
public final class TextUtil {

    public static final int PAD_NONE = 0;
    public static final int PAD_PADME = 1;
    public static final int PAD_BUCKET = 2;
    public static final int PAD_FIXED = 3;

    private TextUtil() {
    }

    /** NFC — каноническая форма перед шифрованием (важно для «й», «ё», CJK). */
    public static String normalize(String text) {
        return Normalizer.normalize(text, Normalizer.Form.NFC);
    }

    public static boolean isHan(int cp) {
        return (cp >= 0x4E00 && cp <= 0x9FFF)
                || (cp >= 0x3400 && cp <= 0x4DBF)
                || (cp >= 0xF900 && cp <= 0xFAFF)
                || (cp >= 0x20000 && cp <= 0x2FA1F)
                || (cp >= 0x3000 && cp <= 0x303F);
    }

    /** Грубая эвристика по письменности: "zh" | "ru" | "en" | "mixed" | "unknown". */
    public static String detectLanguage(String text) {
        int han = 0;
        int cyr = 0;
        int lat = 0;
        int other = 0;
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            if (Character.isDigit(cp)) {
                continue;
            }
            boolean han0 = isHan(cp);
            if (!Character.isLetter(cp) && !han0) {
                continue;
            }
            if (han0) {
                han++;
            } else if ((cp >= 0x0400 && cp <= 0x04FF) || (cp >= 0x0500 && cp <= 0x052F)) {
                cyr++;
            } else if (cp < 0x0250) {
                lat++;
            } else {
                other++;
            }
        }
        int total = han + cyr + lat + other;
        if (total == 0) {
            return "unknown";
        }
        double zh = (double) han / total;
        double ru = (double) cyr / total;
        double en = (double) lat / total;
        double best = Math.max(zh, Math.max(ru, en));
        if (best < 0.6) {
            return "mixed";
        }
        if (best == zh) {
            return "zh";
        }
        return best == ru ? "ru" : "en";
    }

    /** Padmé (PETS 2019): округление длины вверх с потерей ≤ ~12 %. */
    public static long padme(long length) {
        if (length <= 1) {
            return Math.max(length, 1);
        }
        int e = 63 - Long.numberOfLeadingZeros(length);
        int s = e > 0 ? (31 - Integer.numberOfLeadingZeros(e)) + 1 : 1;
        int z = Math.max(e - s, 0);
        long mask = (1L << z) - 1;
        return (length + mask) & ~mask;
    }

    /** Языковые корзины: 256 → 512 → 1024 … одинаковая длина для zh/ru/en. */
    public static long bucket(long length) {
        if (length <= 256) {
            return 256;
        }
        long n = 256;
        while (n < length) {
            n *= 2;
        }
        return n;
    }

    /** Добавляет длину (u64) и набивку согласно политике. */
    public static byte[] pad(byte[] data, int policy, int block) throws TriglyphException {
        byte[] body = Util.concat(Util.u64(data.length), data);
        long target;
        if (policy == PAD_NONE) {
            target = body.length;
        } else if (policy == PAD_PADME) {
            target = padme(body.length);
        } else if (policy == PAD_BUCKET) {
            target = bucket(body.length);
        } else if (policy == PAD_FIXED) {
            if (block <= 0) {
                throw new TriglyphException.Format("PAD_FIXED requires block > 0");
            }
            target = ((body.length + block - 1L) / block) * block;
        } else {
            throw new TriglyphException.Format("unknown padding policy " + policy);
        }
        byte[] out = new byte[(int) target];
        System.arraycopy(body, 0, out, 0, body.length);
        return out;
    }

    public static byte[] unpad(byte[] padded) throws TriglyphException {
        if (padded.length < 8) {
            throw new TriglyphException.Format("padded plaintext too short");
        }
        long n = Util.readU64(padded, 0);
        if (n < 0 || n > padded.length - 8) {
            throw new TriglyphException.Format("declared plaintext length exceeds container");
        }
        return Util.slice(padded, 8, (int) (8 + n));
    }
}
