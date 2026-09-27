package ai.triglyph.core;

/**
 * Стелс-оболочка: контейнер без узнаваемой сигнатуры.
 *
 * <p>На контейнер накладывается гамма SHAKE-256, выведенная из открытого
 * случайного префикса. Это обфускация формата, а НЕ дополнительный шифр:
 * стойкости не добавляет ни бита, только прячет сигнатуру от grep.
 */
public final class Stealth {

    public static final int PREFIX_SIZE = 32;
    private static final int BLOCK = 1 << 16;
    private static final byte[] DOMAIN = Kdf.ascii("TRIGLYPH/v1|stealth|");

    private Stealth() {
    }

    public static byte[] maskBlock(byte[] prefix, long index, int length) {
        return Keccak.shake256(Util.concat(DOMAIN, prefix, Util.u64(index)), length);
    }

    private static byte[] mask(byte[] prefix, byte[] data, int off, int len) {
        byte[] out = new byte[len];
        int pos = 0;
        long index = 0;
        while (pos < len) {
            int take = Math.min(BLOCK, len - pos);
            byte[] gamma = maskBlock(prefix, index, take);
            for (int i = 0; i < take; i++) {
                out[pos + i] = (byte) (data[off + pos + i] ^ gamma[i]);
            }
            pos += take;
            index++;
        }
        return out;
    }

    public static byte[] wrap(byte[] container) {
        byte[] prefix = Util.random(PREFIX_SIZE);
        return Util.concat(prefix, mask(prefix, container, 0, container.length));
    }

    public static byte[] unwrap(byte[] blob) throws TriglyphException {
        if (blob.length < PREFIX_SIZE) {
            throw new TriglyphException.Format("stealth container too short");
        }
        byte[] prefix = Util.slice(blob, 0, PREFIX_SIZE);
        return mask(prefix, blob, PREFIX_SIZE, blob.length - PREFIX_SIZE);
    }

    /** Похоже ли на стелс-обёртку над контейнером TRIGLYPH. */
    public static boolean looksStealth(byte[] blob, byte[] magic) {
        if (blob.length < PREFIX_SIZE + magic.length) {
            return false;
        }
        byte[] prefix = Util.slice(blob, 0, PREFIX_SIZE);
        byte[] gamma = maskBlock(prefix, 0, magic.length);
        for (int i = 0; i < magic.length; i++) {
            if ((byte) (blob[PREFIX_SIZE + i] ^ gamma[i]) != magic[i]) {
                return false;
            }
        }
        return true;
    }
}
