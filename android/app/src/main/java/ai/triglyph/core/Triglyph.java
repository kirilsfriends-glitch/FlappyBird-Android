package ai.triglyph.core;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Каскадный AEAD-контейнер TRIGLYPH/1 — тот же формат, что и в Python-версии.
 *
 * <pre>
 *   открытый текст
 *     ① XChaCha20-Poly1305  → ② AES-256-GCM → ③ Threefish-1024-CTR
 *     ④ HMAC-SHA3-512 поверх всего контейнера (Encrypt-then-MAC)
 * </pre>
 */
public final class Triglyph {

    public static final byte[] MAGIC = {'T', 'R', 'G', 'L', 'Y', 'P', 'H', 1};
    public static final int VERSION = 1;

    public static final int SUITE_TRIPLE = 1;
    public static final int SUITE_DUAL = 2;
    public static final int SUITE_SOLO = 3;

    public static final int MODE_PASSWORD = 1;
    public static final int MODE_X25519_ANON = 2;
    public static final int MODE_X25519_AUTH = 3;
    public static final int MODE_RAWKEY = 4;

    public static final int FLAG_PADDED_WHOLE = 1;
    public static final int FLAG_PADDED_LAST = 1 << 1;
    public static final int FLAG_HAS_AAD = 1 << 2;
    public static final int FLAG_STREAM = 1 << 3;

    public static final int DEFAULT_CHUNK = 1 << 16;
    public static final int SALT_SIZE = 32;
    public static final int MAC_SIZE = 64;
    public static final int MAX_CHUNK = 1 << 24;

    private static final String[] PROFILE_ORDER = {"fast", "balanced", "hard", "paranoid"};

    private Triglyph() {
    }

    public static int suiteId(String name) throws TriglyphException {
        if ("triple".equals(name)) {
            return SUITE_TRIPLE;
        }
        if ("dual".equals(name)) {
            return SUITE_DUAL;
        }
        if ("solo".equals(name)) {
            return SUITE_SOLO;
        }
        throw new TriglyphException.Format("unknown suite '" + name + "'");
    }

    public static String suiteName(int id) {
        if (id == SUITE_TRIPLE) {
            return "triple";
        }
        if (id == SUITE_DUAL) {
            return "dual";
        }
        return id == SUITE_SOLO ? "solo" : "?";
    }

    public static String suiteLayers(int id) {
        if (id == SUITE_TRIPLE) {
            return "XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024-CTR → HMAC-SHA3-512";
        }
        if (id == SUITE_DUAL) {
            return "XChaCha20-Poly1305 → AES-256-GCM → HMAC-SHA3-512";
        }
        return id == SUITE_SOLO ? "XChaCha20-Poly1305 → HMAC-SHA3-512" : "?";
    }

    public static int profileId(String name) throws TriglyphException {
        for (int i = 0; i < PROFILE_ORDER.length; i++) {
            if (PROFILE_ORDER[i].equals(name)) {
                return i;
            }
        }
        throw new TriglyphException.Format("unknown KDF profile '" + name + "'");
    }

    public static String profileName(int id) throws TriglyphException {
        if (id < 0 || id >= PROFILE_ORDER.length) {
            throw new TriglyphException.Format("unknown KDF profile id " + id);
        }
        return PROFILE_ORDER[id];
    }

    public static String modeName(int mode) {
        switch (mode) {
            case MODE_PASSWORD:
                return "password";
            case MODE_X25519_ANON:
                return "x25519-anonymous";
            case MODE_X25519_AUTH:
                return "x25519-authenticated";
            case MODE_RAWKEY:
                return "raw-key";
            default:
                return "?";
        }
    }

    public static byte[] utf8(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException exc) {
            throw new IllegalStateException(exc);
        }
    }

    public static String fromUtf8(byte[] b) {
        try {
            return new String(b, "UTF-8");
        } catch (UnsupportedEncodingException exc) {
            throw new IllegalStateException(exc);
        }
    }

    // ------------------------------------------------------------------ заголовок

    /** Заголовок контейнера. */
    public static final class Header {
        public int version = VERSION;
        public int suite = SUITE_TRIPLE;
        public int mode = MODE_PASSWORD;
        public int kdfId = Kdf.KDF_SCRYPT;
        public int profileId = 1;
        public int padPolicy = TextUtil.PAD_PADME;
        public int flags = 0;
        public int chunkSize = DEFAULT_CHUNK;
        public byte[] salt = new byte[0];
        public byte[] ephPub = new byte[0];
        public byte[] senderPub = new byte[0];
        public byte[] recipientHint = new byte[0];
        public byte[] aad = new byte[0];
        public byte[] commitment = new byte[0];

        public byte[] prefixBytes() {
            return Util.concat(
                    MAGIC,
                    Util.u8(version), Util.u8(suite), Util.u8(mode), Util.u8(kdfId),
                    Util.u8(profileId), Util.u8(padPolicy),
                    Util.u16(flags), Util.u32(chunkSize),
                    Util.lenPrefixed(salt), Util.lenPrefixed(ephPub), Util.lenPrefixed(senderPub),
                    Util.lenPrefixed(recipientHint), Util.lenPrefixed(aad));
        }

        public byte[] toBytes() throws TriglyphException {
            if (commitment.length != 32) {
                throw new TriglyphException.Format("commitment must be 32 bytes");
            }
            return Util.concat(prefixBytes(), commitment);
        }

        /** Человекочитаемое описание для интерфейса. */
        public Map<String, String> describe() {
            Map<String, String> m = new LinkedHashMap<String, String>();
            m.put("version", String.valueOf(version));
            m.put("suite", suiteName(suite));
            m.put("layers", suiteLayers(suite));
            m.put("mode", modeName(mode));
            m.put("kdf", kdfId == Kdf.KDF_SCRYPT ? "scrypt+pbkdf2"
                    : (kdfId == Kdf.KDF_ARGON2ID ? "argon2id+pbkdf2" : "hkdf"));
            m.put("profile", profileId >= 0 && profileId < PROFILE_ORDER.length
                    ? PROFILE_ORDER[profileId] : "custom");
            String pad = padPolicy == TextUtil.PAD_NONE ? "none"
                    : padPolicy == TextUtil.PAD_PADME ? "padme"
                    : padPolicy == TextUtil.PAD_BUCKET ? "bucket" : "fixed";
            m.put("pad_policy", pad);
            m.put("chunk_size", String.valueOf(chunkSize));
            m.put("salt", Util.hex(salt));
            if (ephPub.length > 0) {
                m.put("ephemeral_public_key", Util.hex(ephPub));
            }
            if (senderPub.length > 0) {
                m.put("sender_public_key", Util.hex(senderPub));
            }
            if (aad.length > 0) {
                m.put("aad", fromUtf8(aad));
            }
            m.put("key_commitment", Util.hex(commitment));
            m.put("streaming", String.valueOf((flags & FLAG_STREAM) != 0));
            return m;
        }
    }

    /** Курсор чтения с проверкой границ. */
    private static final class Reader {
        private final byte[] data;
        private int off;

        Reader(byte[] data) {
            this.data = data;
        }

        byte[] take(int n) throws TriglyphException {
            if (n < 0 || off + n > data.length) {
                throw new TriglyphException.Format("unexpected end of container");
            }
            byte[] out = Util.slice(data, off, off + n);
            off += n;
            return out;
        }

        int u8() throws TriglyphException {
            return take(1)[0] & 0xFF;
        }

        int u16() throws TriglyphException {
            byte[] b = take(2);
            return Util.readU16(b, 0);
        }

        long u32() throws TriglyphException {
            byte[] b = take(4);
            return Util.readU32(b, 0);
        }

        byte[] lenPref() throws TriglyphException {
            long n = u32();
            if (n > MAX_CHUNK) {
                throw new TriglyphException.Format("field too large");
            }
            return take((int) n);
        }

        boolean eof() {
            return off >= data.length;
        }
    }

    /** Разобранный заголовок и его длина в байтах. */
    public static final class ParsedHeader {
        public final Header header;
        public final int length;

        ParsedHeader(Header header, int length) {
            this.header = header;
            this.length = length;
        }
    }

    public static ParsedHeader parseHeader(byte[] blob) throws TriglyphException {
        Reader r = new Reader(blob);
        byte[] magic = r.take(8);
        if (!Util.ctEquals(magic, MAGIC)) {
            throw new TriglyphException.Format(
                    "это не контейнер TRIGLYPH (неверная сигнатура) / not a TRIGLYPH container");
        }
        Header h = new Header();
        h.version = r.u8();
        if (h.version != VERSION) {
            throw new TriglyphException.Format("unsupported container version " + h.version);
        }
        h.suite = r.u8();
        h.mode = r.u8();
        h.kdfId = r.u8();
        h.profileId = r.u8();
        h.padPolicy = r.u8();
        h.flags = r.u16();
        long cs = r.u32();
        if (cs < 1 || cs > MAX_CHUNK) {
            throw new TriglyphException.Format("invalid chunk size " + cs);
        }
        h.chunkSize = (int) cs;
        h.salt = r.lenPref();
        h.ephPub = r.lenPref();
        h.senderPub = r.lenPref();
        h.recipientHint = r.lenPref();
        h.aad = r.lenPref();
        h.commitment = r.take(32);
        if (h.suite < 1 || h.suite > 3) {
            throw new TriglyphException.Format("unknown cipher suite " + h.suite);
        }
        if (h.mode < 1 || h.mode > 4) {
            throw new TriglyphException.Format("unknown key mode " + h.mode);
        }
        return new ParsedHeader(h, r.off);
    }

    // ------------------------------------------------------------------- слои

    private static byte[] sealChunk(Kdf.KeySchedule ks, int suite, long index, boolean fin,
                                    byte[] hdrHash, byte[] pt) throws TriglyphException {
        byte[] aad = Util.concat(hdrHash, Util.u64(index), Util.u8(fin ? 1 : 0));
        byte[] out = Chacha.xAeadEncrypt(ks.get("l1"), ks.nonceFor("L1", index, 24), pt, aad);
        if (suite == SUITE_TRIPLE || suite == SUITE_DUAL) {
            out = Aes.gcmEncrypt(ks.get("l2"), ks.nonceFor("L2", index, 12), out, aad);
        }
        if (suite == SUITE_TRIPLE) {
            out = Threefish.ctrXor(ks.get("l3"), ks.nonceFor("L3", index, 16), out);
        }
        return out;
    }

    private static byte[] openChunk(Kdf.KeySchedule ks, int suite, long index, boolean fin,
                                    byte[] hdrHash, byte[] ct) throws TriglyphException {
        byte[] aad = Util.concat(hdrHash, Util.u64(index), Util.u8(fin ? 1 : 0));
        byte[] data = ct;
        if (suite == SUITE_TRIPLE) {
            data = Threefish.ctrXor(ks.get("l3"), ks.nonceFor("L3", index, 16), data);
        }
        if (suite == SUITE_TRIPLE || suite == SUITE_DUAL) {
            data = Aes.gcmDecrypt(ks.get("l2"), ks.nonceFor("L2", index, 12), data, aad);
        }
        return Chacha.xAeadDecrypt(ks.get("l1"), ks.nonceFor("L1", index, 24), data, aad);
    }

    /** Внешний HMAC-SHA3-512 поверх заголовка и всех фрагментов. */
    private static final class OuterMac {
        private final byte[] key;
        private final Util.Buf buf = new Util.Buf();
        private long count = 0;

        OuterMac(byte[] key, byte[] headerBytes) {
            this.key = key;
            buf.add(Kdf.ascii("TRIGLYPH/v1|outer|"));
            buf.add(Util.u32(headerBytes.length));
            buf.add(headerBytes);
        }

        void addChunk(long index, boolean fin, byte[] ct) {
            buf.add(Util.u64(index));
            buf.add(Util.u8(fin ? 1 : 0));
            buf.add(Util.u32(ct.length));
            buf.add(ct);
            count++;
        }

        byte[] finish() {
            buf.add(Kdf.ascii("|end|"));
            buf.add(Util.u64(count));
            return Keccak.hmacSha3_512(key, buf.toBytes());
        }
    }

    // --------------------------------------------------------------- параметры

    /** Параметры шифрования (значения по умолчанию совпадают с Python-версией). */
    public static final class Options {
        public String suite = "triple";
        public String profile = "balanced";
        public int pad = TextUtil.PAD_PADME;
        public byte[] aad = new byte[0];
        public int chunkSize = DEFAULT_CHUNK;
        public byte[] pepper = new byte[0];
        public boolean stealth = false;

        public Options suite(String s) {
            this.suite = s;
            return this;
        }

        public Options profile(String p) {
            this.profile = p;
            return this;
        }

        public Options pad(int p) {
            this.pad = p;
            return this;
        }

        public Options aad(byte[] a) {
            this.aad = a == null ? new byte[0] : a;
            return this;
        }

        public Options stealth(boolean s) {
            this.stealth = s;
            return this;
        }

        public Options pepper(byte[] p) {
            this.pepper = p == null ? new byte[0] : p;
            return this;
        }
    }

    /** Ключевой материал: ровно один из способов. */
    public static final class KeyMaterial {
        byte[] password;
        byte[] rawKey;
        byte[] recipientPub;
        byte[] senderPriv;
        byte[] privateKey;
        byte[] expectSender;

        public static KeyMaterial password(String pw) {
            KeyMaterial k = new KeyMaterial();
            k.password = Kdf.normalizePassword(pw);
            return k;
        }

        public static KeyMaterial passwordBytes(byte[] pw) {
            KeyMaterial k = new KeyMaterial();
            k.password = pw;
            return k;
        }

        public static KeyMaterial rawKey(byte[] key) {
            KeyMaterial k = new KeyMaterial();
            k.rawKey = key;
            return k;
        }

        public static KeyMaterial recipient(byte[] recipientPub) {
            KeyMaterial k = new KeyMaterial();
            k.recipientPub = recipientPub;
            return k;
        }

        public KeyMaterial signedBy(byte[] senderPrivate) {
            this.senderPriv = senderPrivate;
            return this;
        }

        public static KeyMaterial privateKey(byte[] priv) {
            KeyMaterial k = new KeyMaterial();
            k.privateKey = priv;
            return k;
        }

        public KeyMaterial expectSender(byte[] pub) {
            this.expectSender = pub;
            return this;
        }
    }

    // ------------------------------------------------------------- шифрование

    public static byte[] encrypt(byte[] data, KeyMaterial km, Options opt) throws TriglyphException {
        if (opt == null) {
            opt = new Options();
        }
        int sources = (km.password != null ? 1 : 0) + (km.rawKey != null ? 1 : 0)
                + (km.recipientPub != null ? 1 : 0);
        if (sources != 1) {
            throw new TriglyphException.Crypto(
                    "выберите ровно один источник ключа: пароль, ключ или получатель");
        }
        Kdf.Profile prof = Kdf.profile(opt.profile);

        Header h = new Header();
        h.suite = suiteId(opt.suite);
        h.profileId = profileId(opt.profile);
        h.padPolicy = opt.pad;
        h.chunkSize = opt.chunkSize;
        h.salt = Util.random(SALT_SIZE);
        h.aad = opt.aad;
        if (h.aad.length > 0) {
            h.flags |= FLAG_HAS_AAD;
        }

        byte[] master;
        if (km.password != null) {
            h.mode = MODE_PASSWORD;
            h.kdfId = Kdf.KDF_SCRYPT;
            master = Kdf.deriveMasterSecret(km.password, h.salt, prof, h.kdfId, opt.pepper);
        } else if (km.rawKey != null) {
            if (km.rawKey.length < 32) {
                throw new TriglyphException.Crypto("raw key must be at least 32 bytes");
            }
            h.mode = MODE_RAWKEY;
            h.kdfId = Kdf.KDF_RAW;
            master = Kdf.hkdf(km.rawKey, h.salt, Kdf.ascii("TRIGLYPH/v1|rawkey"), 64);
        } else {
            if (km.recipientPub.length != 32) {
                throw new TriglyphException.Crypto("recipient X25519 public key must be 32 bytes");
            }
            h.mode = km.senderPriv != null ? MODE_X25519_AUTH : MODE_X25519_ANON;
            h.kdfId = Kdf.KDF_RAW;
            byte[] esk = X25519.generatePrivateKey();
            byte[] epk = X25519.basePointMult(esk);
            h.ephPub = epk;
            byte[] ikm = Util.concat(X25519.sharedSecret(esk, km.recipientPub), epk, km.recipientPub);
            if (h.mode == MODE_X25519_AUTH) {
                if (km.senderPriv.length != 32) {
                    throw new TriglyphException.Crypto("sender private key must be 32 bytes");
                }
                byte[] spk = X25519.basePointMult(km.senderPriv);
                h.senderPub = spk;
                ikm = Util.concat(ikm, X25519.sharedSecret(km.senderPriv, km.recipientPub), spk);
            }
            master = Kdf.hkdf(ikm, h.salt, Kdf.ascii("TRIGLYPH/v1|x25519"), 64);
        }

        byte[] payload = data;
        if (opt.pad != TextUtil.PAD_NONE) {
            payload = TextUtil.pad(data, opt.pad, 0);
            h.flags |= FLAG_PADDED_WHOLE;
        }

        Kdf.KeySchedule ks = new Kdf.KeySchedule(master, h.prefixBytes());
        try {
            h.commitment = ks.commitment();
            byte[] headerBytes = h.toBytes();
            byte[] hdrHash = Keccak.sha3_256(headerBytes);
            OuterMac mac = new OuterMac(ks.get("mac"), headerBytes);

            Util.Buf out = new Util.Buf();
            out.add(headerBytes);
            int nchunks = Math.max(1, (payload.length + opt.chunkSize - 1) / opt.chunkSize);
            for (int i = 0; i < nchunks; i++) {
                int from = i * opt.chunkSize;
                int to = Math.min(payload.length, from + opt.chunkSize);
                byte[] piece = Util.slice(payload, from, Math.max(from, to));
                boolean fin = i == nchunks - 1;
                byte[] ct = sealChunk(ks, h.suite, i, fin, hdrHash, piece);
                mac.addChunk(i, fin, ct);
                out.add(Util.u32(ct.length));
                out.add(ct);
            }
            out.add(mac.finish());
            byte[] blob = out.toBytes();
            return opt.stealth ? Stealth.wrap(blob) : blob;
        } finally {
            ks.destroy();
        }
    }

    // ----------------------------------------------------------- расшифрование

    public static byte[] decrypt(byte[] blobIn, KeyMaterial km) throws TriglyphException {
        byte[] blob = blobIn;
        boolean hasMagic = blob.length >= 8 && Util.ctEquals(Util.slice(blob, 0, 8), MAGIC);
        if (!hasMagic && Stealth.looksStealth(blob, MAGIC)) {
            blob = Stealth.unwrap(blob);
        }
        ParsedHeader ph = parseHeader(blob);
        Header h = ph.header;
        if (km.expectSender != null && !Util.ctEquals(km.expectSender, h.senderPub)) {
            throw new TriglyphException.Integrity("sender public key does not match the expected one");
        }

        byte[] master;
        if (h.mode == MODE_PASSWORD) {
            if (km.password == null) {
                throw new TriglyphException.Crypto("password required");
            }
            Kdf.Profile prof = Kdf.profile(profileName(h.profileId));
            master = Kdf.deriveMasterSecret(km.password, h.salt, prof, h.kdfId, new byte[0]);
        } else if (h.mode == MODE_RAWKEY) {
            if (km.rawKey == null) {
                throw new TriglyphException.Crypto("raw key required");
            }
            master = Kdf.hkdf(km.rawKey, h.salt, Kdf.ascii("TRIGLYPH/v1|rawkey"), 64);
        } else {
            if (km.privateKey == null || km.privateKey.length != 32) {
                throw new TriglyphException.Crypto("recipient private key (32 bytes) required");
            }
            byte[] myPub = X25519.basePointMult(km.privateKey);
            byte[] ikm = Util.concat(X25519.sharedSecret(km.privateKey, h.ephPub), h.ephPub, myPub);
            if (h.mode == MODE_X25519_AUTH) {
                if (h.senderPub.length != 32) {
                    throw new TriglyphException.Format("authenticated mode without sender public key");
                }
                ikm = Util.concat(ikm, X25519.sharedSecret(km.privateKey, h.senderPub), h.senderPub);
            }
            master = Kdf.hkdf(ikm, h.salt, Kdf.ascii("TRIGLYPH/v1|x25519"), 64);
        }

        Kdf.KeySchedule ks = new Kdf.KeySchedule(master, h.prefixBytes());
        try {
            if (!Util.ctEquals(ks.commitment(), h.commitment)) {
                throw new TriglyphException.Integrity(
                        "неверный ключ или пароль / wrong key or password (key commitment)");
            }
            byte[] headerBytes = Util.slice(blob, 0, ph.length);
            byte[] hdrHash = Keccak.sha3_256(headerBytes);
            OuterMac mac = new OuterMac(ks.get("mac"), headerBytes);

            if (blob.length < ph.length + MAC_SIZE) {
                throw new TriglyphException.Format("container truncated");
            }
            byte[] body = Util.slice(blob, ph.length, blob.length - MAC_SIZE);
            byte[] tailMac = Util.slice(blob, blob.length - MAC_SIZE);

            Reader r = new Reader(body);
            List<byte[]> chunks = new ArrayList<byte[]>();
            while (!r.eof()) {
                long ln = r.u32();
                if (ln > MAX_CHUNK + 1024) {
                    throw new TriglyphException.Format("chunk length out of range");
                }
                chunks.add(r.take((int) ln));
            }
            if (chunks.isEmpty()) {
                throw new TriglyphException.Format("container has no chunks");
            }
            for (int i = 0; i < chunks.size(); i++) {
                mac.addChunk(i, i == chunks.size() - 1, chunks.get(i));
            }
            if (!Util.ctEquals(mac.finish(), tailMac)) {
                throw new TriglyphException.Integrity(
                        "контейнер повреждён или подделан / container tampered (HMAC-SHA3-512)");
            }

            Util.Buf out = new Util.Buf();
            int last = chunks.size() - 1;
            for (int i = 0; i < chunks.size(); i++) {
                byte[] piece = openChunk(ks, h.suite, i, i == last, hdrHash, chunks.get(i));
                if (i == last && (h.flags & FLAG_PADDED_LAST) != 0) {
                    piece = TextUtil.unpad(piece);
                }
                out.add(piece);
            }
            byte[] data = out.toBytes();
            if ((h.flags & FLAG_PADDED_WHOLE) != 0) {
                data = TextUtil.unpad(data);
            }
            return data;
        } finally {
            ks.destroy();
        }
    }

    // --------------------------------------------------------- текстовый режим

    /** Шифрует строку и возвращает её в текстовой броне. */
    public static String encryptText(String text, KeyMaterial km, Options opt, String armorKind)
            throws TriglyphException {
        String norm = TextUtil.normalize(text);
        String kind = armorKind;
        if (kind == null || "auto".equals(kind)) {
            String lang = TextUtil.detectLanguage(norm);
            kind = "zh".equals(lang) ? "hanzi" : ("ru".equals(lang) ? "cyrillic" : "latin");
        }
        byte[] blob = encrypt(utf8(norm), km, opt);
        return Armor.encode(blob, kind);
    }

    public static String decryptText(String armored, KeyMaterial km) throws TriglyphException {
        String payload = Armor.unwrapMessage(armored);
        byte[] blob = Armor.decode(payload);
        return fromUtf8(decrypt(blob, km));
    }

    /** Разбор заголовка без ключа — для экрана «что это за файл». */
    public static Map<String, String> inspect(byte[] blobIn) throws TriglyphException {
        byte[] blob = blobIn;
        boolean hasMagic = blob.length >= 8 && Util.ctEquals(Util.slice(blob, 0, 8), MAGIC);
        boolean stealth = false;
        if (!hasMagic && Stealth.looksStealth(blob, MAGIC)) {
            blob = Stealth.unwrap(blob);
            stealth = true;
        }
        ParsedHeader ph = parseHeader(blob);
        Map<String, String> m = ph.header.describe();
        m.put("stealth", String.valueOf(stealth));
        m.put("container_size", String.valueOf(blobIn.length));
        long overhead = blobIn.length - Math.max(0, blob.length - ph.length - MAC_SIZE);
        m.put("overhead", String.valueOf(overhead));
        return m;
    }
}
