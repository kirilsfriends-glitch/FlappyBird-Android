package ai.triglyph.core;

import java.security.SecureRandom;

/** Генератор паролей и парольных фраз с честной оценкой энтропии. */
public final class PasswordGen {

    private static final SecureRandom RNG = new SecureRandom();

    private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String DIGITS = "23456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

    /** Трёхъязычный словарь для парольных фраз: ровно 256 слов → 8 бит на слово. */
    private static final String[] WORDS = {
            "якорь", "берег", "ветер", "гроза", "долина", "ежевика", "жемчуг", "закат",
            "искра", "камень", "лавина", "молния", "невод", "облако", "парус", "радуга",
            "север", "туман", "утёс", "фонарь", "холод", "цапля", "чайка", "шторм",
            "щавель", "эхо", "юрта", "ясень", "берёза", "волна", "гранит", "дюна",
            "anchor", "bridge", "canyon", "delta", "ember", "forest", "glacier", "harbor",
            "island", "jungle", "kernel", "lantern", "meadow", "nebula", "orchid", "prairie",
            "quartz", "ridge", "summit", "tundra", "umbra", "valley", "willow", "xenon",
            "yarrow", "zenith", "amber", "basalt", "cinder", "dawn", "echo", "fjord",
            "山岳", "河流", "云海", "星辰", "竹林", "青松", "白鹤", "明月",
            "清风", "细雨", "晨曦", "暮色", "石桥", "古道", "红叶", "碧波",
            "长江", "黄河", "泰山", "西湖", "春雷", "夏荷", "秋霜", "冬雪",
            "银杏", "梅花", "兰草", "菊影", "墨砚", "琴弦", "棋盘", "书简",
            "агат", "бархат", "вереск", "гавань", "десна", "ельник", "жасмин", "звезда",
            "изумруд", "кедр", "ландыш", "мрамор", "нефрит", "омут", "пихта", "рябина",
            "сапфир", "топаз", "уголь", "фиалка", "хрусталь", "цитрин", "черника", "шафран",
            "щегол", "янтарь", "азимут", "барьер", "вектор", "градус", "диаметр", "единица",
            "falcon", "granite", "hollow", "indigo", "jasper", "kestrel", "lagoon", "marble",
            "nomad", "onyx", "pebble", "quiver", "raven", "saffron", "thistle", "upland",
            "vellum", "walnut", "yonder", "zephyr", "acorn", "beacon", "cobalt", "driftwood",
            "eagle", "fable", "garnet", "hearth", "ivory", "juniper", "kelp", "lichen",
            "松涛", "竹影", "荷塘", "枫桥", "玉门", "金沙", "铁壁", "云岭",
            "孤舟", "远山", "深谷", "幽兰", "寒潭", "暖阳", "微光", "流萤",
            "剑锋", "鼓声", "笛韵", "钟鸣", "灯火", "星河", "雪原", "沙丘",
            "海角", "天涯", "峡湾", "冰川", "熔岩", "苍穹", "旷野", "密林",
            "мираж", "оазис", "поток", "риф", "смерч", "тайга", "ураган", "фьорд",
            "хребет", "цунами", "чаща", "шквал", "эдельвейс", "юг", "ярус", "basil",
            "clover", "dogwood", "elm", "fennel", "ginger", "hazel", "iris", "jade",
            "laurel", "myrtle", "nutmeg", "olive", "poppy", "quince", "rosemary", "барс",
            "вьюга", "глина", "дозор", "ересь", "жнивьё", "зенит", "исток", "ковыль",
            "лемех", "медведь", "норка", "осока", "полынь", "рожь", "стужа", "терем",
            "улей", "фреска", "хмель", "цикорий", "чертог", "шелест", "щит", "astral",
            "boulder", "cedar", "dunes", "estuary", "flint", "gully", "hummock", "inlet",
    };

    private PasswordGen() {
    }

    /** Случайный пароль из выбранных наборов символов. */
    public static String password(int length, boolean upper, boolean digits, boolean symbols) {
        StringBuilder alphabet = new StringBuilder(LOWER);
        if (upper) {
            alphabet.append(UPPER);
        }
        if (digits) {
            alphabet.append(DIGITS);
        }
        if (symbols) {
            alphabet.append(SYMBOLS);
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(alphabet.charAt(RNG.nextInt(alphabet.length())));
        }
        return out.toString();
    }

    /** Парольная фраза: слова из трёхъязычного словаря по 8 бит каждое. */
    public static String passphrase(int words, String separator) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < words; i++) {
            if (i > 0) {
                out.append(separator);
            }
            out.append(WORDS[RNG.nextInt(WORDS.length)]);
        }
        return out.toString();
    }

    public static double passwordEntropyBits(int length, boolean upper, boolean digits, boolean symbols) {
        int n = LOWER.length() + (upper ? UPPER.length() : 0)
                + (digits ? DIGITS.length() : 0) + (symbols ? SYMBOLS.length() : 0);
        return length * (Math.log(n) / Math.log(2));
    }

    public static double passphraseEntropyBits(int words) {
        return words * (Math.log(WORDS.length) / Math.log(2));
    }

    public static int wordCount() {
        return WORDS.length;
    }
}
