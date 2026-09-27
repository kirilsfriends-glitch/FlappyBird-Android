package ai.triglyph;

import java.util.HashMap;
import java.util.Map;

/**
 * Трёхъязычный словарь интерфейса: русский, английский, китайский.
 *
 * <p>Строки держим в коде, а не в ресурсах с локалями, чтобы язык переключался
 * кнопкой внутри приложения независимо от языка системы.
 */
public final class Strings {

    public static final String[] LANGS = {"ru", "en", "zh"};
    public static final String[] LANG_LABELS = {"РУС", "ENG", "中文"};

    private static final Map<String, String[]> M = new HashMap<String, String[]>();
    private static int lang = 0;

    private Strings() {
    }

    private static void put(String key, String ru, String en, String zh) {
        M.put(key, new String[]{ru, en, zh});
    }

    public static void setLang(int index) {
        lang = index < 0 || index >= LANGS.length ? 0 : index;
    }

    public static int langIndex() {
        return lang;
    }

    public static String langCode() {
        return LANGS[lang];
    }

    public static String t(String key) {
        String[] v = M.get(key);
        return v == null ? key : v[lang];
    }

    static {
        put("app.title", "ТРИГЛИФ", "TRIGLYPH", "三纹密码");
        put("app.subtitle",
                "Каскадный шифр: XChaCha20 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512",
                "Cascade cipher: XChaCha20 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512",
                "级联密码：XChaCha20 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512");

        put("tab.text", "Текст", "Text", "文本");
        put("tab.file", "Файлы", "Files", "文件");
        put("tab.keys", "Ключи", "Keys", "密钥");
        put("tab.share", "Части", "Shares", "分片");
        put("tab.about", "Проверка", "Check", "自检");

        put("text.input", "Сообщение или броня", "Message or armored text", "消息或密文");
        put("text.hint.plain", "Введите текст на любом языке…", "Type a message in any language…",
                "输入任意语言的文字…");
        put("text.password", "Пароль", "Password", "口令");
        put("text.password.hint", "длинный пароль или фраза", "a long password or passphrase",
                "较长的口令或短语");
        put("text.suite", "Каскад", "Suite", "级联");
        put("text.profile", "Стойкость KDF", "KDF strength", "密钥派生强度");
        put("text.armor", "Броня", "Armor", "外壳");
        put("text.pad", "Скрывать длину", "Hide length", "隐藏长度");
        put("text.stealth", "Без сигнатуры", "No signature", "隐藏标识");
        put("btn.encrypt", "Зашифровать", "Encrypt", "加密");
        put("btn.decrypt", "Расшифровать", "Decrypt", "解密");
        put("btn.copy", "Копировать", "Copy", "复制");
        put("btn.paste", "Вставить", "Paste", "粘贴");
        put("btn.share", "Поделиться", "Share", "分享");
        put("btn.clear", "Очистить", "Clear", "清空");
        put("btn.swap", "Результат → вход", "Result → input", "结果 → 输入");
        put("out.title", "Результат", "Result", "结果");
        put("out.empty", "— пусто —", "— empty —", "— 空 —");

        put("msg.copied", "Скопировано в буфер обмена", "Copied to clipboard", "已复制到剪贴板");
        put("msg.pasted", "Вставлено из буфера", "Pasted from clipboard", "已从剪贴板粘贴");
        put("msg.working", "Считаем ключ… это должно быть медленно",
                "Deriving the key… slow on purpose", "正在派生密钥…故意很慢");
        put("msg.need.text", "Сначала введите текст", "Enter some text first", "请先输入文字");
        put("msg.need.password", "Введите пароль", "Enter a password", "请输入口令");
        put("msg.done.enc", "Зашифровано за %d мс, %d знаков",
                "Encrypted in %d ms, %d characters", "加密完成，用时 %d 毫秒，%d 个字符");
        put("msg.done.dec", "Расшифровано за %d мс", "Decrypted in %d ms", "解密完成，用时 %d 毫秒");
        put("msg.fail.integrity",
                "Не сходится: неверный пароль либо текст повреждён или подделан",
                "Mismatch: wrong password, or the text is damaged or forged",
                "校验失败：口令错误，或密文被损坏/伪造");
        put("msg.fail.format", "Это не похоже на контейнер ТРИГЛИФ",
                "This does not look like a TRIGLYPH container", "这看起来不是三纹密码容器");
        put("msg.error", "Ошибка", "Error", "错误");

        put("file.pick", "Выбрать файл", "Pick a file", "选择文件");
        put("file.encrypt", "Зашифровать файл", "Encrypt file", "加密文件");
        put("file.decrypt", "Расшифровать файл", "Decrypt file", "解密文件");
        put("file.none", "Файл не выбран", "No file selected", "未选择文件");
        put("file.saved", "Сохранено: %s", "Saved: %s", "已保存：%s");
        put("file.selected", "Выбрано: %s (%s)", "Selected: %s (%s)", "已选择：%s（%s）");
        put("file.inspect", "Что внутри", "Inspect", "查看内容");
        put("file.hint",
                "Файлы шифруются потоково фрагментами по 64 КиБ; приложению не нужны никакие разрешения — доступ выдаёт системный выбор файла.",
                "Files are processed in 64 KiB chunks; the app needs no permissions — the system file picker grants access.",
                "文件按 64 KiB 分块处理；应用无需任何权限——由系统文件选择器授权。");

        put("keys.title", "Пара ключей X25519", "X25519 key pair", "X25519 密钥对");
        put("keys.generate", "Создать пару", "Generate pair", "生成密钥对");
        put("keys.public", "Открытый ключ (можно публиковать)",
                "Public key (safe to publish)", "公钥（可公开）");
        put("keys.private", "Закрытый ключ (никому)", "Private key (never share)", "私钥（切勿外传）");
        put("keys.hint",
                "Ключи живут только в памяти приложения и исчезают при закрытии. Сохраните их сами.",
                "Keys live in memory only and vanish when the app closes. Save them yourself.",
                "密钥仅存于内存，应用关闭即消失，请自行保存。");
        put("keys.to.recipient", "Зашифровать на открытый ключ",
                "Encrypt to a public key", "用公钥加密");
        put("keys.recipient.hint", "открытый ключ получателя", "recipient public key", "收件人公钥");
        put("pwgen.title", "Генератор паролей", "Password generator", "口令生成器");
        put("pwgen.length", "Длина", "Length", "长度");
        put("pwgen.words", "Слов во фразе", "Words in passphrase", "短语词数");
        put("pwgen.make", "Пароль", "Password", "口令");
        put("pwgen.phrase", "Фраза", "Passphrase", "短语");
        put("pwgen.entropy", "Энтропия: %.0f бит", "Entropy: %.0f bits", "熵：%.0f 比特");
        put("pwgen.use", "Подставить в пароль", "Use as password", "用作口令");

        put("share.title", "Разделение секрета (Шамир)", "Secret sharing (Shamir)", "秘密分享（Shamir）");
        put("share.secret", "Секрет", "Secret", "秘密");
        put("share.threshold", "Порог", "Threshold", "阈值");
        put("share.total", "Всего частей", "Total shares", "分片总数");
        put("share.split", "Разрезать", "Split", "拆分");
        put("share.combine", "Собрать", "Combine", "合并");
        put("share.parts", "Части (по одной в строке)", "Shares (one per line)", "分片（每行一个）");
        put("share.hint",
                "Любые «порог» частей восстановят секрет, меньше — не дадут о нём ни бита.",
                "Any «threshold» shares recover the secret; fewer reveal literally nothing.",
                "任意达到阈值数量的分片可恢复秘密，少于阈值则一无所获。");

        put("about.selftest", "Запустить самопроверку", "Run self-check", "运行自检");
        put("about.running", "Проверяем эталонные векторы…", "Verifying reference vectors…",
                "正在校验参考向量…");
        put("about.ok", "Все проверки пройдены: %d", "All checks passed: %d", "全部通过：%d 项");
        put("about.fail", "Провалено проверок: %d", "Failed checks: %d", "失败：%d 项");
        put("about.vectors",
                "Векторы получены из Python-версии TRIGLYPH и вшиты в приложение: если приложение их проходит, оно совместимо байт в байт.",
                "The vectors come from the Python TRIGLYPH and are bundled in the app: passing them proves byte-for-byte compatibility.",
                "参考向量取自 Python 版三纹密码并内置于应用：通过即证明逐字节兼容。");
        put("about.text",
                "TRIGLYPH шифрует текст и файлы тремя независимыми слоями сразу. Чтобы прочесть сообщение, противнику придётся сломать XChaCha20, AES-256 и Threefish-1024 одновременно, а затем ещё подделать HMAC-SHA3-512.",
                "TRIGLYPH encrypts text and files under three independent layers at once. To read a message an adversary must break XChaCha20, AES-256 and Threefish-1024 simultaneously, and then forge HMAC-SHA3-512 on top.",
                "三纹密码同时使用三层独立加密。攻击者必须同时攻破 XChaCha20、AES-256 与 Threefish-1024，还要伪造 HMAC-SHA3-512。");
        put("about.perm", "Разрешений: ноль. Сети нет.", "Permissions: none. No network.",
                "权限：零。无网络。");
        put("about.version", "Формат TRIGLYPH/1 · ядро на чистой Java",
                "Format TRIGLYPH/1 · pure Java core", "格式 TRIGLYPH/1 · 纯 Java 内核");
    }
}
