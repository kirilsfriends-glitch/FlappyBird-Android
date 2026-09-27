"""
triglyph.i18n — интерфейс на трёх языках: русский, English, 中文.

Язык выбирается флагом --lang, переменной TRIGLYPH_LANG или системной LANG.
Ключи хранятся как кортежи (ru, en, zh).
"""

from __future__ import annotations

import os
from typing import Dict, Tuple

__all__ = ["set_lang", "get_lang", "t", "LANGS"]

LANGS = ("ru", "en", "zh")
_current = "ru"

STRINGS: Dict[str, Tuple[str, str, str]] = {
    # --- общее ---
    "app.desc": (
        "TRIGLYPH — каскадный шифр для китайского, русского и английского: "
        "XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512",
        "TRIGLYPH — cascade cipher for Chinese, Russian and English: "
        "XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512",
        "三纹密码 TRIGLYPH — 面向中文、俄文、英文的级联密码："
        "XChaCha20-Poly1305 → AES-256-GCM → Threefish-1024 → HMAC-SHA3-512",
    ),
    "app.epilog": (
        "Примеры:\n"
        "  triglyph enc -m 'Атака на рассвете' -p тайна\n"
        "  triglyph enc -m '黎明时分进攻' --armor hanzi\n"
        "  triglyph enc -i отчёт.pdf -o отчёт.tgl --profile hard\n"
        "  triglyph keygen -o alice && triglyph enc -m 'hi' --to alice.pub\n"
        "  triglyph selftest -v",
        "Examples:\n"
        "  triglyph enc -m 'Attack at dawn' -p secret\n"
        "  triglyph enc -m '黎明时分进攻' --armor hanzi\n"
        "  triglyph enc -i report.pdf -o report.tgl --profile hard\n"
        "  triglyph keygen -o alice && triglyph enc -m 'hi' --to alice.pub\n"
        "  triglyph selftest -v",
        "示例：\n"
        "  triglyph enc -m '黎明时分进攻' --armor hanzi\n"
        "  triglyph enc -i 报告.pdf -o 报告.tgl --profile hard\n"
        "  triglyph keygen -o alice && triglyph enc -m '你好' --to alice.pub\n"
        "  triglyph selftest -v",
    ),
    "cmd.encrypt": ("зашифровать текст или файл", "encrypt text or a file", "加密文本或文件"),
    "cmd.decrypt": ("расшифровать текст или файл", "decrypt text or a file", "解密文本或文件"),
    "cmd.keygen": ("создать пару ключей X25519", "generate an X25519 key pair", "生成 X25519 密钥对"),
    "cmd.randkey": ("создать случайный симметричный ключ", "generate a random symmetric key", "生成随机对称密钥"),
    "cmd.inspect": ("показать параметры контейнера без ключа", "show container parameters without a key", "无需密钥查看容器参数"),
    "cmd.split": ("разрезать секрет на части (схема Шамира)", "split a secret into shares (Shamir)", "分割秘密（沙米尔门限）"),
    "cmd.combine": ("собрать секрет из частей", "combine shares back into a secret", "由份额还原秘密"),
    "cmd.selftest": ("самопроверка на официальных тест-векторах", "self-test against official test vectors", "按官方测试向量自检"),
    "cmd.bench": ("измерить скорость на этой машине", "measure speed on this machine", "测量本机速度"),
    "cmd.armor": ("перекодировать данные в броню и обратно", "convert data to/from armor", "数据与装甲编码互转"),
    "cmd.passgen": ("сгенерировать стойкий пароль", "generate a strong passphrase", "生成高强度口令"),
    # --- опции ---
    "opt.lang": ("язык интерфейса", "interface language", "界面语言"),
    "opt.message": ("текст сообщения", "message text", "消息文本"),
    "opt.infile": ("входной файл ('-' = стандартный ввод)", "input file ('-' = stdin)", "输入文件（'-' 表示标准输入）"),
    "opt.outfile": ("выходной файл ('-' = стандартный вывод)", "output file ('-' = stdout)", "输出文件（'-' 表示标准输出）"),
    "opt.password": ("пароль (небезопасно: виден в истории команд)", "password (unsafe: visible in shell history)", "口令（不安全：会留在命令历史中）"),
    "opt.passfile": ("файл с паролем (первая строка)", "file containing the password (first line)", "包含口令的文件（第一行）"),
    "opt.passenv": ("имя переменной окружения с паролем", "environment variable holding the password", "存放口令的环境变量名"),
    "opt.keyfile": ("файл с сырым ключом (>= 32 байт)", "file with a raw key (>= 32 bytes)", "原始密钥文件（≥32 字节）"),
    "opt.keyfile2": ("файл-ключ как дополнительный «перец» к паролю", "key file used as an extra pepper for the password", "作为口令附加“胡椒”的密钥文件"),
    "opt.to": ("публичный ключ получателя (файл или hex)", "recipient public key (file or hex)", "收件人公钥（文件或十六进制）"),
    "opt.identity": ("файл с секретным ключом X25519", "file with the X25519 private key", "X25519 私钥文件"),
    "opt.sign": ("подписать отправителем: файл его секретного ключа", "authenticate sender: file with their private key", "发件人认证：其私钥文件"),
    "opt.expect": ("требовать конкретного отправителя (публичный ключ)", "require this sender public key", "要求指定发件人公钥"),
    "opt.suite": ("набор слоёв каскада", "cascade suite", "级联组合"),
    "opt.profile": ("стойкость вывода ключа из пароля", "password hardening profile", "口令强化档位"),
    "opt.armor": ("вид брони для текстового вывода", "armor for textual output", "文本输出的装甲类型"),
    "opt.pad": ("политика сокрытия длины", "length-hiding policy", "长度隐藏策略"),
    "opt.stealth": ("скрыть сигнатуру формата (обфускация, не шифр)", "hide the format signature (obfuscation, not encryption)", "隐藏格式特征（仅混淆，非加密）"),
    "opt.aad": ("открытые связанные данные (аутентифицируются)", "associated data (authenticated, not secret)", "关联数据（参与认证，不保密）"),
    "opt.wrap": ("переносить броню через N символов", "wrap armor at N characters", "每 N 个字符换行"),
    "opt.envelope": ("обрамить броню заголовками BEGIN/END", "wrap armor in BEGIN/END markers", "添加 BEGIN/END 包装"),
    "opt.json": ("вывод в формате JSON", "JSON output", "JSON 输出"),
    "opt.verbose": ("подробный вывод", "verbose output", "详细输出"),
    "opt.force": ("перезаписать существующий файл", "overwrite an existing file", "覆盖已存在的文件"),
    # --- сообщения ---
    "msg.password_prompt": ("Пароль: ", "Password: ", "口令："),
    "msg.password_repeat": ("Повторите пароль: ", "Repeat password: ", "再次输入口令："),
    "msg.password_mismatch": ("Пароли не совпадают.", "Passwords do not match.", "两次输入的口令不一致。"),
    "msg.password_empty": ("Пустой пароль недопустим.", "An empty password is not allowed.", "口令不能为空。"),
    "msg.password_weak": (
        "Внимание: пароль короткий. Оценка энтропии ≈ {bits} бит.",
        "Warning: short password. Estimated entropy ≈ {bits} bits.",
        "警告：口令较短，估计熵约 {bits} 比特。",
    ),
    "msg.no_key_source": (
        "Укажите источник ключа: --password / --key-file / --to (получатель).",
        "Specify a key source: --password / --key-file / --to (recipient).",
        "请指定密钥来源：--password / --key-file / --to（收件人）。",
    ),
    "msg.encrypted": (
        "Зашифровано: {inp} → {out} ({size} байт, сюита {suite}, профиль {profile})",
        "Encrypted: {inp} → {out} ({size} bytes, suite {suite}, profile {profile})",
        "已加密：{inp} → {out}（{size} 字节，组合 {suite}，档位 {profile}）",
    ),
    "msg.decrypted": (
        "Расшифровано и проверено: {inp} → {out} ({size} байт)",
        "Decrypted and verified: {inp} → {out} ({size} bytes)",
        "已解密并验证：{inp} → {out}（{size} 字节）",
    ),
    "msg.integrity_fail": (
        "ОШИБКА ЦЕЛОСТНОСТИ: {err}\n"
        "Либо пароль/ключ неверен, либо контейнер изменён. Открытый текст не выдаётся.",
        "INTEGRITY FAILURE: {err}\n"
        "Either the key is wrong or the container was modified. No plaintext is released.",
        "完整性校验失败：{err}\n口令/密钥错误，或容器已被篡改。不会输出明文。",
    ),
    "msg.keys_written": (
        "Секретный ключ: {sk} (chmod 600)\nПубличный ключ: {pk}\n{pub}",
        "Private key: {sk} (chmod 600)\nPublic key: {pk}\n{pub}",
        "私钥：{sk}（chmod 600）\n公钥：{pk}\n{pub}",
    ),
    "msg.file_exists": (
        "Файл {path} уже существует (используйте --force).",
        "File {path} already exists (use --force).",
        "文件 {path} 已存在（可用 --force 覆盖）。",
    ),
    "msg.shares_hint": (
        "Порог {k} из {n}: любые {k} частей восстановят секрет, {k1} — не дадут ничего.",
        "Threshold {k} of {n}: any {k} shares restore the secret, {k1} reveal nothing.",
        "门限 {k}/{n}：任意 {k} 份可还原秘密，{k1} 份泄露为零。",
    ),
    "msg.bench_header": (
        "Скорость на этой машине (чистый Python, бэкенд: {backend})",
        "Throughput on this machine (pure Python, backend: {backend})",
        "本机吞吐量（纯 Python，后端：{backend}）",
    ),
    "msg.selftest_ok": ("Самопроверка пройдена.", "Self-test passed.", "自检通过。"),
    "msg.selftest_fail": ("САМОПРОВЕРКА ПРОВАЛЕНА.", "SELF-TEST FAILED.", "自检未通过。"),
    "msg.detected_lang": ("Язык исходного текста: {lang}", "Detected language: {lang}", "检测到的语言：{lang}"),
    "msg.entropy": ("Энтропия: {bits} бит", "Entropy: {bits} bits", "熵：{bits} 比特"),
    "msg.large_file_hint": (
        "Подсказка: файл большой. Сюита 'solo' быстрее втрое при той же стойкости "
        "по современным меркам; 'triple' — максимальный запас прочности.",
        "Hint: large input. Suite 'solo' is ~3× faster with solid modern security; "
        "'triple' gives the largest safety margin.",
        "提示：文件较大。'solo' 组合约快三倍且安全性依然稳健；'triple' 余量最大。",
    ),
}


def set_lang(lang: str | None) -> str:
    global _current
    if lang and lang.lower()[:2] in LANGS:
        _current = lang.lower()[:2]
        return _current
    env = os.environ.get("TRIGLYPH_LANG") or os.environ.get("LANG") or ""
    env = env.lower()
    if env.startswith("zh"):
        _current = "zh"
    elif env.startswith("en"):
        _current = "en"
    else:
        _current = "ru"
    return _current


def get_lang() -> str:
    return _current


def t(key: str, **fmt) -> str:
    entry = STRINGS.get(key)
    if entry is None:
        return key
    idx = LANGS.index(_current)
    s = entry[idx]
    return s.format(**fmt) if fmt else s
