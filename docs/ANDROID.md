# Приложение для Android · Android app · 安卓应用

**[⬇ Скачать APK / Download APK / 下载 APK](https://github.com/kirilsfriends-glitch/FlappyBird-Android/releases/latest)**

Тот же шифр, что и в Python-версии, целиком переписанный на Java и упакованный
в приложение размером ~140 КБ, которое **не просит ни одного разрешения**.

---

## Что умеет

| Вкладка | Что делает |
|---|---|
| **Текст** | Шифрует и расшифровывает сообщения; броня (иероглифы / кириллица / латиница / группы по 5) подбирается под язык автоматически; кнопки «копировать», «поделиться», «вставить» |
| **Файлы** | Шифрует любой файл, выбранный через системный диалог; показывает заголовок чужого контейнера, не зная пароля |
| **Ключи** | Создаёт пару X25519 для переписки без общего пароля; шифрует на чужой открытый ключ с подписью своим закрытым; генератор паролей и трёхъязычных парольных фраз с честной оценкой энтропии |
| **Части** | Разделение секрета по Шамиру: любые *k* из *n* частей восстанавливают его, меньше — не дают ни бита |
| **Проверка** | Прогоняет 300+ эталонных векторов, вшитых в приложение, и показывает результат по группам |

Язык интерфейса — РУС / ENG / 中文 — переключается кнопкой в правом верхнем углу
и не зависит от языка системы.

## Чего в приложении нет

* **Ни одного разрешения** в манифесте — в том числе `INTERNET`. Приложение
  физически не может ничего никуда отправить; это проверяется в CI:
  сборка падает, если в готовом APK найдётся хоть одна строка `uses-permission`.
* Нет аналитики, рекламы, счётчиков, облака, аккаунтов.
* Нет доступа к файловой системе: файл выбираете вы сами, системный диалог
  выдаёт приложению разовый доступ ровно к нему.
* Ключи и пароли не сохраняются: они живут в памяти процесса и исчезают
  вместе с ним.

## Совместимость с Python-версией

Формат контейнера один и тот же — `TRIGLYPH/1`. Что зашифровано в приложении,
открывается командой `python -m triglyph dec`, и наоборот. Это не обещание,
а проверка в CI на каждый коммит:

1. `javac` собирает ядро, `SelfCheck` прогоняет плоский файл эталонных
   векторов `docs/test-vectors.txt`, созданный Python-версией: хеши, ChaCha20,
   Poly1305, AES-GCM, Threefish-1024, scrypt, PBKDF2, HKDF, X25519, броня,
   60 готовых контейнеров;
2. Java шифрует набор сообщений (три языка × три сюиты × три политики набивки,
   плюс пароль, стелс и многофрагментный файл), а Python их расшифровывает
   и заодно проверяет, что порченый контейнер отвергается.

## Почему ядро написано заново, а не взято из платформы

| Что нужно | Что есть в Android | Что сделано |
|---|---|---|
| SHA3-256/512, SHAKE-256 | только с API 29 | своя реализация Keccak-f[1600] |
| PBKDF2-HMAC-SHA512 | `SecretKeyFactory` только с API 26 | свой PBKDF2 поверх `Mac` |
| scrypt | нет вообще | своя реализация (Salsa20/8 + ROMix) |
| X25519 | `XDH` только с API 33 | лестница Монтгомери на `BigInteger` |
| AES-256-GCM | есть с API 19, аппаратное ускорение | используется платформенное |
| ChaCha20, Poly1305, Threefish-1024 | нет | свои реализации |

Поэтому приложение работает начиная с **Android 5.0 (API 21)**.

## Сборка своими руками

```bash
cd android
# нужен Android SDK (compileSdk 34) и JDK 17
gradle assembleRelease        # или ./gradlew, если добавите wrapper
# готовый файл: app/build/outputs/apk/release/app-release.apk
```

Ядро можно собрать и проверить вообще без Android SDK — обычным JDK:

```bash
mkdir -p out/classes
javac -encoding UTF-8 -d out/classes $(find android/app/src/main/java/ai/triglyph/core -name '*.java')
java -cp out/classes ai.triglyph.core.SelfCheck docs/test-vectors.txt
```

Релизный APK подписан отладочным ключом — иначе Android отказался бы его
устанавливать. Это значит: **подпись не удостоверяет автора**, проверяйте
файл по SHA-256 из заметок к релизу.

---

## English

The same cipher as the Python version, rewritten in Java, packed into a ~140 KB
app that **requests zero permissions** — not even `INTERNET`. CI fails the build
if a single `uses-permission` line shows up in the finished APK.

Tabs: **Text** (encrypt/decrypt messages, armor auto-selected by language),
**Files** (encrypt any file via the system picker; inspect a container header
without the password), **Keys** (X25519 pairs, encrypt to a public key,
password/passphrase generator), **Shares** (Shamir *k*-of-*n*), **Check**
(runs 300+ reference vectors bundled with the app).

Container format is identical to the Python implementation, and every commit
proves it: Java verifies Python's vectors, then Python opens containers made by
Java. Minimum Android version: 5.0 (API 21).

---

## 中文

与 Python 版本完全相同的密码方案，用 Java 重写，打包为约 140 KB 的应用，
**不申请任何权限**——连 `INTERNET` 都没有。持续集成会检查成品 APK：
只要出现一行 `uses-permission`，构建即失败。

五个标签页：**文本**（加解密消息，按语种自动选择外壳）、**文件**（通过系统选择器
加密任意文件，也可在不知口令的情况下查看容器头部）、**密钥**（X25519 密钥对、
用公钥加密、口令与短语生成器）、**分片**（Shamir *k*/*n* 秘密分享）、
**自检**（运行内置的 300 多组参考向量）。

容器格式与 Python 实现完全一致，并由持续集成逐次提交验证：Java 先校验 Python
生成的向量，Python 再解密 Java 生成的容器。最低系统版本：Android 5.0（API 21）。
