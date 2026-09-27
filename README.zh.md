# TRIGLYPH · ТРИГЛИФ · 三纹密码

**面向中文、俄文、英文的级联密码。**
纯 Python 实现，零外部依赖，全部原语均通过官方测试向量校验。

[🇷🇺 Русский](README.md) · [🇬🇧 English](README.en.md) · 🇨🇳 中文 · [格式规范](docs/SPEC.md) · [威胁模型](docs/THREAT_MODEL.md)

```
                    明文
                     │
   ①  XChaCha20-Poly1305 │  256 位密钥，192 位随机数，128 位标签
                     ▼
   ②  AES-256-GCM        │  独立 256 位密钥，128 位标签
                     ▼
   ③  Threefish-1024-CTR │  独立 1024 位密钥，80 轮
                     ▼
   ④  HMAC-SHA3-512      │  对整个容器做认证
                     ▼
                    密文
```

每一层的密钥都由 HKDF-SHA512 加域分离独立派生。要还原明文，攻击者必须**同时攻破三种密码**：
任何单一算法被完全攻破，消息依然安全。

---

## 为什么不直接用 AES

通用库加密的是*字节*。多语种文本会从字节密码根本不看的地方泄露信息：

| 泄露点 | 攻击者能看到什么 | TRIGLYPH 的做法 |
|---|---|---|
| **长度** | UTF-8 中一个汉字 3 字节、西里尔 2 字节、拉丁 1 字节，密文长度直接暴露语种 | Padmé 填充 + 语言分桶：`黎明时分进攻`、`Атака на рассвете`、`Attack at dawn` 得到**完全相同**的容器大小 |
| **规范化** | `й` 可能是 U+0439，也可能是 U+0438+U+0306；中文输入法会产生全角字符。同一口令派生出不同密钥 | 文本用 NFC、口令用 NFKC，在任何密码学操作之前完成 |
| **传输** | Base64 永远一眼就能认出 | 汉字装甲（每字 12 位）、西里尔装甲（每字母 5 位）、拉丁装甲 |
| **特征字节** | 魔数让容器可被 grep 直接搜出 | 隐身外壳：输出在统计上与随机噪声无法区分 |
| **口令爆破** | 非拉丁口令若不规范化会损失熵 | 三级 KDF：SHA3-512 → scrypt（内存）→ PBKDF2-SHA512（时间） |

---

## 快速上手

只需 Python 3.9+，无需安装任何依赖。

```bash
git clone https://github.com/kirilsfriends-glitch/FlappyBird-Android.git
cd FlappyBird-Android
python3 -m triglyph --lang zh selftest -v      # 按官方向量做 32 项检查
```

```bash
# 文本进，装甲文本出；装甲类型按语种自动选择
$ python3 -m triglyph --lang zh enc -m "黎明时分发起进攻" -p "密码"
㊁卅假勅坐劀企丐企一倀丐丁一一一丠剏孧坤埢坿修哚圯厀凹寥妎嫊争噉咬仭伙咓借嬫夀…

$ echo "$密文" | python3 -m triglyph dec -i - -p "密码"
黎明时分发起进攻

# 任意大小的文件，流式处理，内存恒定
$ python3 -m triglyph encf 报告.pdf 报告.tgl -p 口令 --profile hard
$ python3 -m triglyph decf 报告.tgl 报告.pdf -p 口令

# 公钥模式，并对发件人做认证
$ python3 -m triglyph keygen -o alice
$ python3 -m triglyph enc -m "你好" --to alice.pub --sign bob.key -o msg.tgl
$ python3 -m triglyph dec -i msg.tgl --identity alice.key --expect-sender bob.pub

# 把密钥切成 5 份，任意 3 份可还原
$ python3 -m triglyph split -k 3 -n 5 --secret "主密钥" --armor hanzi

# 不知道口令也能查看容器头部
$ python3 -m triglyph inspect -i 报告.tgl --json
```

命令行界面完整翻译：`--lang zh`、`--lang ru`、`--lang en`。

```python
import triglyph

armored = triglyph.encrypt_text("黎明时分进攻 Attack at dawn", password="密码")
print(triglyph.decrypt_text(armored, password="密码"))

blob = triglyph.encrypt(data, password="密码", suite="triple",
                        profile="hard", aad="账单42".encode(), stealth=True)

priv, pub = triglyph.generate_keypair()
box = triglyph.encrypt("给收件人".encode(), recipient=pub)
assert triglyph.decrypt(box, private_key=priv).decode() == "给收件人"
```

网页演示（三语界面，可在浏览器中运行全部自检）：

```bash
python3 web/server.py     # http://localhost:8000
```

---

## 组成部分

| 组件 | 实现 | 校验依据 |
|---|---|---|
| 流密码 | ChaCha20、HChaCha20、**XChaCha20** | RFC 8439 §2.3.2、§2.4.2；draft-irtf-cfrg-xchacha §2.2.1 |
| 认证码 | Poly1305 | RFC 8439 §2.5.2 |
| AEAD | ChaCha20-Poly1305、XChaCha20-Poly1305 | RFC 8439 §2.8.2 |
| 分组密码 | AES-128/192/256（S 盒由 GF(2⁸) 现算，不写死常量） | FIPS-197 附录 C.1–C.3 |
| AEAD 模式 | AES-GCM（GHASH 使用 4 位窗口表） | McGrew & Viega 测试用例 13–14 |
| 第三层 | Threefish-1024-CTR，80 轮 | 可逆性、雪崩效应、调柄敏感性 |
| 密钥派生 | HKDF-SHA512 | RFC 5869 TC1、TC3 |
| 口令 KDF | SHA3-512 → scrypt → PBKDF2-SHA512 | 确定性、盐与“胡椒”绑定 |
| 非对称 | X25519（蒙哥马利阶梯） | RFC 7748 §5.2、§6.1 |
| 秘密分割 | GF(2⁸) 上的沙米尔门限 | 所有 K/N 组合，K−1 时拒绝 |
| 密钥承诺 | 对专用子密钥做 SHA3-256 | 容器无法在第二个密钥下打开 |

若系统已安装 `cryptography`（OpenSSL、AES-NI），第 ①② 层会自动加速，但**必须**在
导入时用随机向量与内置参考实现逐字节比对通过才会启用。容器格式与后端无关。

---

## 安全性质

* **保密性** —— 三种独立密钥的密码级联。
* **完整性** —— Poly1305、GCM 标签与 HMAC-SHA3-512；重排、重放、截断、头部降级均可检出。
* **密钥承诺** —— 不存在能打开同一容器的第二个密钥。
* **随机数安全** —— 每条消息使用全新的 32 字节随机盐派生随机数。
* **元数据** —— 隐藏长度（因而隐藏语种）；默认隐藏收件人；格式特征也可隐藏。

坦率的局限：未经独立审计；相对 CPU 缓存并非常数时间；隐身只是混淆而非加密；
X25519 不抗量子；Python 无法保证密钥擦除。详见
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。

---

## 性能

在容器内 2 核、纯 Python、未启用加速器下实测：

| 组合 | 层次 | 加密 | 解密 |
|---|---|---|---|
| `solo` | XChaCha20-Poly1305 + HMAC | 1.06 MB/s | 1.10 MB/s |
| `dual` | + AES-256-GCM | 0.47 MB/s | 0.46 MB/s |
| `triple` | + Threefish-1024 | 0.21 MB/s | 0.20 MB/s |

| KDF 档位 | 内存 | 时间 |
|---|---|---|
| `fast` | 8 MiB | 39 ms |
| `balanced` | 64 MiB | 365 ms |
| `hard` | 256 MiB | 1.4 s |
| `paranoid` | 1 GiB | 7.5 s |

对于消息场景，耗时由 KDF 而非密码决定。处理数 GB 文件请使用
`--suite dual` 或 `solo`，或安装 `cryptography`。

## 参考向量

`docs/test-vectors.json` 收录 60 个现成容器及其密钥与期望明文。它们固定在仓库中：
一旦改动破坏格式兼容性，`tests/test_vectors_file.py` 就会失败；其他语言的实现
也可以用同一文件自检。

```bash
python3 tools/verify_vectors.py -v
```

## 测试

```bash
python3 -m unittest discover -s tests -v    # 116 项测试
python3 -m triglyph selftest -v             # 32 项官方向量检查
python3 -m triglyph bench                   # 本机吞吐量
```

测试同样验证那些**必须失败**的情形：翻转容器中的每个字节、截断、追加、
重排分片、降级组合、错误发件人、装甲丢字符、只有 K−1 份秘密份额。

## 许可证

MIT，见 [LICENSE](LICENSE)。

> **警告。** 这是一个未经审计的独立密码学实现。它基于标准且被公开分析过的算法，
> 并与官方测试向量一致；但若性命攸关，请使用经过审计的工具（age、GnuPG、libsodium）。
