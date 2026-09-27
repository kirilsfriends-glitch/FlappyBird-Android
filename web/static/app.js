"use strict";

/* ------------------------------------------------------------------ */
/* Локализация интерфейса: русский / English / 中文                     */
/* ------------------------------------------------------------------ */
const I18N = {
  ru: {
    plainTitle: "Открытый текст", cipherTitle: "Шифртекст", samples: "Примеры:",
    password: "Пароль", generate: "Сгенерировать", suite: "Каскад", profile: "Профиль KDF",
    armor: "Броня", hidelen: "Скрывать длину (язык не виден)",
    stealth: "Стелс: убрать сигнатуру формата",
    encrypt: "Зашифровать →", decrypt: "← Расшифровать", copy: "Копировать",
    inspect: "Разобрать заголовок", clear: "Очистить",
    shamirTitle: "Разделение секрета (схема Шамира)",
    shamirHint: "Ключ режется на N частей: любые K восстановят его, K−1 не дадут ничего (информационно-теоретическая стойкость).",
    split: "Разрезать", combine: "Собрать из отмеченных",
    selftestTitle: "Самопроверка на официальных тест-векторах",
    selftestHint: "RFC 8439 (ChaCha20/Poly1305), FIPS-197 (AES), NIST GCM, RFC 5869 (HKDF), RFC 7748 (X25519) плюс сквозные проверки контейнера.",
    runtests: "Запустить проверки",
    footer1: "Демонстрационный сервер: пароль уходит на сервер в теле запроса. Для настоящей работы используйте CLI (python -m triglyph) или библиотеку.",
    placeholder: "Введите сообщение…", cipherPlaceholder: "Здесь появится броня…",
    encrypted: "Зашифровано за", decrypted: "Расшифровано и проверено за",
    ms: "мс", bytes: "байт", chars: "знаков", lang: "язык",
    working: "Считаю…", copied: "Скопировано", needText: "Введите текст",
    needPassword: "Введите пароль", entropyLbl: "энтропия пароля",
    splitDone: "Части готовы. Отметьте любые K и нажмите «Собрать».",
    combineNeed: "Отметьте хотя бы K частей.", secretIs: "Секрет:",
    testsPassed: "проверок пройдено", weak: "слабый", ok: "хороший", strong: "отличный",
  },
  en: {
    plainTitle: "Plaintext", cipherTitle: "Ciphertext", samples: "Samples:",
    password: "Password", generate: "Generate", suite: "Cascade", profile: "KDF profile",
    armor: "Armor", hidelen: "Hide length (language stays secret)",
    stealth: "Stealth: strip the format signature",
    encrypt: "Encrypt →", decrypt: "← Decrypt", copy: "Copy",
    inspect: "Inspect header", clear: "Clear",
    shamirTitle: "Secret sharing (Shamir)",
    shamirHint: "The key is split into N shares: any K restore it, K−1 reveal nothing (information-theoretic security).",
    split: "Split", combine: "Combine selected",
    selftestTitle: "Self-test against official test vectors",
    selftestHint: "RFC 8439 (ChaCha20/Poly1305), FIPS-197 (AES), NIST GCM, RFC 5869 (HKDF), RFC 7748 (X25519) plus end-to-end container checks.",
    runtests: "Run checks",
    footer1: "Demo server: the password travels to the server in the request body. For real work use the CLI (python -m triglyph) or the library.",
    placeholder: "Type a message…", cipherPlaceholder: "Armored ciphertext appears here…",
    encrypted: "Encrypted in", decrypted: "Decrypted and verified in",
    ms: "ms", bytes: "bytes", chars: "chars", lang: "language",
    working: "Working…", copied: "Copied", needText: "Enter some text",
    needPassword: "Enter a password", entropyLbl: "password entropy",
    splitDone: "Shares ready. Tick any K and press Combine.",
    combineNeed: "Tick at least K shares.", secretIs: "Secret:",
    testsPassed: "checks passed", weak: "weak", ok: "fine", strong: "strong",
  },
  zh: {
    plainTitle: "明文", cipherTitle: "密文", samples: "示例：",
    password: "口令", generate: "生成", suite: "级联", profile: "KDF 档位",
    armor: "装甲编码", hidelen: "隐藏长度（不泄露语种）",
    stealth: "隐身：去除格式特征",
    encrypt: "加密 →", decrypt: "← 解密", copy: "复制",
    inspect: "解析头部", clear: "清空",
    shamirTitle: "秘密分割（沙米尔门限）",
    shamirHint: "密钥被分成 N 份：任意 K 份可还原，K−1 份毫无信息（信息论安全）。",
    split: "分割", combine: "合并所选",
    selftestTitle: "按官方测试向量自检",
    selftestHint: "RFC 8439（ChaCha20/Poly1305）、FIPS-197（AES）、NIST GCM、RFC 5869（HKDF）、RFC 7748（X25519），以及容器端到端检查。",
    runtests: "运行检查",
    footer1: "演示服务器：口令会随请求发送到服务端。实际使用请用命令行（python -m triglyph）或库。",
    placeholder: "请输入消息……", cipherPlaceholder: "装甲密文将显示在这里……",
    encrypted: "加密耗时", decrypted: "解密并验证，耗时",
    ms: "毫秒", bytes: "字节", chars: "字符", lang: "语种",
    working: "计算中……", copied: "已复制", needText: "请输入文本",
    needPassword: "请输入口令", entropyLbl: "口令熵",
    splitDone: "份额已生成。勾选任意 K 份后点击“合并”。",
    combineNeed: "请至少勾选 K 份。", secretIs: "秘密：",
    testsPassed: "项检查通过", weak: "偏弱", ok: "尚可", strong: "很强",
  },
};

const SAMPLES = {
  zh: "黎明时分发起进攻。联络点已暴露，请从第三个楼梯撤离，密码是「三纹」。",
  ru: "Атака начнётся на рассвете. Явка провалена — уходи через третий подъезд.",
  en: "The attack begins at dawn. The safe house is blown; leave by the third stairwell.",
  mix: "Пароль: 密码 · password. Встреча в 07:45 у 北门, bring the 钥匙.",
};

let LANG = "ru";
const $ = (id) => document.getElementById(id);
const T = (k) => (I18N[LANG] && I18N[LANG][k]) || I18N.ru[k] || k;

function applyLang() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = T(el.dataset.i18n);
  });
  $("plain").placeholder = T("placeholder");
  $("cipher").placeholder = T("cipherPlaceholder");
  document.querySelectorAll("#langswitch button").forEach((b) =>
    b.classList.toggle("active", b.dataset.lang === LANG));
  updateEntropy();
  updatePlainMeta();
}

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */
async function api(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });
  return res.json();
}

function setStatus(msg, kind) {
  const el = $("status");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

function renderInfo(info) {
  const rows = Object.entries(info || {})
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `<tr><td>${k}</td><td>${String(v)}</td></tr>`)
    .join("");
  $("info").innerHTML = rows;
}

/* ------------------------------------------------------------------ */
/* Метрики                                                             */
/* ------------------------------------------------------------------ */
function updatePlainMeta() {
  const s = $("plain").value;
  const bytes = new TextEncoder().encode(s).length;
  $("plain-meta").textContent = `${s.length} ${T("chars")} · ${bytes} ${T("bytes")} UTF-8`;
}

function updateEntropy() {
  const pw = $("password").value;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes += 26;
  if (/[A-Z]/.test(pw)) classes += 26;
  if (/[0-9]/.test(pw)) classes += 10;
  if (/[^\p{L}\p{N}]/u.test(pw)) classes += 32;
  if (/[\u0400-\u04FF]/.test(pw)) classes += 66;
  if (/[\u4E00-\u9FFF]/.test(pw)) classes += 3000;
  const bits = Math.round(pw.length * Math.log2(Math.max(classes, 2)));
  const pct = Math.max(2, Math.min(100, bits / 1.28));
  const bar = $("entropy-bar");
  bar.style.width = pct + "%";
  bar.style.background = bits < 60 ? "var(--red)" : bits < 100 ? "var(--gold)" : "var(--jade)";
  const verdict = bits < 60 ? T("weak") : bits < 100 ? T("ok") : T("strong");
  $("entropy-text").textContent = `${T("entropyLbl")} ≈ ${bits} бит · ${verdict}`;
}

/* ------------------------------------------------------------------ */
/* Действия                                                            */
/* ------------------------------------------------------------------ */
async function doEncrypt() {
  const text = $("plain").value;
  const password = $("password").value;
  if (!text) return setStatus(T("needText"), "err");
  if (!password) return setStatus(T("needPassword"), "err");
  const btn = $("btn-encrypt");
  btn.disabled = true;
  setStatus(T("working"));
  try {
    const r = await api("/api/encrypt", {
      text, password,
      suite: $("suite").value,
      profile: $("profile").value,
      armor: $("armor").value,
      stealth: $("stealth").checked,
      hideLength: $("hidelen").checked,
    });
    if (!r.ok) { setStatus("✕ " + r.error, "err"); return; }
    $("cipher").value = r.armor;
    const name = (r.languageName && r.languageName[LANG]) || r.language;
    setStatus(`✓ ${T("encrypted")} ${r.ms} ${T("ms")} · ${r.bytes} ${T("bytes")} · ${T("lang")}: ${name} · armor: ${r.armorKind}`, "ok");
    $("cipher-meta").textContent = `${r.armor.length} ${T("chars")} · ${r.layers}`;
    renderInfo(r.info);
  } catch (e) {
    setStatus("✕ " + e, "err");
  } finally {
    btn.disabled = false;
  }
}

async function doDecrypt() {
  const text = $("cipher").value.trim();
  const password = $("password").value;
  if (!text) return setStatus(T("needText"), "err");
  const btn = $("btn-decrypt");
  btn.disabled = true;
  setStatus(T("working"));
  try {
    const r = await api("/api/decrypt", { text, password });
    if (!r.ok) { setStatus("✕ " + r.error, "err"); renderInfo({}); return; }
    $("plain").value = r.text;
    updatePlainMeta();
    setStatus(`✓ ${T("decrypted")} ${r.ms} ${T("ms")} · HMAC-SHA3-512 OK`, "ok");
    renderInfo(r.info);
  } catch (e) {
    setStatus("✕ " + e, "err");
  } finally {
    btn.disabled = false;
  }
}

async function doInspect() {
  const text = $("cipher").value.trim();
  if (!text) return setStatus(T("needText"), "err");
  const r = await api("/api/inspect", { text });
  if (!r.ok) return setStatus("✕ " + r.error, "err");
  renderInfo(r.info);
  setStatus("✓ header", "ok");
}

async function doGenPw() {
  const r = await api("/api/passgen", { style: $("pwstyle").value, bits: 128 });
  if (r.ok) {
    $("password").value = r.password;
    $("password").type = "text";
    updateEntropy();
  }
}

async function doSplit() {
  const r = await api("/api/split", {
    secret: $("secret").value,
    threshold: +$("k").value,
    shares: +$("n").value,
    armor: $("sharmor").value,
  });
  const box = $("shares");
  if (!r.ok) { box.innerHTML = ""; $("shares-out").textContent = "✕ " + r.error; return; }
  box.innerHTML = r.shares.map((s, i) =>
    `<div class="share"><input type="checkbox" data-share="${i}"><b>${i + 1}/${r.total}</b><code>${s}</code></div>`
  ).join("");
  $("shares-out").textContent = T("splitDone");
  $("shares-out").className = "status ok";
}

async function doCombine() {
  const picked = [...document.querySelectorAll("#shares input:checked")]
    .map((c) => c.parentElement.querySelector("code").textContent);
  if (!picked.length) { $("shares-out").textContent = T("combineNeed"); return; }
  const r = await api("/api/combine", { shares: picked });
  $("shares-out").textContent = r.ok ? `${T("secretIs")} ${r.secret}` : "✕ " + r.error;
  $("shares-out").className = "status " + (r.ok ? "ok" : "err");
}

async function doSelfTest() {
  const box = $("selftest");
  const btn = $("btn-selftest");
  btn.disabled = true;
  box.innerHTML = `<div class="test">${T("working")}</div>`;
  try {
    const r = await api("/api/selftest", {});
    box.innerHTML = r.results.map((t) =>
      `<div class="test ${t.ok ? "ok" : "fail"}"><span class="mark">${t.ok ? "✓" : "✕"}</span>` +
      `<span>${t.name}${t.error ? " — " + t.error : ""}</span><span class="ms">${t.ms} ms</span></div>`
    ).join("") + `<div class="test"><span class="mark"></span><b>${r.passed}/${r.total} ${T("testsPassed")}</b></div>`;
  } finally {
    btn.disabled = false;
  }
}

/* ------------------------------------------------------------------ */
/* Инициализация                                                       */
/* ------------------------------------------------------------------ */
function init() {
  $("plain").value = SAMPLES.ru;
  document.querySelectorAll("#langswitch button").forEach((b) =>
    b.addEventListener("click", () => { LANG = b.dataset.lang; applyLang(); }));
  document.querySelectorAll("[data-sample]").forEach((b) =>
    b.addEventListener("click", () => { $("plain").value = SAMPLES[b.dataset.sample]; updatePlainMeta(); }));
  $("btn-encrypt").addEventListener("click", doEncrypt);
  $("btn-decrypt").addEventListener("click", doDecrypt);
  $("btn-inspect").addEventListener("click", doInspect);
  $("btn-clear").addEventListener("click", () => {
    $("cipher").value = ""; $("cipher-meta").textContent = ""; renderInfo({}); setStatus("");
  });
  $("btn-copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("cipher").value);
    setStatus("✓ " + T("copied"), "ok");
  });
  $("genpw").addEventListener("click", doGenPw);
  $("toggle-pw").addEventListener("click", () => {
    const el = $("password");
    el.type = el.type === "password" ? "text" : "password";
  });
  $("password").addEventListener("input", updateEntropy);
  $("plain").addEventListener("input", updatePlainMeta);
  $("btn-split").addEventListener("click", doSplit);
  $("btn-combine").addEventListener("click", doCombine);
  $("btn-selftest").addEventListener("click", doSelfTest);
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") doEncrypt();
  });

  fetch("/api/config").then((r) => r.json()).then((cfg) => {
    $("backend-badge").textContent = `v${cfg.version} · ${cfg.backend}`;
    $("backend-info").textContent = Object.values(cfg.profiles).join("  |  ");
  }).catch(() => {});

  applyLang();
  updateEntropy();
  updatePlainMeta();
}

document.addEventListener("DOMContentLoaded", init);
