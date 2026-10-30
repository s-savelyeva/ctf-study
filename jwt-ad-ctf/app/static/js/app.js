/* ============================================================
   JWT ARENA — клиентская логика: декодер/конструктор JWT,
   отправка запросов с Web Crypto (HS256) и захват флага.
   Работает в браузере без внешних библиотек.
   ============================================================ */
"use strict";

const SERVICE = window.__SERVICE__;
const ORIGIN = location.origin;

const ENDPOINTS = {
  "alg-none": [
    { method: "GET", path: "/api/admin", auth: true, note: "флаг здесь (нужен admin)" },
    { method: "POST", path: "/api/login", auth: false, body: '{"username":"guest","password":"guest"}', note: "гостевой токен" },
  ],
  bruteforce: [
    { method: "GET", path: "/api/token", auth: false, note: "выдать гостевой HS256-токен" },
    { method: "GET", path: "/api/vault", auth: true, note: "флаг здесь (нужен admin)" },
  ],
  "rs256-hs256": [
    { method: "GET", path: "/api/token", auth: false, note: "выдать RS256-токен" },
    { method: "GET", path: "/public.pem", auth: false, note: "публичный ключ" },
    { method: "GET", path: "/api/dashboard", auth: true, note: "флаг здесь (нужен admin)" },
  ],
};

const THEORY = {
  "alg-none": `
    <p><strong>Суть:</strong> сервер смотрит на поле <code>alg</code> из заголовка токена
    и при значении <code>"none"</code> вообще не проверяет подпись. Атакующий снимает
    подпись и ставит <code>{"alg":"none"}</code>.</p>
    <pre>// header атаки
{ "alg": "none", "typ": "JWT" }
// токен: base64url(header).base64url(payload).  ← пустая сигнатура</pre>
    <p><strong>Патч:</strong> никогда не доверять alg из токена — жёстко задавать
    ожидаемый алгоритм на сервере (<code>jose.jwt_decode(token, key, algorithms=["HS256"])</code>)
    и явно отвергать <code>none</code>.</p>`,
  bruteforce: `
    <p><strong>Суть:</strong> HMAC-секрет подобран из частотного списка паролей.
    Любой, кто скачает образец токена, может перебрать словарь офлайн
    (hashcat mode 16500 / jwt-cracker) и подписать <code>"role":"admin"</code>.</p>
    <pre>hashcat -m 16500 token.txt wordlist.txt</pre>
    <p><strong>Патч:</strong> секрет ≥ 32 криптографически случайных байт
    (<code>secrets.token_bytes(32)</code>), ротация по ENV, rate-limit не помогает —
    проверка офлайн.</p>`,
  "rs256-hs256": `
    <p><strong>Суть (algorithm confusion):</strong> сервер поддерживает RS256 и сам
    выбирает способ проверки по <code>alg</code> из токена. Если поставить
    <code>alg=HS256</code>, библиотека проверит HMAC, используя <em>публичный RSA-ключ</em>
    как секрет. Ключ открыт на <code>/public.pem</code> — токен подделывается полностью
    на стороне атакующего.</p>
    <pre>secret  = GET /public.pem        // PEM-текст как строка
header  = { "alg": "HS256", ... } // меняем RS256 -> HS256
payload = { "role": "admin", ... }
sig     = HMAC_SHA256(secret, header + "." + payload)</pre>
    <p><strong>Патч:</strong> фиксировать алгоритм на сервере (разрешить только RS256),
    либо использовать библиотеки, где тип ключа и alg должны совпадать (PyJWT ≥ 2.x
    с <code>algorithms=["RS256"]</code>).</p>`,
};

/* ------------------------------- helpers -------------------------------- */

const $ = (id) => document.getElementById(id);

function b64urlEncodeBytes(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlEncodeStr(str) {
  return b64urlEncodeBytes(new TextEncoder().encode(str));
}
function b64urlDecodeToStr(seg) {
  const pad = seg.length % 4 === 0 ? "" : "=".repeat(4 - (seg.length % 4));
  const bin = atob(seg.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
async function hmacSha256(secretStr, messageStr) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secretStr),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(messageStr));
  return b64urlEncodeBytes(new Uint8Array(sig));
}

/* ------------------------------ состояние ------------------------------- */

const state = {
  token: "",
  header: null,     // объект
  payload: null,    // объект
  signature: "",    // base64url как в токене
  activeTab: "header",
};

function renderPreview() {
  const view = $("jwt-preview");
  if (!state.token) {
    view.innerHTML = '<span class="jwt-preview__empty">// вставьте или соберите токен</span>';
    return;
  }
  const parts = state.token.split(".");
  view.innerHTML = parts.map((p, i) => {
    const cls = ["seg-header", "seg-payload", "seg-signature"][i] || "seg-signature";
    return `<span class="${cls}">${p || "(пусто)"}</span>`;
  }).join('<span class="seg-dot">.</span>');
}

function loadToken(token, { keepEditor = false } = {}) {
  state.token = token.trim();
  $("token-input").value = state.token;
  const parts = state.token.split(".");
  try {
    state.header = JSON.parse(b64urlDecodeToStr(parts[0]));
    state.payload = JSON.parse(b64urlDecodeToStr(parts[1]));
    state.signature = parts[2] ?? "";
  } catch {
    state.header = null; state.payload = null; state.signature = "";
  }
  renderPreview();
  if (!keepEditor) renderEditor();
}

function currentEditorObj() {
  try { return JSON.parse($("json-editor").value); } catch { return null; }
}

function renderEditor() {
  const obj = state.activeTab === "header" ? state.header : state.payload;
  $("json-label").textContent = state.activeTab === "header" ? "HEADER (JSON)" : "PAYLOAD (JSON)";
  $("json-editor").value = obj ? JSON.stringify(obj, null, 2) : "";
}

/* --------------------------- пересборка токена --------------------------- */

function rebuildTokenFromEditors() {
  const hdr = currentEditorObj();
  if (hdr === null) { flashResponse("// Header должен быть валидным JSON", false); return; }
  // payload берём из состояния (могли не редактировать)
  const payload = state.payload ?? {};
  const h = b64urlEncodeStr(JSON.stringify(hdr));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const token = `${h}.${p}.${state.signature}`;
  loadToken(token, { keepEditor: true });
  flashResponse(`// токен пересобран\n${token}`, state.signature !== "");
}

async function signAndRebuild() {
  const secret = $("secret-input").value;
  if (!secret) { flashResponse("// укажите секрет (или публичный ключ для RS256→HS256)", false); return; }
  const hdr = currentEditorObj() ?? state.header ?? { alg: "HS256", typ: "JWT" };
  const payload = state.payload ?? {};
  if ((hdr.alg || "").toUpperCase() !== "HS256") hdr.alg = "HS256";
  const h = b64urlEncodeStr(JSON.stringify(hdr));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const sig = await hmacSha256(secret, signingInput);
  loadToken(`${signingInput}.${sig}`, { keepEditor: true });
  flashResponse(`// подписано HS256 (длина секрета ${secret.length} байт)\n${state.token}`, true);
}

function flashResponse(text, ok) {
  const el = $("response-view");
  el.textContent = text;
  el.style.borderColor = ok ? "rgba(52,211,153,.5)" : "rgba(248,113,113,.5)";
}

/* ------------------------------ запросы --------------------------------- */

async function sendRequest() {
  const ep = JSON.parse($("endpoint-select").value);
  const headers = { "Content-Type": "application/json" };
  if (ep.auth && $("use-current-token").checked && state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  const opts = { method: ep.method, headers };
  if (ep.body) opts.body = ep.body;

  let res, text;
  try {
    res = await fetch(ORIGIN + ep.path, opts);
    text = await res.text();
  } catch (e) {
    flashResponse(`// сетевая ошибка: ${e}`, false);
    setHealth(false);
    return;
  }
  setHealth(true);

  let data = null;
  try { data = JSON.parse(text); } catch { text = text.slice(0, 4000); }
  const pretty = data ? JSON.stringify(data, null, 2) : text;
  $("response-view").textContent = `HTTP ${res.status}\n\n${pretty}`;
  $("response-view").style.borderColor =
    res.ok && data?.ok ? "rgba(52,211,153,.5)" : "rgba(248,113,113,.4)";

  if (data && data.ok && data.flag) captureFlag(data.flag);
  else if (data && data.token && !state.token) loadToken(data.token);
  else if (data && data.token) {
    // не перетираем токен пользователя автоматически — предложим
    autoLoadSampleIntoLab(data.token);
  }
}

let sampleAskCount = 0;
function autoLoadSampleIntoLab(token) {
  if (sampleAskCount++ === 0 && !state.token) loadToken(token);
}

function captureFlag(flag) {
  const card = $("flag-card");
  $("flag-display").textContent = flag;
  $("btn-copy-flag").hidden = false;
  card.classList.add("is-captured");
  try { localStorage.setItem(`flag_${SERVICE.id}`, flag); } catch {}
}

/* ------------------------------ выбор endpoints ------------------------- */

function buildEndpointUI() {
  const eps = ENDPOINTS[SERVICE.id] || [];
  const list = $("endpoint-list");
  const sel = $("endpoint-select");
  list.innerHTML = "";
  sel.innerHTML = "";
  eps.forEach((ep, i) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="m">${ep.method}</span>${ep.path}<br><small style="color:var(--text-dim)">${ep.note}</small>`;
    list.appendChild(li);
    const opt = document.createElement("option");
    opt.value = JSON.stringify(ep);
    opt.textContent = `${ep.method} ${ep.path} — ${ep.note}`;
    sel.appendChild(opt);
  });
}

/* ------------------------------ health ---------------------------------- */

function setHealth(up) {
  const b = $("health-badge");
  b.textContent = up ? "● online" : "● offline";
  b.classList.toggle("badge--ok", up);
  b.classList.toggle("badge--down", !up);
}

/* -------------------------------- init ---------------------------------- */

function init() {
  buildEndpointUI();
  $("theory-body").innerHTML = THEORY[SERVICE.id] || "";

  // навигация по сервисам — относительные порты текущего хоста
  document.querySelectorAll(".chip[data-port]").forEach((a) => {
    a.href = `${location.protocol}//${location.hostname}:${a.dataset.port}/`;
  });

  // восстановление флага
  try {
    const saved = localStorage.getItem(`flag_${SERVICE.id}`);
    if (saved) captureFlag(saved);
  } catch {}

  // табы
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      // перед переключением сохранить текущий редактор в состояние
      const obj = currentEditorObj();
      if (obj !== null) {
        if (state.activeTab === "header") state.header = obj; else state.payload = obj;
      }
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("tab--active"));
      tab.classList.add("tab--active");
      state.activeTab = tab.dataset.tab;
      renderEditor();
    });
  });

  // авто-синхронизация редактора с состоянием при наборе
  $("json-editor").addEventListener("input", () => {
    const obj = currentEditorObj();
    if (obj !== null) {
      if (state.activeTab === "header") state.header = obj; else state.payload = obj;
    }
  });

  $("token-input").addEventListener("change", () => loadToken($("token-input").value));
  $("btn-rebuild").addEventListener("click", () => {
    const obj = currentEditorObj();
    if (obj !== null) {
      if (state.activeTab === "header") state.header = obj; else state.payload = obj;
    }
    rebuildTokenFromEditors();
  });
  $("btn-sign").addEventListener("click", signAndRebuild);
  $("btn-send").addEventListener("click", sendRequest);

  $("btn-sample").addEventListener("click", async () => {
    const url = SERVICE.id === "alg-none" ? "/api/login" : "/api/token";
    const opts = { method: SERVICE.id === "alg-none" ? "POST" : "GET",
                   headers: { "Content-Type": "application/json" } };
    if (SERVICE.id === "alg-none") opts.body = JSON.stringify({ username: "guest", password: "guest" });
    try {
      const data = await (await fetch(ORIGIN + url, opts)).json();
      if (data.token) {
        loadToken(data.token);
        flashResponse(`// получен токен сервиса\n${data.hint || ""}`, true);
        setHealth(true);
      }
    } catch (e) {
      flashResponse(`// ошибка: ${e}`, false); setHealth(false);
    }
  });

  $("btn-pubkey-use").addEventListener("click", () => {
    const pem = $("pubkey-input").value.trim();
    if (!pem) {
      fetchPemIntoPubkeyBox();
    } else {
      $("secret-input").value = pem;
      flashResponse("// публичный ключ скопирован в поле секрета — жмите «Подписать HS256»", true);
    }
  });

  async function fetchPemIntoPubkeyBox() {
    try {
      const txt = await (await fetch(ORIGIN + "/public.pem")).text();
      $("pubkey-input").value = txt;
      $("secret-input").value = txt;
      flashResponse("// /public.pem загружен и подставлен как секрет HS256", true);
    } catch (e) {
      flashResponse(`// не удалось получить ключ: ${e}`, false);
    }
  }

  $("btn-copy-json").addEventListener("click", () => copy($("json-editor").value, $("btn-copy-json")));
  $("btn-copy-flag").addEventListener("click", () => copy($("flag-display").textContent, $("btn-copy-flag")));

  function copy(text, btn) {
    navigator.clipboard?.writeText(text).then(() => {
      const old = btn.textContent; btn.textContent = "✓ готово";
      setTimeout(() => (btn.textContent = old), 1200);
    });
  }

  loadToken("");
  fetch(ORIGIN + "/").then((r) => setHealth(r.ok)).catch(() => setHealth(false));
}

document.addEventListener("DOMContentLoaded", init);
