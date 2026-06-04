import http from "node:http";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import { URL } from "node:url";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = path.join(ROOT, "data");
const VAULT_PATH = path.join(DATA_DIR, "vault.json.enc");
const ACCESS_CONTROL_PATH = path.join(DATA_DIR, "access-control.json");
const PORT = Number(process.env.PORT || 3040);
const HOST = process.env.HOST || "0.0.0.0";
const DEFAULT_PASSWORD = process.env.CERTIMAN_PASSWORD || "admin";
const SESSION_SECRET = process.env.CERTIMAN_SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const COOKIE_NAME = "certiman_session";
const DAY_MS = 24 * 60 * 60 * 1000;
const NOTIFICATION_HOUR = 10;

let vaultKey = null;
let state = null;
let accessControl = null;

const defaultCategories = () => ["웹사이트", "API", "서버", "로드밸런서", "메일", "기타"];
const defaultAccessControl = () => ({ enabled: false, allowlist: [] });

const emptyState = () => ({
  certificates: [],
  usages: [],
  categories: defaultCategories(),
  smtp: {
    host: "",
    port: 587,
    secure: false,
    username: "",
    password: "",
    from: "",
    testTo: "",
    warningDays: 30,
    enabled: false
  },
  notificationLog: []
});

function deriveKey(password) {
  return crypto.scryptSync(password, "certiman-v1", 32);
}

function encryptJson(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value, null, 2));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    version: 1,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64")
  });
}

function decryptJson(payload, key) {
  const box = JSON.parse(payload);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "base64"));
  decipher.setAuthTag(Buffer.from(box.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(box.data, "base64")),
    decipher.final()
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function loadAccessControl() {
  await ensureDataDir();
  if (!fsSync.existsSync(ACCESS_CONTROL_PATH)) {
    accessControl = defaultAccessControl();
    await saveAccessControl();
    return;
  }
  const loaded = JSON.parse(await fs.readFile(ACCESS_CONTROL_PATH, "utf8"));
  accessControl = {
    enabled: loaded.enabled === true,
    allowlist: Array.isArray(loaded.allowlist) ? loaded.allowlist.map(String) : []
  };
}

async function saveAccessControl() {
  await ensureDataDir();
  const tmp = `${ACCESS_CONTROL_PATH}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(accessControl || defaultAccessControl(), null, 2), { mode: 0o600 });
  await fs.rename(tmp, ACCESS_CONTROL_PATH);
}

async function loadVault(password) {
  await ensureDataDir();
  const key = deriveKey(password);
  if (!fsSync.existsSync(VAULT_PATH)) {
    vaultKey = key;
    state = emptyState();
    await saveVault();
    return true;
  }

  try {
    const loadedState = decryptJson(await fs.readFile(VAULT_PATH, "utf8"), key);
    state = loadedState;
    vaultKey = key;
    state.certificates ||= [];
    state.certificates = state.certificates.map((cert) => ({
      ...cert,
      renewalComplete: cert.renewalComplete === true
    }));
    state.usages ||= [];
    state.categories ||= defaultCategories();
    state.notificationLog ||= [];
    state.smtp ||= emptyState().smtp;
    state.smtp.testTo ||= "";
    return true;
  } catch {
    return false;
  }
}

async function changeVaultPassword(currentPassword, nextPassword) {
  if (!nextPassword || nextPassword.length < 5) {
    throw new Error("새 비밀번호는 5자 이상이어야 합니다.");
  }
  if (!fsSync.existsSync(VAULT_PATH)) {
    throw new Error("저장소가 아직 초기화되지 않았습니다.");
  }
  const currentKey = deriveKey(currentPassword);
  try {
    decryptJson(await fs.readFile(VAULT_PATH, "utf8"), currentKey);
  } catch {
    throw new Error("현재 비밀번호가 올바르지 않습니다.");
  }
  vaultKey = deriveKey(nextPassword);
  await saveVault();
}

async function saveVault() {
  if (!vaultKey || !state) throw new Error("vault is locked");
  const tmp = `${VAULT_PATH}.tmp`;
  await fs.writeFile(tmp, encryptJson(state, vaultKey), { mode: 0o600 });
  await fs.rename(tmp, VAULT_PATH);
}

function signSession(value) {
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
  return `${value}.${sig}`;
}

function verifySession(cookie) {
  if (!cookie) return false;
  const raw = cookie.split(";").map((p) => p.trim()).find((p) => p.startsWith(`${COOKIE_NAME}=`));
  if (!raw) return false;
  const value = decodeURIComponent(raw.slice(COOKIE_NAME.length + 1));
  const idx = value.lastIndexOf(".");
  if (idx === -1) return false;
  const body = value.slice(0, idx);
  const sig = value.slice(idx + 1);
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  if (sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)) && body === "ok";
}

function getClientIp(req) {
  if (process.env.CERTIMAN_TRUST_PROXY === "true") {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const realIp = String(req.headers["x-real-ip"] || "").trim();
    return normalizeIp(forwarded || realIp || req.socket.remoteAddress || "");
  }
  return normalizeIp(req.socket.remoteAddress || "");
}

function normalizeIp(value) {
  let ip = String(value || "").trim().replace(/%.+$/, "");
  if (ip.startsWith("::ffff:") && net.isIP(ip.slice(7)) === 4) ip = ip.slice(7);
  return ip;
}

function parseAccessControlInput(value) {
  const allowlist = String(value || "")
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  for (const rule of allowlist) parseAccessRule(rule);
  return Array.from(new Set(allowlist));
}

function parseAccessRule(rule) {
  const [rawIp, rawPrefix, extra] = String(rule).split("/");
  const ip = normalizeIp(rawIp);
  if (!ip || extra !== undefined) throw new Error(`IP 규칙 형식이 올바르지 않습니다: ${rule}`);
  const parsed = ipToBigInt(ip);
  if (!parsed) throw new Error(`유효한 IP 주소가 아닙니다: ${rule}`);
  const prefix = rawPrefix === undefined ? parsed.bits : Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > parsed.bits) {
    throw new Error(`CIDR prefix가 올바르지 않습니다: ${rule}`);
  }
  return { ...parsed, prefix };
}

function ipToBigInt(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return {
      version,
      bits: 32,
      value: parts.reduce((acc, part) => (acc << 8n) + BigInt(part), 0n)
    };
  }
  if (version === 6) {
    const parts = expandIpv6(ip);
    if (!parts) return null;
    return {
      version,
      bits: 128,
      value: parts.reduce((acc, part) => (acc << 16n) + BigInt(part), 0n)
    };
  }
  return null;
}

function expandIpv6(ip) {
  let value = ip.toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = value.slice(lastColon + 1);
    const parsed = ipToBigInt(ipv4);
    if (!parsed || parsed.version !== 4) return null;
    const high = Number((parsed.value >> 16n) & 0xffffn).toString(16);
    const low = Number(parsed.value & 0xffffn).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  const parts = [...left, ...Array(missing).fill("0"), ...right];
  if (parts.length !== 8) return null;
  return parts.map((part) => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return NaN;
    return Number.parseInt(part, 16);
  }).every((part) => Number.isInteger(part) && part >= 0 && part <= 0xffff)
    ? parts.map((part) => Number.parseInt(part, 16))
    : null;
}

function isIpAllowed(ip, config = accessControl) {
  if (!config?.enabled) return true;
  const client = ipToBigInt(normalizeIp(ip));
  if (!client) return false;
  return config.allowlist.some((rule) => {
    const parsedRule = parseAccessRule(rule);
    if (client.version !== parsedRule.version) return false;
    const shift = BigInt(client.bits - parsedRule.prefix);
    return (client.value >> shift) === (parsedRule.value >> shift);
  });
}

function accessDeniedPage(ip) {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>접속 차단 · Certiman</title>
  <link rel="stylesheet" href="/public/styles.css">
</head>
<body class="login-body">
  <section class="login-panel">
    <div class="brand large"><div class="mark">C</div><div><strong>Certiman</strong><span>Certificate Manager</span></div></div>
    <h1>접속이 차단되었습니다.</h1>
    <p class="error">현재 IP는 Certiman 허용 목록에 없습니다.</p>
    <p class="muted">감지된 IP: <code>${escapeHtml(ip || "unknown")}</code></p>
  </section>
</body>
</html>`;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "cache-control": "no-store",
    ...headers
  });
  res.end(body);
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    "cache-control": "no-store"
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2_000_000) throw new Error("request too large");
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  const type = req.headers["content-type"] || "";
  if (type.includes("application/json")) return JSON.parse(raw || "{}");
  return Object.fromEntries(new URLSearchParams(raw));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function uuid() {
  return crypto.randomUUID();
}

function normalizeDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function certStatus(cert) {
  if (cert.renewalComplete) return { label: "갱신 완료", className: "ok", days: "" };
  const expires = new Date(cert.validTo).getTime();
  const days = Math.ceil((expires - Date.now()) / DAY_MS);
  if (days < 0) return { label: "Expired", className: "danger", days };
  if (days <= Number(state.smtp.warningDays || 30)) return { label: "Expiring", className: "warn", days };
  return { label: "Valid", className: "ok", days };
}

function usageCount(certificateId) {
  return state.usages.filter((usage) => usage.certificateId === certificateId).length;
}

function statusBadge(cert) {
  const status = certStatus(cert);
  const suffix = status.days === "" ? "" : ` · ${status.days}일`;
  return `<span class="badge ${status.className}">${escapeHtml(status.label)}${escapeHtml(suffix)}</span>`;
}

function parseCertificate(pem, fallbackName) {
  const x509 = new crypto.X509Certificate(pem);
  return {
    id: uuid(),
    name: fallbackName || subjectValue(x509.subject, "CN") || "Imported certificate",
    subject: x509.subject,
    issuer: x509.issuer,
    serialNumber: x509.serialNumber,
    fingerprint256: x509.fingerprint256,
    validFrom: normalizeDate(x509.validFrom),
    validTo: normalizeDate(x509.validTo),
    renewalComplete: false,
    pem,
    createdAt: new Date().toISOString()
  };
}

function subjectValue(subject, key) {
  const found = String(subject).split(/\n|,/).map((x) => x.trim()).find((part) => part.startsWith(`${key}=`));
  return found ? found.slice(key.length + 1) : "";
}

function layout(title, inner, active = "dashboard") {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Certiman</title>
  <link rel="stylesheet" href="/public/styles.css">
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">C</div>
        <div>
          <strong>Certiman</strong>
          <span>Certificate Manager</span>
        </div>
      </div>
      <button class="sidebar-toggle" type="button" aria-label="사이드바 접기" title="사이드바 접기" data-sidebar-toggle>☰</button>
      <nav>
        ${navLink("/", "대시보드", active === "dashboard")}
        ${navLink("/certificates", "인증서", active === "certificates")}
        ${navLink("/usages", "사용처", active === "usages")}
        ${navLink("/settings", "설정", active === "settings")}
      </nav>
      <form method="post" action="/logout" class="logout"><button data-short="⎋">로그아웃</button></form>
    </aside>
    <main class="content">${inner}</main>
  </div>
  <script>
    document.querySelector("[data-sidebar-toggle]")?.addEventListener("click", () => {
      document.querySelector(".app-shell")?.classList.toggle("sidebar-collapsed");
    });
    document.querySelectorAll("[data-tab-target]").forEach((button) => {
      button.addEventListener("click", () => {
        const target = button.getAttribute("data-tab-target");
        document.querySelectorAll("[data-tab-target]").forEach((item) => item.classList.toggle("active", item === button));
        document.querySelectorAll("[data-tab-panel]").forEach((panel) => panel.classList.toggle("active", panel.getAttribute("data-tab-panel") === target));
      });
    });
  </script>
</body>
</html>`;
}

function navLink(href, label, active) {
  return `<a class="${active ? "active" : ""}" href="${href}" data-short="${escapeHtml(label.slice(0, 1))}">${escapeHtml(label)}</a>`;
}

function loginPage(error = "") {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Certiman Login</title>
  <link rel="stylesheet" href="/public/styles.css">
</head>
<body class="login-body">
  <form class="login-panel" method="post" action="/login" autocomplete="off">
    <div class="brand large"><div class="mark">C</div><div><strong>Certiman</strong><span>Certificate Manager</span></div></div>
    <label>접근 비밀번호<input type="password" name="password" autocomplete="off" autofocus required></label>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <button class="primary">로그인</button>
    <p class="muted">초기 비밀번호는 <code>CERTIMAN_PASSWORD</code> 값이며, 미설정 시 <code>admin</code>입니다.</p>
  </form>
</body>
</html>`;
}

function dashboardPage() {
  const total = state.certificates.length;
  const expiring = state.certificates.filter((cert) => certStatus(cert).className === "warn").length;
  const expired = state.certificates.filter((cert) => certStatus(cert).className === "danger").length;
  const usages = state.usages.length;
  const rows = state.certificates
    .slice()
    .sort((a, b) => new Date(a.validTo) - new Date(b.validTo))
    .slice(0, 8)
    .map(certificateRow)
    .join("");
  return layout("대시보드", `
    <header class="page-header">
      <div><h1>인증서 현황</h1><p>만료일, 사용처, 담당자 알림 상태를 한 화면에서 확인합니다.</p></div>
      <a class="button primary" href="/certificates">인증서 등록</a>
    </header>
    <section class="intro-panel">
      <h2>Certiman은 인증서 운영 정보를 한곳에 모으는 관리 도구입니다.</h2>
      <p>인증서를 임포트하면 만료일과 발급 정보를 자동으로 등록하고, 각 인증서가 쓰이는 웹사이트나 시스템, 담당자 메일을 연결합니다. 만료일이 가까워지면 설정된 SMTP 서버를 통해 담당자에게 알림을 보냅니다.</p>
    </section>
    <section class="stats">
      ${stat("등록 인증서", total)}
      ${stat("등록 사용처", usages)}
      ${stat("만료 임박", expiring)}
      ${stat("만료", expired)}
    </section>
    <section class="table-section">
      <div class="section-title"><h2>가까운 만료일</h2><form method="post" action="/notifications/run"><button>알림 점검 실행</button></form></div>
      <table><thead><tr><th>이름</th><th>상태</th><th>만료일</th><th>사용처</th><th>발급자</th></tr></thead><tbody>${rows || emptyRow(5, "등록된 인증서가 없습니다.")}</tbody></table>
    </section>
  `);
}

function stat(label, value) {
  return `<div class="stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function certificateRow(cert, actions = false) {
  return `<tr>
    <td><a href="/certificates/${cert.id}">${escapeHtml(cert.name)}</a><small>${escapeHtml(cert.subject)}</small></td>
    <td>${statusBadge(cert)}</td>
    <td>${escapeHtml(new Date(cert.validTo).toLocaleDateString("ko-KR"))}</td>
    <td>${usageCount(cert.id)}</td>
    <td>${escapeHtml(cert.issuer)}</td>
    ${actions ? `<td>${renewalForm(cert)}</td><td><form method="post" action="/certificates/${cert.id}/delete" onsubmit="return confirm('이 인증서를 삭제할까요? 연결된 사용처도 삭제됩니다.');"><button class="danger-button">삭제</button></form></td>` : ""}
  </tr>`;
}

function emptyRow(cols, message) {
  return `<tr><td colspan="${cols}" class="empty">${escapeHtml(message)}</td></tr>`;
}

function certificatesPage(error = "") {
  const rows = state.certificates
    .slice()
    .sort((a, b) => new Date(a.validTo) - new Date(b.validTo))
    .map((cert) => certificateRow(cert, true))
    .join("");
  return layout("인증서", `
    <header class="page-header"><div><h1>인증서</h1><p>PEM 인증서를 임포트하면 주체, 발급자, 만료일, 지문을 자동 등록합니다.</p></div></header>
    <section class="split">
      <form class="panel" method="post" action="/certificates" autocomplete="off">
        <h2>인증서 임포트</h2>
        <label>표시 이름<input name="name" placeholder="예: api.example.com wildcard"></label>
        <label>PEM 인증서<textarea name="pem" rows="12" required placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
        ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
        <button class="primary">등록</button>
      </form>
      <section class="table-section">
        <h2>등록 목록</h2>
        <table><thead><tr><th>이름</th><th>상태</th><th>만료일</th><th>사용처</th><th>발급자</th><th>갱신</th><th>관리</th></tr></thead><tbody>${rows || emptyRow(7, "등록된 인증서가 없습니다.")}</tbody></table>
      </section>
    </section>
  `, "certificates");
}

function certificateDetailPage(cert) {
  const rows = state.usages.filter((u) => u.certificateId === cert.id).map((usage) => usageRow(usage, true)).join("");
  return layout(cert.name, `
    <header class="page-header">
      <div><h1>${escapeHtml(cert.name)}</h1><p>${escapeHtml(cert.subject)}</p></div>
      <div class="header-actions">${renewalForm(cert)}<form method="post" action="/certificates/${cert.id}/delete" onsubmit="return confirm('이 인증서를 삭제할까요? 연결된 사용처도 삭제됩니다.');"><button class="danger-button">삭제</button></form></div>
    </header>
    <section class="details-grid">
      ${detail("상태", statusBadge(cert), true)}
      ${detail("유효 시작", new Date(cert.validFrom).toLocaleString("ko-KR"))}
      ${detail("유효 종료", new Date(cert.validTo).toLocaleString("ko-KR"))}
      ${detail("시리얼", cert.serialNumber)}
      ${detail("SHA-256 지문", cert.fingerprint256)}
      ${detail("발급자", cert.issuer)}
    </section>
    <section class="table-section">
      <div class="section-title"><h2>연결된 사용처</h2><a class="button" href="/usages">사용처 등록</a></div>
      <table><thead><tr><th>이름</th><th>카테고리</th><th>주소/식별자</th><th>담당자</th><th>인증서</th><th>관리</th></tr></thead><tbody>${rows || emptyRow(6, "연결된 사용처가 없습니다.")}</tbody></table>
    </section>
  `, "certificates");
}

function renewalForm(cert) {
  return `<form class="checkbox-form" method="post" action="/certificates/${cert.id}/renewal">
    <label class="checkbox-row"><input name="renewalComplete" type="checkbox" value="true" ${cert.renewalComplete ? "checked" : ""} onchange="this.form.submit()"> 갱신 완료</label>
  </form>`;
}

function detail(label, value, raw = false) {
  return `<div class="detail"><span>${escapeHtml(label)}</span><strong>${raw ? value : escapeHtml(value)}</strong></div>`;
}

function usagesPage(error = "") {
  const certificateOptions = state.certificates.map((cert) => `<option value="${cert.id}">${escapeHtml(cert.name)}</option>`).join("");
  const categoryOptions = state.categories.map((category) => `<option>${escapeHtml(category)}</option>`).join("");
  const rows = state.usages.slice().sort((a, b) => a.name.localeCompare(b.name)).map((usage) => usageRow(usage, true)).join("");
  return layout("사용처", `
    <header class="page-header"><div><h1>사용처</h1><p>웹사이트, API, 서버, 기타 시스템처럼 인증서가 쓰이는 위치와 담당자를 관리합니다.</p></div></header>
    <section class="split">
      <form class="panel" method="post" action="/usages" autocomplete="off">
        <h2>사용처 등록</h2>
        <label>인증서<select name="certificateId" required>${certificateOptions}</select></label>
        <label>이름<input name="name" required placeholder="예: 고객 포털"></label>
        <label>카테고리<select name="category">${categoryOptions}</select></label>
        <label>URL 또는 식별자<input name="locator" placeholder="https://example.com 또는 시스템명"></label>
        <label>담당자 이름<input name="ownerName" required></label>
        <label>담당자 메일<input name="ownerEmail" type="email" required></label>
        <label>비고<textarea name="notes" rows="4"></textarea></label>
        ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
        <button class="primary" ${state.certificates.length ? "" : "disabled"}>등록</button>
      </form>
      <section class="table-section">
        <h2>등록 목록</h2>
        <table><thead><tr><th>이름</th><th>카테고리</th><th>주소/식별자</th><th>담당자</th><th>인증서</th><th>관리</th></tr></thead><tbody>${rows || emptyRow(6, "등록된 사용처가 없습니다.")}</tbody></table>
      </section>
    </section>
  `, "usages");
}

function usageRow(usage, actions = false) {
  const cert = state.certificates.find((item) => item.id === usage.certificateId);
  return `<tr>
    <td>${escapeHtml(usage.name)}<small>${escapeHtml(usage.notes || "")}</small></td>
    <td>${escapeHtml(usage.category)}</td>
    <td>${usage.locator?.startsWith("http") ? `<a href="${escapeHtml(usage.locator)}" target="_blank" rel="noreferrer">${escapeHtml(usage.locator)}</a>` : escapeHtml(usage.locator || "")}</td>
    <td>${escapeHtml(usage.ownerName)}<small>${escapeHtml(usage.ownerEmail)}</small></td>
    <td>${cert ? `<a href="/certificates/${cert.id}">${escapeHtml(cert.name)}</a>` : "삭제된 인증서"}</td>
    ${actions ? `<td><form method="post" action="/usages/${usage.id}/delete" onsubmit="return confirm('이 사용처를 삭제할까요?');"><button class="danger-button">삭제</button></form></td>` : ""}
  </tr>`;
}

function settingsPage(message = "", error = "", req = null) {
  const smtp = state.smtp;
  const categories = state.categories || defaultCategories();
  const acl = accessControl || defaultAccessControl();
  const currentIp = req ? getClientIp(req) : "";
  return layout("설정", `
    <header class="page-header"><div><h1>설정</h1><p>접근 비밀번호, 접속 제한, SMTP 발송 설정을 관리합니다.</p></div></header>
    ${message ? `<p class="success">${escapeHtml(message)}</p>` : ""}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <div class="tabs" role="tablist">
      <button type="button" class="active" data-tab-target="security">보안</button>
      <button type="button" data-tab-target="access">접속 제한</button>
      <button type="button" data-tab-target="smtp">SMTP</button>
      <button type="button" data-tab-target="categories">사용처 카테고리</button>
    </div>
    <section class="tab-panel active" data-tab-panel="security">
      <form class="panel" method="post" action="/settings/password" autocomplete="off">
        <h2>접근 비밀번호 변경</h2>
        <label>현재 비밀번호<input name="currentPassword" type="password" autocomplete="off" required></label>
        <label>새 비밀번호<input name="nextPassword" type="password" autocomplete="off" minlength="5" required></label>
        <label>새 비밀번호 확인<input name="confirmPassword" type="password" autocomplete="off" minlength="5" required></label>
        <button class="primary">비밀번호 변경</button>
        <p class="muted">비밀번호를 변경하면 서버 vault가 새 비밀번호로 다시 암호화됩니다.</p>
      </form>
    </section>
    <section class="tab-panel" data-tab-panel="access">
      <form class="panel" method="post" action="/settings/access-control" autocomplete="off">
        <h2>접속 IP 제한</h2>
        <div class="form-grid">
          <label>상태<select name="enabled"><option value="false" ${acl.enabled ? "" : "selected"}>비활성</option><option value="true" ${acl.enabled ? "selected" : ""}>활성</option></select></label>
          <label>현재 접속 IP<input value="${escapeHtml(currentIp || "unknown")}" readonly></label>
        </div>
        <label>허용 IP / CIDR 목록<textarea name="allowlist" rows="8" placeholder="예: 127.0.0.1&#10;192.168.0.0/24&#10;2001:db8::/32">${escapeHtml(acl.allowlist.join("\n"))}</textarea></label>
        <button class="primary">접속 제한 저장</button>
        <p class="muted">단일 IP 또는 CIDR을 줄바꿈, 공백, 쉼표로 입력할 수 있습니다. 리버스 프록시의 <code>X-Forwarded-For</code>를 신뢰하려면 서버 실행 환경에 <code>CERTIMAN_TRUST_PROXY=true</code>를 설정하세요.</p>
      </form>
    </section>
    <section class="tab-panel" data-tab-panel="smtp">
      <form class="panel" method="post" action="/settings/smtp" autocomplete="off">
        <h2>SMTP 발송 설정</h2>
        <div class="form-grid">
          <label>SMTP 호스트<input name="host" value="${escapeHtml(smtp.host)}" placeholder="smtp.example.com"></label>
          <label>포트<input name="port" type="number" value="${escapeHtml(smtp.port)}"></label>
          <label>보안 연결<select name="secure"><option value="false" ${smtp.secure ? "" : "selected"}>STARTTLS 또는 일반</option><option value="true" ${smtp.secure ? "selected" : ""}>TLS 즉시 연결</option></select></label>
          <label>보내는 주소<input name="from" value="${escapeHtml(smtp.from)}" placeholder="certiman@example.com"></label>
          <label>테스트 수신자<input name="testTo" type="email" value="${escapeHtml(smtp.testTo || "")}" placeholder="admin@example.com"></label>
          <label>사용자명<input name="username" value="${escapeHtml(smtp.username)}" autocomplete="off"></label>
          <label>비밀번호<input name="password" type="password" autocomplete="off" placeholder="${smtp.password ? "저장된 비밀번호 유지" : ""}"></label>
          <label class="checkbox-row"><input name="clearPassword" type="checkbox" value="true"> 저장된 SMTP 비밀번호 삭제</label>
          <label>만료 알림 기준일<input name="warningDays" type="number" min="1" value="${escapeHtml(smtp.warningDays)}"></label>
          <label>자동 알림<select name="enabled"><option value="false" ${smtp.enabled ? "" : "selected"}>비활성</option><option value="true" ${smtp.enabled ? "selected" : ""}>활성</option></select></label>
        </div>
        <div class="actions"><button class="primary">SMTP 저장</button><button formaction="/settings/smtp/test" formmethod="post">테스트 메일 발송</button></div>
      </form>
    </section>
    <section class="tab-panel" data-tab-panel="categories">
      <form class="panel category-add" method="post" action="/settings/categories" autocomplete="off">
        <h2>사용처 카테고리 추가</h2>
        <label>카테고리 이름<input name="name" required placeholder="예: Kubernetes Ingress"></label>
        <button class="primary">추가</button>
      </form>
      <section class="table-section">
        <h2>카테고리 목록</h2>
        <table><thead><tr><th>이름</th><th>사용처 수</th><th>수정</th><th>삭제</th></tr></thead><tbody>${categories.map(categoryRow).join("") || emptyRow(4, "등록된 카테고리가 없습니다.")}</tbody></table>
      </section>
    </section>
    <section class="table-section">
      <h2>최근 알림 로그</h2>
      <table><thead><tr><th>시간</th><th>수신자</th><th>인증서</th><th>결과</th></tr></thead><tbody>${state.notificationLog.slice(-20).reverse().map(logRow).join("") || emptyRow(4, "발송 로그가 없습니다.")}</tbody></table>
    </section>
  `, "settings");
}

function categoryRow(category) {
  const count = state.usages.filter((usage) => usage.category === category).length;
  const encoded = encodeURIComponent(category);
  return `<tr>
    <td>${escapeHtml(category)}</td>
    <td>${count}</td>
    <td>
      <form class="inline-form" method="post" action="/settings/categories/${encoded}/rename" autocomplete="off">
        <input name="name" value="${escapeHtml(category)}" required>
        <button>수정</button>
      </form>
    </td>
    <td>
      <form method="post" action="/settings/categories/${encoded}/delete" onsubmit="return confirm('이 카테고리를 삭제할까요? 사용 중인 카테고리는 삭제되지 않습니다.');">
        <button class="danger-button">삭제</button>
      </form>
    </td>
  </tr>`;
}

function logRow(log) {
  return `<tr><td>${escapeHtml(new Date(log.at).toLocaleString("ko-KR"))}</td><td>${escapeHtml(log.to)}</td><td>${escapeHtml(log.certificateName)}</td><td>${escapeHtml(log.result)}</td></tr>`;
}

function redirect(res, location) {
  res.writeHead(303, { location });
  res.end();
}

async function smtpSend(config, message) {
  if (!config.host || !config.port || !config.from) throw new Error("SMTP host, port, from are required");
  const socket = await connectSmtp(config);
  const read = createLineReader(socket);
  const command = async (line, expected = [250]) => {
    socket.write(`${line}\r\n`);
    const response = await read();
    const code = Number(response.slice(0, 3));
    if (!expected.includes(code)) throw new Error(`SMTP ${line} failed: ${response}`);
    return response;
  };

  await read();
  await command(`EHLO certiman.local`);
  let activeSocket = socket;
  if (!config.secure) {
    try {
      await command("STARTTLS", [220, 250]);
      activeSocket = tls.connect({ socket, servername: config.host });
      await new Promise((resolve, reject) => {
        activeSocket.once("secureConnect", resolve);
        activeSocket.once("error", reject);
      });
    } catch {
      activeSocket = socket;
    }
  }
  const activeRead = createLineReader(activeSocket);
  const activeCommand = async (line, expected = [250]) => {
    activeSocket.write(`${line}\r\n`);
    const response = await activeRead();
    const code = Number(response.slice(0, 3));
    if (!expected.includes(code)) throw new Error(`SMTP ${line} failed: ${response}`);
    return response;
  };

  await activeCommand(`EHLO certiman.local`);
  if (config.username || config.password) {
    const auth = Buffer.from(`\0${config.username}\0${config.password}`).toString("base64");
    await activeCommand(`AUTH PLAIN ${auth}`, [235]);
  }
  await activeCommand(`MAIL FROM:<${config.from}>`);
  await activeCommand(`RCPT TO:<${message.to}>`, [250, 251]);
  await activeCommand("DATA", [354]);
  activeSocket.write([
    `From: ${config.from}`,
    `To: ${message.to}`,
    `Subject: ${encodeMime(message.subject)}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    message.body.replaceAll("\n.", "\n.."),
    "."
  ].join("\r\n") + "\r\n");
  const result = await activeRead();
  if (Number(result.slice(0, 3)) !== 250) throw new Error(`SMTP DATA failed: ${result}`);
  await activeCommand("QUIT", [221, 250]);
}

function connectSmtp(config) {
  return new Promise((resolve, reject) => {
    const options = { host: config.host, port: Number(config.port), servername: config.host };
    const socket = config.secure ? tls.connect(options) : net.connect(options);
    socket.setTimeout(15000);
    socket.once(config.secure ? "secureConnect" : "connect", () => resolve(socket));
    socket.once("timeout", () => reject(new Error("SMTP connection timed out")));
    socket.once("error", reject);
  });
}

function createLineReader(socket) {
  let buffer = "";
  const waiters = [];
  socket.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    flush();
  });
  function flush() {
    while (waiters.length) {
      const match = buffer.match(/(?:^|\r\n)(\d{3}) [^\r]*\r\n/);
      if (!match) return;
      const end = buffer.indexOf(match[0]) + match[0].length;
      const response = buffer.slice(0, end).trim();
      buffer = buffer.slice(end);
      waiters.shift().resolve(response);
    }
  }
  return () => new Promise((resolve, reject) => {
    waiters.push({ resolve, reject });
    flush();
    setTimeout(() => reject(new Error("SMTP response timed out")), 15000);
  });
}

function encodeMime(value) {
  return `=?UTF-8?B?${Buffer.from(value).toString("base64")}?=`;
}

async function runNotifications({ force = false } = {}) {
  if (!state.smtp.enabled && !force) return [];
  const warningDays = Number(state.smtp.warningDays || 30);
  const today = localDateKey(new Date());
  const results = [];
  for (const cert of state.certificates) {
    if (cert.renewalComplete) continue;
    const status = certStatus(cert);
    if (status.days > warningDays || status.days < 0) continue;
    const usages = state.usages.filter((usage) => usage.certificateId === cert.id);
    for (const usage of usages) {
      const sentToday = state.notificationLog.find((log) =>
        log.certificateId === cert.id &&
        log.usageId === usage.id &&
        localDateKey(new Date(log.at)) === today
      );
      if (sentToday && !force) continue;
      const message = {
        to: usage.ownerEmail,
        subject: `[Certiman] 인증서 만료 알림: ${cert.name}`,
        body: [
          `${usage.ownerName}님,`,
          "",
          `다음 인증서의 만료일이 다가왔습니다.`,
          `인증서: ${cert.name}`,
          `사용처: ${usage.name}`,
          `카테고리: ${usage.category}`,
          `주소/식별자: ${usage.locator || "-"}`,
          `만료일: ${new Date(cert.validTo).toLocaleString("ko-KR")}`,
          `남은 기간: ${status.days}일`,
          "",
          "Certiman"
        ].join("\n")
      };
      try {
        await smtpSend(state.smtp, message);
        results.push({ cert, usage, result: "sent" });
        state.notificationLog.push(logEntry(cert, usage, "sent"));
      } catch (error) {
        results.push({ cert, usage, result: error.message });
        state.notificationLog.push(logEntry(cert, usage, `failed: ${error.message}`));
      }
    }
  }
  await saveVault();
  return results;
}

function localDateKey(date) {
  return [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0")
  ].join("-");
}

function millisecondsUntilNextNotificationRun(now = new Date()) {
  const next = new Date(now);
  next.setHours(NOTIFICATION_HOUR, 0, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  return next.getTime() - now.getTime();
}

function scheduleDailyNotifications() {
  const delay = millisecondsUntilNextNotificationRun();
  setTimeout(async () => {
    try {
      if (state?.smtp?.enabled) await runNotifications();
    } catch (error) {
      console.error("notification error", error);
    } finally {
      scheduleDailyNotifications();
    }
  }, delay).unref();
}

function logEntry(cert, usage, result) {
  return {
    at: new Date().toISOString(),
    certificateId: cert.id,
    certificateName: cert.name,
    usageId: usage.id,
    to: usage.ownerEmail,
    result
  };
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const clientIp = getClientIp(req);
  const authed = verifySession(req.headers.cookie);

  try {
    if (url.pathname === "/public/styles.css") {
      const css = await fs.readFile(path.join(ROOT, "public", "styles.css"), "utf8");
      res.writeHead(200, { "content-type": "text/css; charset=utf-8" });
      res.end(css);
      return;
    }

    if (!isIpAllowed(clientIp)) {
      return send(res, 403, accessDeniedPage(clientIp));
    }

    if (url.pathname === "/login" && req.method === "GET") return send(res, 200, loginPage());
    if (url.pathname === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const password = String(body.password || "");
      if (!fsSync.existsSync(VAULT_PATH) && password !== DEFAULT_PASSWORD) {
        return send(res, 401, loginPage("초기 비밀번호가 올바르지 않습니다."));
      }
      const loaded = await loadVault(password);
      if (!loaded) return send(res, 401, loginPage("저장소를 열 수 없습니다. 기존 비밀번호와 일치하는지 확인하세요."));
      res.writeHead(303, {
        location: "/",
        "set-cookie": `${COOKIE_NAME}=${encodeURIComponent(signSession("ok"))}; HttpOnly; SameSite=Lax; Path=/`
      });
      res.end();
      return;
    }

    if (!authed) return redirect(res, "/login");
    if (!state) return redirect(res, "/login");

    if (url.pathname === "/logout" && req.method === "POST") {
      res.writeHead(303, {
        location: "/login",
        "set-cookie": `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
      });
      res.end();
      return;
    }
    if (url.pathname === "/" && req.method === "GET") return send(res, 200, dashboardPage());
    if (url.pathname === "/certificates" && req.method === "GET") return send(res, 200, certificatesPage());
    if (url.pathname === "/certificates" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const cert = parseCertificate(body.pem, body.name);
        state.certificates.push(cert);
        await saveVault();
        return redirect(res, `/certificates/${cert.id}`);
      } catch (error) {
        return send(res, 400, certificatesPage(`인증서 파싱 실패: ${error.message}`));
      }
    }
    const certMatch = url.pathname.match(/^\/certificates\/([^/]+)$/);
    if (certMatch && req.method === "GET") {
      const cert = state.certificates.find((item) => item.id === certMatch[1]);
      if (!cert) return send(res, 404, layout("없음", "<h1>인증서를 찾을 수 없습니다.</h1>"));
      return send(res, 200, certificateDetailPage(cert));
    }
    const certRenewalMatch = url.pathname.match(/^\/certificates\/([^/]+)\/renewal$/);
    if (certRenewalMatch && req.method === "POST") {
      const body = await readBody(req);
      const cert = state.certificates.find((item) => item.id === certRenewalMatch[1]);
      if (!cert) return send(res, 404, layout("없음", "<h1>인증서를 찾을 수 없습니다.</h1>"));
      cert.renewalComplete = body.renewalComplete === "true";
      await saveVault();
      const referer = req.headers.referer || "/certificates";
      return redirect(res, new URL(referer, `http://${req.headers.host}`).pathname);
    }
    const certDeleteMatch = url.pathname.match(/^\/certificates\/([^/]+)\/delete$/);
    if (certDeleteMatch && req.method === "POST") {
      state.certificates = state.certificates.filter((item) => item.id !== certDeleteMatch[1]);
      state.usages = state.usages.filter((item) => item.certificateId !== certDeleteMatch[1]);
      await saveVault();
      return redirect(res, "/certificates");
    }
    if (url.pathname === "/usages" && req.method === "GET") return send(res, 200, usagesPage());
    if (url.pathname === "/usages" && req.method === "POST") {
      const body = await readBody(req);
      if (!state.certificates.some((cert) => cert.id === body.certificateId)) {
        return send(res, 400, usagesPage("먼저 인증서를 등록해야 합니다."));
      }
      state.usages.push({
        id: uuid(),
        certificateId: body.certificateId,
        name: String(body.name || "").trim(),
        category: String(body.category || "기타").trim(),
        locator: String(body.locator || "").trim(),
        ownerName: String(body.ownerName || "").trim(),
        ownerEmail: String(body.ownerEmail || "").trim(),
        notes: String(body.notes || "").trim(),
        createdAt: new Date().toISOString()
      });
      await saveVault();
      return redirect(res, "/usages");
    }
    const usageDeleteMatch = url.pathname.match(/^\/usages\/([^/]+)\/delete$/);
    if (usageDeleteMatch && req.method === "POST") {
      state.usages = state.usages.filter((item) => item.id !== usageDeleteMatch[1]);
      await saveVault();
      return redirect(res, "/usages");
    }
    if (url.pathname === "/settings" && req.method === "GET") return send(res, 200, settingsPage("", "", req));
    if (url.pathname === "/settings/password" && req.method === "POST") {
      const body = await readBody(req);
      const currentPassword = String(body.currentPassword || "");
      const nextPassword = String(body.nextPassword || "");
      const confirmPassword = String(body.confirmPassword || "");
      try {
        if (nextPassword !== confirmPassword) throw new Error("새 비밀번호 확인이 일치하지 않습니다.");
        await changeVaultPassword(currentPassword, nextPassword);
        return send(res, 200, settingsPage("비밀번호를 변경했고 저장소를 다시 암호화했습니다.", "", req));
      } catch (error) {
        return send(res, 400, settingsPage("", error.message, req));
      }
    }
    if (url.pathname === "/settings/access-control" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const nextAccessControl = {
          enabled: body.enabled === "true",
          allowlist: parseAccessControlInput(body.allowlist)
        };
        if (nextAccessControl.enabled && nextAccessControl.allowlist.length === 0) {
          throw new Error("접속 제한을 활성화하려면 허용 IP 또는 CIDR을 하나 이상 입력하세요.");
        }
        if (nextAccessControl.enabled && !isIpAllowed(clientIp, nextAccessControl)) {
          throw new Error(`현재 접속 IP(${clientIp})가 허용 목록에 없어 저장할 수 없습니다.`);
        }
        accessControl = nextAccessControl;
        await saveAccessControl();
        return send(res, 200, settingsPage("접속 IP 제한 설정을 저장했습니다.", "", req));
      } catch (error) {
        return send(res, 400, settingsPage("", error.message, req));
      }
    }
    if (url.pathname === "/settings/smtp" && req.method === "POST") {
      const body = await readBody(req);
      const nextPassword = String(body.password || "");
      const clearPassword = body.clearPassword === "true";
      const testTo = String(body.testTo || "").trim();
      state.smtp = {
        host: String(body.host || "").trim(),
        port: Number(body.port || 587),
        secure: body.secure === "true",
        username: String(body.username || "").trim(),
        password: clearPassword ? "" : nextPassword || state.smtp.password || "",
        from: String(body.from || "").trim(),
        testTo,
        warningDays: Number(body.warningDays || 30),
        enabled: body.enabled === "true"
      };
      await saveVault();
      return send(res, 200, settingsPage("SMTP 설정을 저장했습니다.", "", req));
    }
    if (url.pathname === "/settings/smtp/test" && req.method === "POST") {
      const body = await readBody(req);
      const nextPassword = String(body.password || "");
      const clearPassword = body.clearPassword === "true";
      const testTo = String(body.testTo || "").trim();
      state.smtp = {
        host: String(body.host || "").trim(),
        port: Number(body.port || 587),
        secure: body.secure === "true",
        username: String(body.username || "").trim(),
        password: clearPassword ? "" : nextPassword || state.smtp.password || "",
        from: String(body.from || "").trim(),
        testTo,
        warningDays: Number(body.warningDays || 30),
        enabled: body.enabled === "true"
      };
      try {
        if (!testTo) throw new Error("테스트 수신자 메일주소를 입력하세요.");
        await smtpSend(state.smtp, {
          to: testTo,
          subject: "[Certiman] SMTP test",
          body: "Certiman SMTP 설정 테스트 메일입니다."
        });
        await saveVault();
        return send(res, 200, settingsPage("테스트 메일을 발송했습니다.", "", req));
      } catch (error) {
        await saveVault();
        return send(res, 400, settingsPage("", `테스트 실패: ${error.message}`, req));
      }
    }
    if (url.pathname === "/settings/categories" && req.method === "POST") {
      const body = await readBody(req);
      const name = String(body.name || "").trim();
      if (!name) return send(res, 400, settingsPage("", "카테고리 이름을 입력하세요.", req));
      state.categories ||= defaultCategories();
      if (state.categories.some((category) => category.toLowerCase() === name.toLowerCase())) {
        return send(res, 400, settingsPage("", "이미 등록된 카테고리입니다.", req));
      }
      state.categories.push(name);
      state.categories.sort((a, b) => a.localeCompare(b, "ko"));
      await saveVault();
      return send(res, 200, settingsPage("사용처 카테고리를 추가했습니다.", "", req));
    }
    const categoryRenameMatch = url.pathname.match(/^\/settings\/categories\/([^/]+)\/rename$/);
    if (categoryRenameMatch && req.method === "POST") {
      const oldName = decodeURIComponent(categoryRenameMatch[1]);
      const body = await readBody(req);
      const nextName = String(body.name || "").trim();
      state.categories ||= defaultCategories();
      if (!state.categories.includes(oldName)) return send(res, 404, settingsPage("", "카테고리를 찾을 수 없습니다.", req));
      if (!nextName) return send(res, 400, settingsPage("", "카테고리 이름을 입력하세요.", req));
      if (nextName !== oldName && state.categories.some((category) => category.toLowerCase() === nextName.toLowerCase())) {
        return send(res, 400, settingsPage("", "이미 등록된 카테고리입니다.", req));
      }
      state.categories = state.categories.map((category) => category === oldName ? nextName : category).sort((a, b) => a.localeCompare(b, "ko"));
      state.usages = state.usages.map((usage) => usage.category === oldName ? { ...usage, category: nextName } : usage);
      await saveVault();
      return send(res, 200, settingsPage("사용처 카테고리를 수정했습니다.", "", req));
    }
    const categoryDeleteMatch = url.pathname.match(/^\/settings\/categories\/([^/]+)\/delete$/);
    if (categoryDeleteMatch && req.method === "POST") {
      const name = decodeURIComponent(categoryDeleteMatch[1]);
      state.categories ||= defaultCategories();
      if (state.usages.some((usage) => usage.category === name)) {
        return send(res, 400, settingsPage("", "사용 중인 카테고리는 삭제할 수 없습니다.", req));
      }
      state.categories = state.categories.filter((category) => category !== name);
      await saveVault();
      return send(res, 200, settingsPage("사용처 카테고리를 삭제했습니다.", "", req));
    }
    if (url.pathname === "/notifications/run" && req.method === "POST") {
      await runNotifications({ force: true });
      return redirect(res, "/settings");
    }
    if (url.pathname === "/api/state" && req.method === "GET") {
      return sendJson(res, 200, {
        certificates: state.certificates.map(({ pem, ...cert }) => cert),
        usages: state.usages,
        smtp: { ...state.smtp, password: state.smtp.password ? "********" : "" },
        accessControl
      });
    }
    return send(res, 404, layout("404", "<h1>페이지를 찾을 수 없습니다.</h1>"));
  } catch (error) {
    console.error(error);
    return send(res, 500, layout("오류", `<h1>오류</h1><p class="error">${escapeHtml(error.message)}</p>`));
  }
}

async function boot() {
  await ensureDataDir();
  await loadAccessControl();
  if (fsSync.existsSync(VAULT_PATH)) {
    const loaded = await loadVault(DEFAULT_PASSWORD);
    if (!loaded) {
      console.log("Encrypted vault is locked. Log in with the current password to unlock it.");
    }
  }
  scheduleDailyNotifications();
  http.createServer(handle).listen(PORT, HOST, () => {
    console.log(`Certiman running at http://${HOST}:${PORT}`);
    console.log(`Initial password source: ${process.env.CERTIMAN_PASSWORD ? "CERTIMAN_PASSWORD" : "default admin"}`);
  });
}

boot().catch((error) => {
  console.error(error);
  process.exit(1);
});
