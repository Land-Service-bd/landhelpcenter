require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const multer = require("multer");
const nodemailer = require("nodemailer");
// The hosted deployment installs pg. Local JSON-based development does not
// need the driver, so keep it optional when POSTGRES_URL is absent.
const { Pool } = process.env.POSTGRES_URL ? require("pg") : { Pool: null };

const app = express();
const PORT = process.env.PORT || 3000;
// DATA_DIR can point at a persistent hosting volume (for example /data on
// Railway). Without it, local development continues to use ./data unchanged.
const VERCEL_TMP_DIR = process.platform === "win32" ? path.join(os.tmpdir(), "customer-management-data") : "/tmp/customer-management-data";
const DATA_DIR = path.resolve(process.env.DATA_DIR || (process.env.VERCEL ? VERCEL_TMP_DIR : path.join(__dirname, "data")));
const DB_FILE = path.join(DATA_DIR, "db.json");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const ADMIN_RESET_EMAIL = process.env.ADMIN_RESET_EMAIL || "bdenfo@gmail.com";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || `http://localhost:${PORT}`)
  .split(",").map(value => value.trim()).filter(Boolean);
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Security headers are set without changing the existing single-page UI.
app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (IS_PRODUCTION) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});
app.use((req, res, next) => {
  const origin = req.get("origin");
  let sameSite = false;
  try { sameSite = new URL(origin).host === req.get("host"); } catch {}
  // Same-site browser calls work automatically; cross-site calls must be
  // explicitly listed in ALLOWED_ORIGINS.
  if (origin && !sameSite && !ALLOWED_ORIGINS.includes(origin)) return res.status(403).json({ error: "Origin is not allowed" });
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});
app.use(express.json({ limit: "2mb" }));

// Lightweight deployment diagnostic. It never exposes credentials or tokens.
// Keep this endpoint before database initialization so a broken DB connection
// can be diagnosed from Vercel even when the application state is unavailable.
app.get("/api/health", (req, res) => {
  const database = statePool ? "postgres-configured" : (googleDriveEnabled ? "google-drive-state" : "local-json-fallback");
  res.json({
    ok: true,
    service: "landhelpcenter-api",
    node: process.version,
    vercel: Boolean(process.env.VERCEL),
    storage: googleDriveEnabled ? "google-drive" : (process.env.VERCEL ? "not-configured" : "local-dev"),
    database,
    durableState: Boolean(statePool || googleDriveEnabled),
    timestamp: new Date().toISOString()
  });
});
// On Vercel, restore the persistent PostgreSQL state before any route reads it.
app.use(async (req, res, next) => {
  try {
    // Wait for any previous request's persistence write before reading state.
    await writeQueue;
    await ensureState();
    // Vercel can route consecutive requests to different instances. Refresh
    // the authoritative shared state on every request so login sessions,
    // registrations, orders, balances and notifications stay visible everywhere.
    if (statePool) {
      const latest = await statePool.query("select payload from cms_app_state where state_key = 'primary'");
      if (latest.rowCount) {
        db = latest.rows[0].payload;
        normalizeState();
      }
    } else if (googleDriveEnabled) {
      const latest = await loadGoogleDriveState();
      if (latest) {
        db = latest;
        normalizeState();
      }
    } else if (process.env.VERCEL) {
      return res.status(503).json({ error: "Persistent storage is not configured. Configure Google Drive storage (or PostgreSQL) in Vercel Environment Variables." });
    }
    next();
  }
  catch (error) { console.error("Persistent state initialization failed:", error.message); res.status(503).json({ error: "Persistent storage is temporarily unavailable" }); }
});
app.use(express.static(path.join(__dirname, "public"), { dotfiles: "deny", index: false }));

const requestBuckets = new Map();
function rateLimit({ windowMs, max, key = req => req.ip }) {
  return (req, res, next) => {
    const now = Date.now(), bucketKey = `${key(req)}:${req.path}`;
    const hits = (requestBuckets.get(bucketKey) || []).filter(time => time > now - windowMs);
    if (hits.length >= max) return res.status(429).json({ error: "অনেকবার চেষ্টা করা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।" });
    hits.push(now); requestBuckets.set(bucketKey, hits); next();
  };
}
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));
// Authentication pages may legitimately make several requests while the UI
// restores a session.  This is deliberately generous; password failures are
// still rate-limited separately below.
const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const failedLoginBuckets = new Map();
function loginAttemptKey(req, identifier) { return `${req.ip}:${identifier}`; }
function rejectTooManyLoginAttempts(req, res, identifier) {
  const key = loginAttemptKey(req, identifier), now = Date.now();
  const hits = (failedLoginBuckets.get(key) || []).filter(time => time > now - 15 * 60 * 1000);
  if (hits.length >= 10) { failedLoginBuckets.set(key, hits); res.status(429).json({ error: "নিরাপত্তার জন্য অনেকবার ভুল Login চেষ্টা করা হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন।" }); return true; }
  return false;
}
function recordFailedLogin(req, identifier) {
  const key = loginAttemptKey(req, identifier), now = Date.now();
  const hits = (failedLoginBuckets.get(key) || []).filter(time => time > now - 15 * 60 * 1000);
  hits.push(now); failedLoginBuckets.set(key, hits);
}
function clearFailedLogin(req, identifier) { failedLoginBuckets.delete(loginAttemptKey(req, identifier)); }
function normalizeLoginIdentifier(value) {
  const trimmed = String(value ?? "").trim();
  // Allow customers to type a registered mobile number with spaces or dashes,
  // but retain ordinary usernames such as "admin" unchanged.
  return /^[+0-9()\s-]+$/.test(trimmed) ? trimmed.replace(/[\s()-]/g, "") : trimmed.toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, user) {
  try {
    const hash = crypto.scryptSync(String(password), user.salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"));
  } catch {
    return false;
  }
}
function createInitialDB() {
    const admin = hashPassword("admin123");
    const manager = hashPassword("manager123");
    return {
      users: [
        { id: 1, customerId: "ADM-0001", name: "Main Admin", phone: "admin", email: "", role: "ADMIN", balance: 0, ...admin },
        { id: 2, customerId: "MGR-0001", name: "Manager", phone: "manager", email: "", role: "MANAGER", balance: 0, ...manager }
      ],
      topups: [],
      services: [
        { id: 1, title: "নামজারি আবেদন", description: "নামজারি/মিউটেশন আবেদন সেবা", price: 300, paid: true, active: true, formFields: [] },
        { id: 2, title: "খতিয়ান অনলাইন", description: "খতিয়ান/পর্চা সংগ্রহ সহায়তা", price: 100, paid: true, active: true, formFields: [] },
        { id: 3, title: "সাধারণ তথ্য সেবা", description: "তথ্য ও পরামর্শ", price: 0, paid: false, active: true }
      ],
      orders: [],
      supportMessages: [],
      passwordResetCodes: [],
      siteSettings: { headerTitle: "Customer Management", headerSubtitle: "Phase 5 — Order System", footerText: "Customer Management System • Phase 5 • Order + Top-up", uiLabels: {}, homepage: {} },
      transactions: [],
      next: { user: 3, topup: 1, service: 4, order: 1, transaction: 1, supportMessage: 1 }
    };
}
function loadLocalDB() {
  if (!fs.existsSync(DB_FILE)) return createInitialDB();
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
let db = process.env.POSTGRES_URL ? createInitialDB() : loadLocalDB();
(db.services || []).forEach(s => { if (!Array.isArray(s.formFields)) s.formFields = []; if (typeof s.allowExtraFiles !== "boolean") s.allowExtraFiles = false; if (!Number.isFinite(Number(s.businessDiscountPercent))) s.businessDiscountPercent = 0; });
(db.orders || []).forEach(o => { if (!Array.isArray(o.files)) o.files = []; if (!o.formData) o.formData = {}; });
if (!Array.isArray(db.supportMessages)) db.supportMessages = [];
if (!Array.isArray(db.passwordResetCodes)) db.passwordResetCodes = [];
if (!Array.isArray(db.notifications)) db.notifications = [];
if (!Array.isArray(db.coupons)) db.coupons = [];
function notify(userId, text, target = {}) {
  const kind = target.kind || "general";
  const messageKinds = new Set(["support", "password-reset", "sms", "message"]);
  const category = target.category || (messageKinds.has(kind) ? "message" : "general");
  db.notifications.push({
    id: crypto.randomBytes(8).toString("hex"),
    userId,
    text: String(text).slice(0, 500),
    category,
    kind,
    targetId: target.targetId ?? null,
    customerId: target.customerId ?? null,
    read: false,
    createdAt: new Date().toISOString()
  });
}
if (!db.siteSettings) db.siteSettings = { headerTitle: "Customer Management", headerSubtitle: "Phase 5 — Order System", footerText: "Customer Management System • Phase 5 • Order + Top-up", uiLabels: {}, homepage: {}, colors: {}, logoUrl: "", replyFee: 0 };
if (!db.siteSettings.uiLabels || typeof db.siteSettings.uiLabels !== "object") db.siteSettings.uiLabels = {};
if (!db.siteSettings.homepage || typeof db.siteSettings.homepage !== "object") db.siteSettings.homepage = {};
if (!db.siteSettings.colors || typeof db.siteSettings.colors !== "object") db.siteSettings.colors = {};
if (typeof db.siteSettings.logoUrl !== "string") db.siteSettings.logoUrl = "";
if (typeof db.siteSettings.logoDriveFileId !== "string") db.siteSettings.logoDriveFileId = "";
// Older installations stored the logo in the public uploads directory.  Keep
// it working, but now expose only the currently configured logo.
if (db.siteSettings.logoUrl.startsWith("/uploads/")) db.siteSettings.logoUrl = `/api/public/logo/${path.basename(db.siteSettings.logoUrl)}`;
if (!Number.isFinite(Number(db.siteSettings.replyFee))) db.siteSettings.replyFee = 0;
if (!db.siteSettings.recoveryTexts || typeof db.siteSettings.recoveryTexts !== "object") db.siteSettings.recoveryTexts = { supportTitle: "Customer Support-এ Password Recovery Request", supportDescription: "Email মনে না থাকলে নিবন্ধিত মোবাইল নম্বর দিয়ে Admin-কে message পাঠান।", pendingMessage: "আপনার request পাঠানো হয়েছে। Admin reset না করা পর্যন্ত অপেক্ষা করুন অথবা Admin-কে কল করুন।", approvedMessage: "Admin password reset অনুমোদন করেছেন। নিবন্ধিত নম্বর দিয়ে Login চাপুন।", messagePlaceholder: "আমি password ভুলে গেছি, reset অনুমোদন চাই।" };
if (!db.siteSettings.topupConfig || typeof db.siteSettings.topupConfig !== "object") db.siteSettings.topupConfig = { bKash: "01989792828", Nagad: "01989792828", Cash: "Cash counter", others: [], message: "Top-up করার আগে সঠিক নম্বর ও নির্দেশনা দেখুন।" };
if (!Array.isArray(db.siteSettings.topupConfig.others)) db.siteSettings.topupConfig.others = [];
if (!db.managerPermissions || typeof db.managerPermissions !== "object") db.managerPermissions = { orders: true, topups: true, services: true, support: true, replies: true };
if (!db.next.supportMessage) db.next.supportMessage = 1;
function normalizePostgresUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(value);
    // pg's connection-string parser can let sslmode in the URL override the
    // explicit ssl object. Strip SSL query options so Vercel/Supabase-style
    // certificates do not fail with a self-signed certificate-chain error.
    ["sslmode", "sslcert", "sslkey", "sslrootcert", "sslcrl"].forEach(key => url.searchParams.delete(key));
    return url.toString();
  } catch {
    return String(value).replace(/([?&])sslmode=[^&]*/i, "$1").replace(/[?&]$/, "");
  }
}
const POSTGRES_CONNECTION_STRING = normalizePostgresUrl(process.env.POSTGRES_URL);
const statePool = POSTGRES_CONNECTION_STRING
  ? new Pool({ connectionString: POSTGRES_CONNECTION_STRING, ssl: { rejectUnauthorized: false } })
  : null;
let stateReadyPromise;
let writeQueue = Promise.resolve();
const GOOGLE_DRIVE_STATE_FILE_NAME = process.env.GOOGLE_DRIVE_STATE_FILE_NAME || "landhelpcenter-state.json";
let googleDriveStateFileId = process.env.GOOGLE_DRIVE_STATE_FILE_ID || "";
function normalizeState() {
  (db.services || []).forEach(s => { if (!Array.isArray(s.formFields)) s.formFields = []; if (typeof s.allowExtraFiles !== "boolean") s.allowExtraFiles = false; if (!Number.isFinite(Number(s.businessDiscountPercent))) s.businessDiscountPercent = 0; });
  (db.orders || []).forEach(o => { if (!Array.isArray(o.files)) o.files = []; if (!o.formData) o.formData = {}; });
  if (!Array.isArray(db.supportMessages)) db.supportMessages = [];
  if (!Array.isArray(db.passwordResetCodes)) db.passwordResetCodes = [];
  if (!Array.isArray(db.notifications)) db.notifications = [];
  if (!Array.isArray(db.coupons)) db.coupons = [];
  if (!db.next) db.next = { user: 3, topup: 1, service: 4, order: 1, transaction: 1, supportMessage: 1 };
  if (!db.next.supportMessage) db.next.supportMessage = 1;
  if (!db.sessions || typeof db.sessions !== "object") db.sessions = {};
}
async function ensureState() {
  if (stateReadyPromise) return stateReadyPromise;
  stateReadyPromise = (async () => {
    if (statePool) {
      await statePool.query("create table if not exists cms_app_state (state_key text primary key, payload jsonb not null, updated_at timestamptz not null default now())");
      const saved = await statePool.query("select payload from cms_app_state where state_key = 'primary'");
      if (saved.rowCount) db = saved.rows[0].payload;
      else {
        const seed = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, "utf8")) : createInitialDB();
        db = seed;
        await statePool.query("insert into cms_app_state (state_key, payload) values ('primary', $1::jsonb)", [JSON.stringify(db)]);
      }
      normalizeState();
      return;
    }
    if (googleDriveEnabled) {
      const saved = await loadGoogleDriveState();
      if (saved) db = saved;
      else {
        normalizeState();
        await saveGoogleDriveState(db);
      }
      normalizeState();
      return;
    }
    normalizeState();
  })().catch(error => {
    stateReadyPromise = null;
    throw error;
  });
  return stateReadyPromise;
}
function save() {
  if (!statePool && !googleDriveEnabled) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return Promise.resolve();
  }
  // Serialize writes so concurrent serverless requests never overwrite each other.
  writeQueue = writeQueue.then(async () => {
    await ensureState();
    if (statePool) {
      await statePool.query("update cms_app_state set payload = $1::jsonb, updated_at = now() where state_key = 'primary'", [JSON.stringify(db)]);
    } else {
      await saveGoogleDriveState(db);
    }
  }).catch(error => console.error("Persistent state save failed:", error.message));
  return writeQueue;
}
function nextId(k) {
  return db.next[k]++;
}
function token() {
  return crypto.randomBytes(32).toString("hex");
}
async function sendEmail(to, subject, text) {
  // Gmail requires a Google App Password; never place it in source code.
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error("Email is not configured. Set EMAIL_USER and EMAIL_PASS (Gmail App Password).");
  }
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to, subject, text
  });
}
async function sendSms(to, text) {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_FROM_NUMBER) {
    throw new Error("SMS is not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER.");
  }
  const body = new URLSearchParams({ To: to, From: process.env.TWILIO_FROM_NUMBER, Body: text });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
    method: "POST", headers: { Authorization: "Basic " + Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString("base64"), "Content-Type": "application/x-www-form-urlencoded" }, body
  });
  if (!response.ok) throw new Error(`SMS provider error: ${(await response.json().catch(() => ({}))).message || response.status}`);
}
function otpHash(code) { return crypto.createHash("sha256").update(String(code)).digest("hex"); }
function createOtp(userId, purpose, channel) {
  const code = String(crypto.randomInt(100000, 1000000));
  db.passwordResetCodes = db.passwordResetCodes.filter(x => x.expiresAt > Date.now() && !(x.userId === userId && x.purpose === purpose));
  db.passwordResetCodes.push({ userId, purpose, channel, codeHash: otpHash(code), expiresAt: Date.now() + 15 * 60 * 1000 });
  return code;
}
const sessions = new Map();

const GOOGLE_DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID || "";
// Final production storage: Google Drive only. Credentials stay in Vercel Environment Variables.
const googleDriveOAuthEnabled = Boolean(
  GOOGLE_DRIVE_FOLDER_ID && process.env.GOOGLE_DRIVE_CLIENT_ID &&
  process.env.GOOGLE_DRIVE_CLIENT_SECRET && process.env.GOOGLE_DRIVE_REFRESH_TOKEN
);
const googleDriveServiceAccountEnabled = Boolean(
  GOOGLE_DRIVE_FOLDER_ID && process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL &&
  process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY
);
const googleDriveEnabled = googleDriveOAuthEnabled || googleDriveServiceAccountEnabled;
let googleAccessToken = null;
let googleAccessTokenExpiresAt = 0;

function base64url(value) { return Buffer.from(value).toString("base64url"); }
async function googleDriveToken() {
  if (!googleDriveEnabled) throw new Error("Google Drive storage is not configured");
  if (googleAccessToken && googleAccessTokenExpiresAt > Date.now() + 60 * 1000) return googleAccessToken;
  if (googleDriveOAuthEnabled) {
    const body = new URLSearchParams({
      client_id: process.env.GOOGLE_DRIVE_CLIENT_ID,
      client_secret: process.env.GOOGLE_DRIVE_CLIENT_SECRET,
      refresh_token: process.env.GOOGLE_DRIVE_REFRESH_TOKEN,
      grant_type: "refresh_token"
    });
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result.access_token) throw new Error(`Google Drive authentication failed (${response.status})`);
    googleAccessToken = result.access_token;
    googleAccessTokenExpiresAt = Date.now() + Math.max(60, Number(result.expires_in || 3600) - 60) * 1000;
    return googleAccessToken;
  }
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = base64url(JSON.stringify({
    iss: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: "https://www.googleapis.com/auth/drive",
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600
  }));
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(`${header}.${claim}`); signer.end();
  const privateKey = String(process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY).replace(/\\n/g, "\n");
  const assertion = `${header}.${claim}.${signer.sign(privateKey, "base64url")}`;
  const body = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });
  const response = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) throw new Error(`Google Drive authentication failed (${response.status})`);
  googleAccessToken = result.access_token;
  googleAccessTokenExpiresAt = Date.now() + Math.max(60, Number(result.expires_in || 3600) - 60) * 1000;
  return googleAccessToken;
}
async function putGoogleDriveFile(name, file, metadata = {}) {
  if (!googleDriveEnabled) throw new Error("Google Drive storage is not configured");
  const boundary = `cms-${crypto.randomBytes(12).toString("hex")}`;
  const driveMetadata = JSON.stringify({
    name,
    parents: [GOOGLE_DRIVE_FOLDER_ID],
    description: String(metadata.description || "").slice(0, 1000),
    appProperties: { orderId: String(metadata.orderId || ""), customerId: String(metadata.customerId || "") }
  });
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${driveMetadata}\r\n--${boundary}\r\nContent-Type: ${file.mimetype || "application/octet-stream"}\r\n\r\n`),
    file.buffer,
    Buffer.from(`\r\n--${boundary}--`)
  ]);
  const response = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id,name,mimeType,size", {
    method: "POST",
    headers: { Authorization: `Bearer ${await googleDriveToken()}`, "Content-Type": `multipart/related; boundary=${boundary}` },
    body
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.id) throw new Error(`Google Drive upload failed (${response.status})`);
  return result.id;
}
async function getGoogleDriveFile(fileId) {
  if (!fileId) return null;
  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`, {
    headers: { Authorization: `Bearer ${await googleDriveToken()}` }
  });
  if (!response.ok) return null;
  return Buffer.from(await response.arrayBuffer());
}

async function loadGoogleDriveState() {
  if (!googleDriveEnabled) return null;
  const token = await googleDriveToken();
  if (!googleDriveStateFileId) {
    const q = `name = '${GOOGLE_DRIVE_STATE_FILE_NAME.replace(/'/g, "\\'")}' and '${GOOGLE_DRIVE_FOLDER_ID}' in parents and trashed = false`;
    const response = await fetch(`https://www.googleapis.com/drive/v3/files?corpora=allDrives&includeItemsFromAllDrives=true&supportsAllDrives=true&q=${encodeURIComponent(q)}&fields=files(id,name,mimeType,modifiedTime)&pageSize=1`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`Google Drive state lookup failed (${response.status})`);
    googleDriveStateFileId = result.files?.[0]?.id || "";
  }
  if (!googleDriveStateFileId) return null;
  const content = await getGoogleDriveFile(googleDriveStateFileId);
  if (!content) {
    googleDriveStateFileId = "";
    return null;
  }
  try { return JSON.parse(content.toString("utf8")); }
  catch { throw new Error("Google Drive state file is invalid JSON"); }
}

async function saveGoogleDriveState(nextState) {
  if (!googleDriveEnabled) throw new Error("Google Drive storage is not configured");
  const token = await googleDriveToken();
  const body = Buffer.from(JSON.stringify(nextState));
  let response;
  if (googleDriveStateFileId) {
    response = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(googleDriveStateFileId)}?uploadType=media&supportsAllDrives=true`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body
    });
  } else {
    const file = { originalname: GOOGLE_DRIVE_STATE_FILE_NAME, mimetype: "application/json", buffer: body, size: body.length };
    googleDriveStateFileId = await putGoogleDriveFile(GOOGLE_DRIVE_STATE_FILE_NAME, file, { description: "Land Help Center durable application state" });
    return googleDriveStateFileId;
  }
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Google Drive state save failed (${response.status})${detail ? `: ${detail.slice(0, 300)}` : ""}`);
  }
  return googleDriveStateFileId;
}

const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = path.basename(file.originalname || "file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120);
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${safe || "file"}`);
  }
});
const upload = multer({
  storage: googleDriveEnabled ? multer.memoryStorage() : diskStorage,
  limits: { fileSize: 50 * 1024 * 1024, files: 10 },
  fileFilter: (req, file, cb) => {
    const allowed = new Set([
      "application/pdf", "image/jpeg", "image/png", "image/webp",
      "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "text/plain", "application/zip", "application/x-zip-compressed"
    ]);
    if (!allowed.has(file.mimetype)) return cb(new Error("Unsupported file type"));
    cb(null, true);
  }
});
async function saveUploadedFiles(files, uploadedBy, orderId, orderNo = "") {
  const saved = [];
  if (process.env.VERCEL && !googleDriveEnabled) throw new Error("Google Drive storage is not configured. Configure the required Vercel Environment Variables before uploading files.");
  for (const f of files || []) {
    const safe = path.basename(f.originalname || "file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120) || "file";
    if (googleDriveEnabled) {
      const storedName = `${Date.now()}-${crypto.randomBytes(10).toString("hex")}-${safe}`;
      const driveFileId = await putGoogleDriveFile(`orders-${orderNo || orderId}-${storedName}`, f, { orderId, customerId: uploadedBy.customerId, description: `Land Help Center order ${orderNo || orderId}` });
      saved.push({ id: crypto.randomBytes(10).toString("hex"), orderId, originalName: f.originalname, storedName, storage: "google-drive", driveFileId, mimeType: f.mimetype || "application/octet-stream", size: f.size, uploadedBy: uploadedBy.id, uploadedByName: uploadedBy.name, uploadedAt: new Date().toISOString() });
    } else {
      saved.push({ id: crypto.randomBytes(10).toString("hex"), orderId, originalName: f.originalname, storedName: f.filename, storage: "local", driveFileId: null, mimeType: f.mimetype || "application/octet-stream", size: f.size, uploadedBy: uploadedBy.id, uploadedByName: uploadedBy.name, uploadedAt: new Date().toISOString() });
    }
  }
  return saved;
}

function currentUser(req) {
  const t = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const session = t ? (sessions.get(t) || db.sessions?.[t]) : null;
  if (!session || session.expiresAt <= Date.now()) {
    if (t) { sessions.delete(t); if (db.sessions) { delete db.sessions[t]; save(); } }
    return null;
  }
  return db.users.find(u => u.id === session.userId) || null;
}
function revokeSessions(userId) {
  for (const [key, session] of sessions) if (session.userId === userId) sessions.delete(key);
  if (!db.sessions) return;
  for (const [key, session] of Object.entries(db.sessions)) if (session.userId === userId) delete db.sessions[key];
}
function auth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Login required" });
  // Keep an active login alive across normal refreshes while still expiring
  // abandoned sessions after 30 days.
  if (session.expiresAt - Date.now() < 7 * 24 * 60 * 60 * 1000) {
    session.expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
    if (t && db.sessions?.[t]) db.sessions[t].expiresAt = session.expiresAt;
    save();
  }
  req.user = u;
  next();
}
function staff(req, res, next) {
  if (!["ADMIN", "MANAGER"].includes(req.user.role)) {
    return res.status(403).json({ error: "Admin/Manager access required" });
  }
  next();
}
function admin(req, res, next) {
  if (req.user.role !== "ADMIN") return res.status(403).json({ error: "Admin access required" });
  next();
}
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    customerId: u.customerId,
    name: u.name,
    phone: u.phone,
    email: u.email,
    role: u.role,
    balance: Number(u.balance || 0)
  };
}
function normalizeFormFields(fields) {
  if (!Array.isArray(fields)) return [];
  const allowed = new Set(["text", "textarea", "number", "date", "select", "file", "checkbox"]);
  return fields.map((f, i) => ({
    id: String(f.id || `field_${Date.now()}_${i}`),
    label: String(f.label || "").trim(),
    type: allowed.has(f.type) ? f.type : "text",
    required: Boolean(f.required),
    options: Array.isArray(f.options) ? f.options.map(x => String(x).trim()).filter(Boolean) : []
  })).filter(f => f.label);
}
function customerUsers() {
  return db.users.filter(u => ["CUSTOMER", "BUSINESS_CUSTOMER"].includes(u.role));
}
function isClient(user) { return ["CUSTOMER", "BUSINESS_CUSTOMER"].includes(user.role); }
function businessPrice(service) { return service.paid ? Number((Number(service.price || 0) * (1 - Number(service.businessDiscountPercent || 0) / 100)).toFixed(2)) : 0; }
function aggregates() {
  const customers = customerUsers();
  const ids = new Set(customers.map(u => u.id));
  const currentCustomerBalance = customers.reduce((a, u) => a + Number(u.balance || 0), 0);
  const totalSpent = db.orders
    .filter(o => o.status === "APPROVED" && ids.has(o.userId))
    .reduce((a, o) => a + Number(o.amount || 0), 0);
  const totalCustomerFunds = db.topups
    .filter(t => t.status === "APPROVED" && ids.has(t.userId))
    .reduce((a, t) => a + Number(t.amount || 0), 0);
  return {
    customers: customers.length,
    totalCustomerFunds,
    totalSpent,
    currentCustomerBalance,
    pendingTopups: db.topups.filter(t => t.status === "PENDING" && ids.has(t.userId)).length,
    pendingOrders: db.orders.filter(o => o.status === "PENDING" && ids.has(o.userId)).length,
    approvedOrders: db.orders.filter(o => o.status === "APPROVED" && ids.has(o.userId)).length
  };
}

app.get("/api/health", (req, res) => res.json({ ok: true, phase: "5.3" }));
app.get("/api/site-settings", (req, res) => res.json(db.siteSettings));

// ---------- Authentication ----------
app.post("/api/customer/register", authRateLimit, async (req, res) => {
  const { name, phone, email = "", password } = req.body || {};
  const normalizedPhone = normalizeLoginIdentifier(phone);
  if (!String(name || "").trim() || !String(phone || "").trim() || !String(password || "")) {
    return res.status(400).json({ error: "নাম, মোবাইল ও পাসওয়ার্ড দিন" });
  }
  if (String(name).trim().length > 100 || String(phone).trim().length > 30 || String(email).trim().length > 150 || String(password).length < 8) {
    return res.status(400).json({ error: "নাম/মোবাইল সঠিক দিন এবং পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের ব্যবহার করুন" });
  }
  if (db.users.some(u => normalizeLoginIdentifier(u.phone) === normalizedPhone)) {
    return res.status(409).json({ error: "এই মোবাইল/Username আগে ব্যবহার হয়েছে" });
  }
  const id = nextId("user");
  const hp = hashPassword(password);
  const u = {
    id,
    customerId: `CUS-${String(id).padStart(5, "0")}`,
    name: String(name).trim(),
    phone: normalizedPhone,
    email: String(email || "").trim(),
    role: "CUSTOMER",
    balance: 0,
    ...hp
  };
  db.users.push(u);
  await save();
  res.json({ success: true, customer: publicUser(u) });
});

app.post("/api/customer/login", authRateLimit, async (req, res) => {
  const { phone, password } = req.body || {};
  const identifier = normalizeLoginIdentifier(phone);
  if (rejectTooManyLoginAttempts(req, res, identifier)) return;
  const u = db.users.find(x => normalizeLoginIdentifier(x.phone) === identifier);
  // A support-approved reset uses the temporary password generated by the
  // administrator. Never reveal that password from the login endpoint.
  if (!u || !verifyPassword(password, u)) {
    recordFailedLogin(req, identifier);
    return res.status(401).json({ error: "Username/Mobile অথবা Password ভুল" });
  }
  const t = token();
  const session = { userId: u.id, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 };
  sessions.set(t, session);
  if (!db.sessions) db.sessions = {};
  db.sessions[t] = session;
  clearFailedLogin(req, identifier);
  await save();
  res.json({ success: true, token: t, customer: publicUser(u), mustSetPassword: Boolean(u.forcePasswordReset) });
});
app.post("/api/customer/set-password", auth, async (req, res) => {
  const password = String(req.body?.password || "");
  if (password.length < 8) return res.status(400).json({ error: "কমপক্ষে ৮ অক্ষরের নতুন পাসওয়ার্ড দিন" });
  Object.assign(req.user, hashPassword(password)); delete req.user.forcePasswordReset; delete req.user.oneTimePassword; delete req.user.resetMessage; await save();
  res.json({ success: true });
});

app.post("/api/customer/logout", auth, (req, res) => {
  const t = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (t) { sessions.delete(t); if (db.sessions) delete db.sessions[t]; save(); }
  res.json({ success: true });
});
app.get("/api/customer/me", auth, (req, res) => res.json({ customer: publicUser(req.user) }));

// Customer self-recovery: phone plus the registration email (or Customer ID for
// accounts created without email) is required. Staff passwords can only be reset
// by an authenticated administrator below.
app.post("/api/customer/password-recovery/request", authRateLimit, async (req, res) => {
  const { phone, channel } = req.body || {};
  const normalizedPhone = normalizeLoginIdentifier(phone);
  const u = db.users.find(x => isClient(x) && normalizeLoginIdentifier(x.phone) === normalizedPhone);
  if (!u || !["email", "sms"].includes(channel)) return res.status(400).json({ error: "সঠিক মোবাইল ও Email/SMS মাধ্যম নির্বাচন করুন" });
  if (channel === "email" && !u.email) return res.status(400).json({ error: "এই account-এ Email নেই; SMS OTP ব্যবহার করুন অথবা Admin-এর সঙ্গে যোগাযোগ করুন" });
  const code = createOtp(u.id, "customer-reset", channel);
  try {
    const text = `Customer Management System OTP: ${code}. এটি ১৫ মিনিট কার্যকর। কাউকে কোডটি দেবেন না।`;
    if (channel === "email") await sendEmail(u.email, "Password reset OTP", text); else await sendSms(u.phone, text);
    save(); res.json({ success: true, message: channel === "email" ? "OTP আপনার নিবন্ধিত Email-এ পাঠানো হয়েছে" : "OTP আপনার মোবাইলে SMS করা হয়েছে" });
  } catch (err) { db.passwordResetCodes = db.passwordResetCodes.filter(x => x.codeHash !== otpHash(code)); res.status(503).json({ error: `OTP পাঠানো যায়নি: ${err.message}` }); }
});
app.post("/api/customer/password-recovery", authRateLimit, (req, res) => {
  const { phone, code, newPassword } = req.body || {};
  if (String(newPassword || "").length < 8) return res.status(400).json({ error: "কমপক্ষে ৮ অক্ষরের নতুন পাসওয়ার্ড দিন" });
  const u = db.users.find(x => isClient(x) && x.phone === String(phone || "").trim());
  const reset = u && db.passwordResetCodes.find(x => x.userId === u.id && x.purpose === "customer-reset" && x.codeHash === otpHash(code) && x.expiresAt > Date.now());
  if (!reset) return res.status(400).json({ error: "OTP ভুল অথবা মেয়াদ শেষ" });
  Object.assign(u, hashPassword(newPassword)); db.passwordResetCodes = db.passwordResetCodes.filter(x => x !== reset);
  revokeSessions(u.id);
  save(); res.json({ success: true, message: "পাসওয়ার্ড পরিবর্তন হয়েছে। এখন নতুন পাসওয়ার্ড দিয়ে লগইন করুন।" });
});

// The administrator reset code is delivered only to the configured mailbox.
app.post("/api/admin/password-recovery/request", authRateLimit, async (req, res) => {
  const u = db.users.find(x => x.role === "ADMIN");
  if (!u) return res.status(404).json({ error: "Admin account পাওয়া যায়নি" });
  const email = String(req.body?.email || "").trim();
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "সঠিক Email address লিখুন" });
  if (email.toLowerCase() !== ADMIN_RESET_EMAIL.toLowerCase()) return res.status(400).json({ error: "নিরাপত্তার কারণে এই Email-এ reset code পাঠানো যাবে না" });
  const code = createOtp(u.id, "admin-reset", "email");
  db.passwordResetCodes[db.passwordResetCodes.length - 1].targetEmail = email;
  try {
    await sendEmail(email, "Customer Management System — Admin password reset OTP", `Your administrator password-reset OTP is: ${code}\nIt expires in 15 minutes. If you did not request this, ignore this email.`);
    save();
    res.json({ success: true, message: "Reset code আপনার দেওয়া Email-এ পাঠানো হয়েছে" });
  } catch (err) {
    db.passwordResetCodes = db.passwordResetCodes.filter(x => x.codeHash !== otpHash(code));
    res.status(503).json({ error: `ইমেইল পাঠানো যায়নি: ${err.message}` });
  }
});
app.post("/api/admin/password-recovery/confirm", authRateLimit, (req, res) => {
  const { code, newPassword, email } = req.body || {};
  if (String(newPassword || "").length < 8) return res.status(400).json({ error: "কমপক্ষে ৮ অক্ষরের নতুন পাসওয়ার্ড দিন" });
  const hash = otpHash(code);
  const reset = db.passwordResetCodes.find(x => x.purpose === "admin-reset" && x.targetEmail === String(email || "").trim() && x.codeHash === hash && x.expiresAt > Date.now());
  if (!reset) return res.status(400).json({ error: "কোডটি ভুল অথবা মেয়াদ শেষ" });
  const u = db.users.find(x => x.id === reset.userId && x.role === "ADMIN");
  if (!u) return res.status(404).json({ error: "Admin account পাওয়া যায়নি" });
  Object.assign(u, hashPassword(newPassword));
  db.passwordResetCodes = db.passwordResetCodes.filter(x => x !== reset);
  revokeSessions(u.id);
  save();
  res.json({ success: true, message: "Admin password পরিবর্তন হয়েছে। নতুন password দিয়ে Login করুন।" });
});

// ---------- Public services ----------
app.get("/api/services", (req, res) => {
  res.json(db.services.filter(s => s.active).map(s => ({ ...s, businessPrice: businessPrice(s) })));
});
app.post("/api/coupons/preview", auth, (req, res) => {
  if (!isClient(req.user)) return res.status(403).json({ error: "Customer access required" });
  const s = db.services.find(x => x.id == req.body?.serviceId && x.active);
  if (!s) return res.status(404).json({ error: "Service পাওয়া যায়নি" });
  let amount = req.user.role === "BUSINESS_CUSTOMER" ? businessPrice(s) : (s.paid ? Number(s.price) : 0);
  const code = String(req.body?.couponCode || "").trim().toUpperCase();
  const coupon = db.coupons.find(c => c.code === code && c.active && (!c.expiresAt || new Date(c.expiresAt) > new Date()));
  if (!coupon) return res.status(400).json({ error: "Coupon code সঠিক নয়" });
  const discountedAmount = Number((amount * (1 - Number(coupon.percent) / 100)).toFixed(2));
  res.json({ success: true, percent: Number(coupon.percent), originalAmount: amount, discountedAmount, balance: Number(req.user.balance || 0), balanceAfter: Number((Number(req.user.balance || 0) - discountedAmount).toFixed(2)) });
});

// ---------- Service management: Admin + Manager ----------
app.post("/api/services", auth, staff, (req, res) => {
  const { title, description = "", price = 0, paid = true, formFields = [], allowExtraFiles = false, businessDiscountPercent = 0 } = req.body || {};
  if (!String(title || "").trim()) return res.status(400).json({ error: "সেবার নাম দিন" });
  const s = {
    id: nextId("service"),
    title: String(title).trim(),
    description: String(description || "").trim(),
    price: Number(price) >= 0 ? Number(price) : 0,
    paid: Boolean(paid),
    active: true,
    formFields: normalizeFormFields(formFields),
    allowExtraFiles: Boolean(allowExtraFiles),
    businessDiscountPercent: Math.min(100, Math.max(0, Number(businessDiscountPercent) || 0))
  };
  db.services.push(s);
  db.users.filter(u => isClient(u)).forEach(u => notify(u.id, `নতুন Service/Post প্রকাশ হয়েছে: ${s.title}`, { category: "general", kind: "service", targetId: s.id }));
  save();
  res.json({ success: true, service: s });
});
app.put("/api/services/:id", auth, staff, (req, res) => {
  const s = db.services.find(x => x.id == req.params.id);
  if (!s) return res.status(404).json({ error: "Service not found" });
  s.title = String(req.body.title ?? s.title).trim();
  s.description = String(req.body.description ?? s.description).trim();
  s.price = Number(req.body.price ?? s.price);
  if (!Number.isFinite(s.price) || s.price < 0) s.price = 0;
  if (req.body.paid !== undefined) s.paid = Boolean(req.body.paid);
  if (req.body.formFields !== undefined) s.formFields = normalizeFormFields(req.body.formFields);
  if (req.body.allowExtraFiles !== undefined) s.allowExtraFiles = Boolean(req.body.allowExtraFiles);
  if (req.body.businessDiscountPercent !== undefined) s.businessDiscountPercent = Math.min(100, Math.max(0, Number(req.body.businessDiscountPercent) || 0));
  if (req.user.role === "ADMIN" && req.body.active !== undefined) s.active = Boolean(req.body.active);
  save();
  res.json({ success: true, service: s });
});
app.delete("/api/services/:id", auth, admin, (req, res) => {
  const s = db.services.find(x => x.id == req.params.id);
  if (!s) return res.status(404).json({ error: "Service not found" });
  s.active = false;
  save();
  res.json({ success: true });
});

// ---------- Top-up ----------
app.post("/api/topups", auth, async (req, res) => {
  const { method, amount, transactionId } = req.body || {};
  const a = Number(amount);
  if (!["bKash", "Nagad", "Cash"].includes(method)) {
    return res.status(400).json({ error: "Payment method invalid" });
  }
  if (!a || a <= 0 || !String(transactionId || "").trim()) {
    return res.status(400).json({ error: "Amount ও Transaction ID দিন" });
  }
  if (db.topups.some(t => t.transactionId === String(transactionId).trim())) {
    return res.status(409).json({ error: "এই Transaction ID আগে ব্যবহার হয়েছে" });
  }
  const t = {
    id: nextId("topup"),
    userId: req.user.id,
    customerId: req.user.customerId,
    method,
    amount: a,
    transactionId: String(transactionId).trim(),
    status: "PENDING",
    createdAt: new Date().toISOString(),
    reviewedBy: null
  };
  db.topups.push(t);
  db.users.filter(u => ["ADMIN", "MANAGER"].includes(u.role)).forEach(u =>
    notify(u.id, String(req.user.customerId) + " নতুন Top-up request: " + a + " টাকা (" + method + ")", {
      category: "message", kind: "topup", targetId: t.id, customerId: req.user.customerId
    })
  );
  await save();
  res.json({ success: true, topup: t });
});
app.get("/api/topups", auth, (req, res) => {
  const list = isClient(req.user)
    ? db.topups.filter(t => t.userId === req.user.id)
    : db.topups;
  res.json(list);
});
app.post("/api/topups/:id/approve", auth, staff, (req, res) => {
  const t = db.topups.find(x => x.id == req.params.id);
  if (!t || t.status !== "PENDING") return res.status(400).json({ error: "Pending top-up not found" });
  const u = db.users.find(x => x.id === t.userId);
  if (!u || !isClient(u)) return res.status(400).json({ error: "Customer not found" });
  t.status = "APPROVED";
  t.reviewedBy = req.user.id;
  t.reviewedAt = new Date().toISOString();
  u.balance = Number(u.balance) + Number(t.amount);
  notify(u.id, `আপনার Top-up ${t.amount} টাকা APPROVED হয়েছে। নতুন Balance: ${u.balance} টাকা`, { category: "general", kind: "topup", targetId: t.id, customerId: u.customerId });
  db.transactions.push({
    id: nextId("transaction"), userId: u.id, type: "TOPUP",
    amount: t.amount, balanceAfter: u.balance, reference: `TOPUP-${t.id}`,
    createdAt: new Date().toISOString()
  });
  save();
  res.json({ success: true, balance: u.balance });
});
app.post("/api/topups/:id/reject", auth, staff, (req, res) => {
  const t = db.topups.find(x => x.id == req.params.id);
  if (!t || t.status !== "PENDING") return res.status(400).json({ error: "Pending top-up not found" });
  t.status = "REJECTED";
  t.reviewedBy = req.user.id;
  t.reviewedAt = new Date().toISOString();
  t.reason = req.body.reason || "Rejected";
  notify(u.id, `আপনার Top-up request ${t.amount} টাকা REJECTED হয়েছে। কারণ: ${t.reason}`, { category: "general", kind: "topup", targetId: t.id, customerId: u.customerId });
  save();
  res.json({ success: true });
});

// ---------- Orders + documents ----------
function validateOrderForm(service, formData) {
  const fields = Array.isArray(service.formFields) ? service.formFields : [];
  const data = formData && typeof formData === "object" ? formData : {};
  for (const f of fields) {
    const value = data[f.id];
    const empty = value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length);
    if (f.required && f.type !== "file" && empty) return `${f.label} পূরণ করুন`;
    if (f.type === "select" && !empty && f.options.length && !f.options.includes(String(value))) return `${f.label} সঠিকভাবে নির্বাচন করুন`;
  }
  return null;
}
function serviceAllowsFiles(service) {
  return Boolean(service.allowExtraFiles) || (service.formFields || []).some(f => f.type === "file");
}

app.post("/api/orders", auth, upload.array("files", 10), async (req, res) => {
  if (!isClient(req.user)) return res.status(403).json({ error: "শুধু Customer বা Business Customer Order করতে পারবে" });
  const s = db.services.find(x => x.id == req.body.serviceId && x.active);
  if (!s) return res.status(404).json({ error: "Service not found" });
  let formData = {};
  try { formData = req.body.formData ? JSON.parse(req.body.formData) : {}; } catch { return res.status(400).json({ error: "Form data invalid" }); }
  const formError = validateOrderForm(s, formData);
  if (formError) return res.status(400).json({ error: formError });
  if (req.files?.length && !serviceAllowsFiles(s)) return res.status(400).json({ error: "এই Service-এ ফাইল/ডকুমেন্ট যুক্ত করার অনুমতি নেই" });
  // The browser keeps the optional description inside formData so that the
  // same request format works with both dynamic and normal service forms.
  const details = String(req.body.details || formData.__extra || "").trim();
  if (!(Array.isArray(s.formFields) && s.formFields.length) && !details) return res.status(400).json({ error: "Order details দিন" });
  let amount = req.user.role === "BUSINESS_CUSTOMER" ? businessPrice(s) : (s.paid ? Number(s.price) : 0);
  const couponCode = String(req.body.couponCode || "").trim().toUpperCase();
  let coupon = null;
  if (couponCode) {
    coupon = db.coupons.find(c => c.code === couponCode && c.active && (!c.expiresAt || new Date(c.expiresAt) > new Date()));
    if (!coupon) return res.status(400).json({ error: "Coupon code সঠিক নয় অথবা মেয়াদ শেষ" });
    amount = Number((amount * (1 - Number(coupon.percent || 0) / 100)).toFixed(2));
  }
  if (amount > 0 && req.user.balance < amount) return res.status(400).json({ error: `পর্যাপ্ত Balance নেই। প্রয়োজন ${amount} টাকা, বর্তমান ${req.user.balance} টাকা` });
  const o = {
    id: nextId("order"), orderNo: `ORD-${String(db.next.order - 1).padStart(5, "0")}`,
    userId: req.user.id, customerId: req.user.customerId, serviceId: s.id, serviceTitle: s.title,
    details, formData, formFields: JSON.parse(JSON.stringify(s.formFields || [])), files: [], amount, status: "PENDING", createdAt: new Date().toISOString(),
    approvedBy: null, approvedAt: null, note: "", couponCode: coupon?.code || "", couponPercent: coupon?.percent || 0
  };
  o.files = await saveUploadedFiles(req.files, req.user, o.id, o.orderNo);
  db.orders.push(o);
  db.users.filter(u => ["ADMIN", "MANAGER"].includes(u.role)).forEach(u => notify(u.id, `${o.customerId} নতুন Order করেছেন: ${o.orderNo}`, { category: "general", kind: "order", targetId: o.id, customerId: o.customerId }));
  save();
  res.json({ success: true, order: o });
});
app.get("/api/orders", auth, (req, res) => {
  const list = isClient(req.user) ? db.orders.filter(o => o.userId === req.user.id) : db.orders;
  res.json(list);
});
app.post("/api/orders/:id/files", auth, staff, upload.array("files", 10), async (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o) return res.status(404).json({ error: "Order not found" });
  if (!req.files?.length) return res.status(400).json({ error: "একটি বা একাধিক file নির্বাচন করুন" });
  if (!Array.isArray(o.files)) o.files = [];
  const added = await saveUploadedFiles(req.files, req.user, o.id, o.orderNo);
  o.files.push(...added); save();
  res.json({ success: true, files: added, order: o });
});
app.get("/api/files/:fileId", auth, async (req, res) => {
  const o = db.orders.find(x => Array.isArray(x.files) && x.files.some(f => f.id === req.params.fileId));
  if (!o) return res.status(404).json({ error: "File not found" });
  const f = o.files.find(x => x.id === req.params.fileId);
  if (isClient(req.user) && o.userId !== req.user.id) return res.status(403).json({ error: "Access denied" });
  if (f.storage === "google-drive") {
    const content = await getGoogleDriveFile(f.driveFileId);
    if (!content) return res.status(404).json({ error: "Stored file not found" });
    res.setHeader("Content-Type", f.mimeType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(f.originalName)}`);
    return res.send(content);
  }
    const full = path.join(UPLOAD_DIR, f.storedName);
  if (!fs.existsSync(full)) return res.status(404).json({ error: "Stored file not found" });
  res.download(full, f.originalName);
});
app.post("/api/orders/:id/approve", auth, staff, (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o || o.status !== "PENDING") return res.status(400).json({ error: "Pending order not found" });
  const u = db.users.find(x => x.id === o.userId);
  if (!u || !isClient(u)) return res.status(400).json({ error: "Customer not found" });
  if (o.amount > 0 && u.balance < o.amount) return res.status(400).json({ error: "Customer balance is insufficient" });
  if (o.amount > 0) {
    u.balance -= o.amount;
    db.transactions.push({ id: nextId("transaction"), userId: u.id, type: "ORDER", amount: -o.amount, balanceAfter: u.balance, reference: o.orderNo, createdAt: new Date().toISOString() });
  }
  o.status = "APPROVED"; o.approvedBy = req.user.id; o.approvedAt = new Date().toISOString(); o.note = req.body.note || "";
  notify(o.userId, `${o.orderNo} APPROVED হয়েছে।${o.note ? " Note: " + o.note : ""}`, { category: "general", kind: "order", targetId: o.id, customerId: o.customerId });
  save(); res.json({ success: true, balance: u.balance, order: o });
});
app.post("/api/orders/:id/reject", auth, staff, (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o || o.status !== "PENDING") return res.status(400).json({ error: "Pending order not found" });
  o.status = "REJECTED"; o.approvedBy = req.user.id; o.approvedAt = new Date().toISOString(); o.note = req.body.note || "";
  notify(o.userId, `${o.orderNo} REJECTED হয়েছে.${o.note ? " Note: " + o.note : ""}`, { category: "general", kind: "order", targetId: o.id, customerId: o.customerId });
  save(); res.json({ success: true });
});
// A customer may send one correction reply after an approved order.  Files are
// stored with the order so the staff and that customer can download them safely.
app.post("/api/orders/:id/reply", auth, upload.array("files", 10), async (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o || o.userId !== req.user.id || !isClient(req.user)) return res.status(404).json({ error: "Order পাওয়া যায়নি" });
  if (o.status !== "APPROVED") return res.status(400).json({ error: "শুধু Confirm হওয়া Order-এ reply দেওয়া যাবে" });
  if (o.customerReply) return res.status(400).json({ error: "এই Order-এ একবার reply ইতিমধ্যে দেওয়া হয়েছে" });
  const message = String(req.body?.message || "").trim();
  if (!message && !req.files?.length) return res.status(400).json({ error: "Reply লিখুন অথবা file যুক্ত করুন" });
  const replyFee = Math.max(0, Number(db.siteSettings.replyFee || 0));
  if (replyFee > 0 && Number(req.user.balance || 0) < replyFee) return res.status(400).json({ error: `Reply fee দেওয়ার জন্য পর্যাপ্ত Balance নেই। প্রয়োজন ${replyFee} টাকা` });
  if (replyFee > 0) {
    req.user.balance = Number(req.user.balance) - replyFee;
    db.transactions.push({ id: nextId("transaction"), userId: req.user.id, type: "ORDER_REPLY_FEE", amount: -replyFee, balanceAfter: req.user.balance, reference: o.orderNo, createdAt: new Date().toISOString() });
  }
  if (!Array.isArray(o.files)) o.files = [];
  const files = await saveUploadedFiles(req.files, req.user, o.id, o.orderNo);
  o.files.push(...files);
  o.customerReply = { message, files: files.map(f => f.id), fee: replyFee, status: "PENDING", createdAt: new Date().toISOString() };
  db.users.filter(u => ["ADMIN", "MANAGER"].includes(u.role)).forEach(u => notify(u.id, `${o.customerId} একটি Order Reply পাঠিয়েছেন`, { category: "general", kind: "order-reply", targetId: o.id, customerId: o.customerId }));
  save(); res.json({ success: true, order: o });
});
app.post("/api/orders/:id/reply/confirm", auth, staff, (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o?.customerReply || o.customerReply.status !== "PENDING") return res.status(400).json({ error: "Pending reply পাওয়া যায়নি" });
  o.customerReply.status = "CONFIRMED"; o.customerReply.confirmedBy = req.user.id; o.customerReply.confirmedAt = new Date().toISOString();
  notify(o.userId, `${o.orderNo} এর Reply Admin/Manager confirm করেছেন`, { category: "general", kind: "order", targetId: o.id, customerId: o.customerId }); save(); res.json({ success: true });
});
// Admin may correct, cancel, or permanently remove any order when necessary.
app.put("/api/admin/orders/:id", auth, admin, (req, res) => {
  const o = db.orders.find(x => x.id == req.params.id);
  if (!o) return res.status(404).json({ error: "Order not found" });
  const requestedStatus = req.body.status;
  if (requestedStatus !== undefined && !["PENDING", "APPROVED", "REJECTED", "CANCELLED"].includes(requestedStatus)) {
    return res.status(400).json({ error: "Invalid order status" });
  }
  const previousStatus = o.status;
  const nextStatus = requestedStatus === undefined ? previousStatus : requestedStatus;
  const u = db.users.find(x => x.id === o.userId);
  if (!u || !isClient(u)) return res.status(400).json({ error: "Customer not found" });

  // Keep the admin edit screen financially consistent with the normal
  // Approve/Reject buttons: approving charges once; moving an approved order
  // back to a non-approved state refunds that charge once.
  if (previousStatus !== "APPROVED" && nextStatus === "APPROVED") {
    if (o.amount > 0 && Number(u.balance || 0) < Number(o.amount)) {
      return res.status(400).json({ error: "Customer balance is insufficient" });
    }
    if (o.amount > 0) {
      u.balance = Number(u.balance) - Number(o.amount);
      db.transactions.push({ id: nextId("transaction"), userId: u.id, type: "ORDER", amount: -Number(o.amount), balanceAfter: u.balance, reference: o.orderNo, createdAt: new Date().toISOString() });
    }
    o.approvedBy = req.user.id;
    o.approvedAt = new Date().toISOString();
  } else if (previousStatus === "APPROVED" && nextStatus !== "APPROVED") {
    if (o.amount > 0) {
      u.balance = Number(u.balance) + Number(o.amount);
      db.transactions.push({ id: nextId("transaction"), userId: u.id, type: "ORDER_REFUND", amount: Number(o.amount), balanceAfter: u.balance, reference: o.orderNo, createdAt: new Date().toISOString() });
    }
    o.approvedBy = null;
    o.approvedAt = null;
  }
  if (req.body.serviceTitle !== undefined) o.serviceTitle = String(req.body.serviceTitle).trim().slice(0, 200);
  if (req.body.details !== undefined) o.details = String(req.body.details).trim().slice(0, 5000);
  if (req.body.note !== undefined) o.note = String(req.body.note).trim().slice(0, 2000);
  o.status = nextStatus;
  o.updatedAt = new Date().toISOString(); o.updatedBy = req.user.id;
  if (previousStatus !== nextStatus) {
    notify(o.userId, `${o.orderNo} status ${nextStatus} হয়েছে.${o.note ? " Note: " + o.note : ""}`, { category: "general", kind: "order", targetId: o.id, customerId: o.customerId });
  }
  save(); res.json({ success: true, order: o, balance: u.balance });
});
app.delete("/api/admin/orders/:id", auth, admin, (req, res) => {
  const index = db.orders.findIndex(x => x.id == req.params.id);
  if (index < 0) return res.status(404).json({ error: "Order not found" });
  db.orders.splice(index, 1); save(); res.json({ success: true });
});

// ---------- Transactions / admin ----------
app.get("/api/transactions", auth, (req, res) => {
  res.json(isClient(req.user)
    ? db.transactions.filter(t => t.userId === req.user.id)
    : db.transactions);
});
app.get("/api/admin/users", auth, staff, (req, res) => res.json(db.users.map(publicUser)));
app.put("/api/admin/users/:id/role", auth, admin, (req, res) => {
  const u = db.users.find(x => x.id == req.params.id);
  if (!u) return res.status(404).json({ error: "User not found" });
  if (!["CUSTOMER", "BUSINESS_CUSTOMER", "EDITOR", "MANAGER", "ADMIN"].includes(req.body.role)) {
    return res.status(400).json({ error: "Invalid role" });
  }
  u.role = req.body.role;
  save();
  res.json({ success: true, user: publicUser(u) });
});
app.put("/api/admin/users/:id/balance", auth, admin, (req, res) => {
  const u = db.users.find(x => x.id == req.params.id);
  const b = Number(req.body.balance);
  if (!u || !isClient(u) || !Number.isFinite(b) || b < 0) {
    return res.status(400).json({ error: "Invalid customer balance" });
  }
  const delta = b - Number(u.balance || 0);
  u.balance = b;
  if (delta !== 0) {
    db.transactions.push({
      id: nextId("transaction"), userId: u.id, type: "ADMIN_ADJUSTMENT",
      amount: delta, balanceAfter: b, reference: "ADMIN",
      createdAt: new Date().toISOString()
    });
  }
  save();
  res.json({ success: true, user: publicUser(u) });
});
app.put("/api/admin/users/:id/password", auth, admin, (req, res) => {
  const u = db.users.find(x => x.id == req.params.id);
  const password = String(req.body?.password || "");
  if (!u || password.length < 8) return res.status(400).json({ error: "কমপক্ষে ৮ অক্ষরের নতুন পাসওয়ার্ড দিন" });
  Object.assign(u, hashPassword(password));
  revokeSessions(u.id);
  save();
  res.json({ success: true });
});
app.delete("/api/admin/users/:id", auth, admin, (req, res) => {
  const id = Number(req.params.id);
  const index = db.users.findIndex(u => u.id === id);
  const u = db.users[index];
  if (!u) return res.status(404).json({ error: "User not found" });
  if (u.id === req.user.id || u.role === "ADMIN") return res.status(403).json({ error: "নিজের বা অন্য Admin account Delete করা যাবে না" });
  db.users.splice(index, 1);
  revokeSessions(id);
  db.supportMessages = (db.supportMessages || []).filter(m => m.customerId !== id && m.senderId !== id);
  db.notifications = (db.notifications || []).filter(n => n.userId !== id);
  save(); res.json({ success: true });
});

// ---------- Customer support chat ----------
app.get("/api/support/messages", auth, (req, res) => {
  const list = isClient(req.user)
    ? db.supportMessages.filter(m => m.customerId === req.user.id)
    : db.supportMessages;
  res.json(list);
});
app.post("/api/support/messages", auth, (req, res) => {
  const message = String(req.body?.message || "").trim();
  const customerId = isClient(req.user) ? req.user.id : Number(req.body?.customerId);
  const customer = db.users.find(u => u.id === customerId && isClient(u));
  if (!customer || !message) return res.status(400).json({ error: "Customer এবং বার্তা দিন" });
  db.supportMessages.push({
    id: nextId("supportMessage"), customerId: customer.id, customerName: customer.name,
    senderId: req.user.id, senderName: req.user.name, senderRole: req.user.role,
    message, createdAt: new Date().toISOString()
  });
  if (isClient(req.user)) db.users.filter(u => ["ADMIN", "MANAGER"].includes(u.role)).forEach(u => notify(u.id, `${req.user.customerId} থেকে নতুন Support message`, { category: "message", kind: "support", targetId: customer.id, customerId: req.user.customerId }));
  else notify(customer.id, "Admin/Manager আপনার Support message-এর reply দিয়েছেন", { category: "message", kind: "support", targetId: customer.id, customerId: customer.customerId });
  save();
  res.json({ success: true });
});
app.get("/api/notifications", auth, (req, res) => {
  if (!Array.isArray(db.notifications)) db.notifications = [];
  res.json(db.notifications.filter(n => n && n.userId === req.user.id).slice(-100).reverse());
});
app.post("/api/notifications/read", auth, (req, res) => {
  const now = new Date().toISOString();
  let count = 0;
  (db.notifications || []).forEach(n => {
    if (n && n.userId === req.user.id && !n.read) { n.read = true; n.readAt = now; count++; }
  });
  save();
  res.json({ success: true, count });
});
app.post("/api/notifications/:id/read", auth, (req, res) => {
  const n = (db.notifications || []).find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!n) return res.status(404).json({ error: "Notification পাওয়া যায়নি" });
  n.read = true;
  n.readAt = new Date().toISOString();
  save();
  res.json({ success: true });
});
app.get("/api/admin/coupons", auth, admin, (req, res) => res.json(db.coupons));
app.post("/api/admin/coupons", auth, admin, (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase().replace(/[^A-Z0-9_-]/g, "");
  const percent = Number(req.body?.percent);
  if (code.length < 3 || !Number.isFinite(percent) || percent <= 0 || percent > 100) return res.status(400).json({ error: "সঠিক coupon code এবং 1-100 শতাংশ দিন" });
  if (db.coupons.some(c => c.code === code)) return res.status(409).json({ error: "এই coupon code আগে আছে" });
  db.coupons.push({ id: crypto.randomBytes(8).toString("hex"), code, percent, active: true, expiresAt: req.body?.expiresAt || null, createdAt: new Date().toISOString() }); save();
  res.json({ success: true });
});
app.post("/api/admin/users/:id/reset-login", auth, admin, (req, res) => {
  const u = db.users.find(x => x.id == req.params.id && isClient(x));
  if (!u) return res.status(404).json({ error: "Customer পাওয়া যায়নি" });
  const oneTimePassword = String(crypto.randomInt(100000, 1000000));
  Object.assign(u, hashPassword(oneTimePassword)); u.forcePasswordReset = true; u.passwordSupportPending = false; u.oneTimePassword = oneTimePassword; u.resetMessage = String(req.body?.message || db.siteSettings.recoveryTexts.approvedMessage).slice(0, 500); save();
  res.json({ success: true, message: "Reset অনুমোদন হয়েছে। Customer নিবন্ধিত নম্বর দিয়ে Login চাপলে OTP দেখতে পাবে।" });
});
app.post("/api/customer/password-support", (req, res) => {
  const phone = String(req.body?.phone || "").trim(), message = String(req.body?.message || "").trim();
  const customer = db.users.find(u => isClient(u) && u.phone === phone);
  if (!customer || !message) return res.status(400).json({ error: "নিবন্ধিত মোবাইল নম্বর ও বার্তা দিন" });
  if (customer.forcePasswordReset) return res.status(409).json({ error: customer.resetMessage || db.siteSettings.recoveryTexts.approvedMessage, status: "APPROVED" });
  if (customer.passwordSupportPending) return res.status(409).json({ error: db.siteSettings.recoveryTexts.pendingMessage, status: "PENDING" });
  db.supportMessages.push({ id: nextId("supportMessage"), customerId: customer.id, customerName: customer.name, senderId: customer.id, senderName: customer.name, senderRole: "CUSTOMER", message: `Password recovery request: ${message}`, createdAt: new Date().toISOString() });
  customer.passwordSupportPending = true;
  db.users.filter(u => ["ADMIN", "MANAGER"].includes(u.role)).forEach(u => notify(u.id, `${customer.customerId} password recovery support চেয়েছেন`, { category: "message", kind: "password-reset", targetId: customer.id, customerId: customer.customerId }));
  save(); res.json({ success: true, message: "Support request পাঠানো হয়েছে। Admin অনুমোদন দিলে নিবন্ধিত নম্বর দিয়ে Login চাপুন।" });
});
app.get("/api/admin/recovery-texts", auth, admin, (req, res) => res.json(db.siteSettings.recoveryTexts));
app.put("/api/admin/recovery-texts", auth, admin, (req, res) => { const clean = x => String(x || "").trim().slice(0, 500); db.siteSettings.recoveryTexts = { supportTitle: clean(req.body?.supportTitle), supportDescription: clean(req.body?.supportDescription), pendingMessage: clean(req.body?.pendingMessage), approvedMessage: clean(req.body?.approvedMessage), messagePlaceholder: clean(req.body?.messagePlaceholder) }; save(); res.json({ success: true, recoveryTexts: db.siteSettings.recoveryTexts }); });
app.get("/api/admin/dashboard", auth, staff, (req, res) => res.json(aggregates()));
app.get("/api/admin/topup-config", auth, admin, (req, res) => res.json(db.siteSettings.topupConfig));
app.put("/api/admin/topup-config", auth, admin, (req, res) => {
  const others = Array.isArray(req.body?.others) ? req.body.others.map(x => ({ name: String(x?.name || "").trim().slice(0, 80), number: String(x?.number || "").trim().slice(0, 120) })).filter(x => x.name && x.number) : [];
  db.siteSettings.topupConfig = { bKash: String(req.body?.bKash || ""), Nagad: String(req.body?.Nagad || ""), Cash: String(req.body?.Cash || ""), others, message: String(req.body?.message || "") };
  save(); res.json({ success: true, topupConfig: db.siteSettings.topupConfig });
});
app.get("/api/topup-config", (req, res) => res.json(db.siteSettings.topupConfig));
app.get("/api/admin/manager-permissions", auth, admin, (req, res) => res.json(db.managerPermissions));
app.put("/api/admin/manager-permissions", auth, admin, (req, res) => { const p = req.body || {}; db.managerPermissions = { orders: Boolean(p.orders), topups: Boolean(p.topups), services: Boolean(p.services), support: Boolean(p.support), replies: Boolean(p.replies) }; save(); res.json({ success: true, permissions: db.managerPermissions }); });
app.put("/api/admin/site-settings", auth, admin, (req, res) => {
  const clean = value => String(value || "").trim().slice(0, 300);
  const headerTitle = clean(req.body?.headerTitle);
  const headerSubtitle = clean(req.body?.headerSubtitle);
  const footerText = clean(req.body?.footerText);
  if (!headerTitle || !footerText) return res.status(400).json({ error: "Header title এবং Footer text দিন" });
  const allowedLabels = ["welcomePrefix", "dashboard", "services", "orders", "topups", "history", "support", "staff", "settings", "publicHome", "publicServices", "publicLogin", "publicRegister"];
  const suppliedLabels = req.body?.uiLabels && typeof req.body.uiLabels === "object" ? req.body.uiLabels : {};
  const uiLabels = {};
  for (const key of allowedLabels) {
    const value = clean(suppliedLabels[key]);
    if (value) uiLabels[key] = value;
  }
  const homepageKeys = ["heroTitle", "heroText", "servicesButton", "registerButton", "servicesTitle", "servicesSubtitle", "publicHome", "publicServices", "publicLogin", "publicRegister", "status1Label", "status1Value", "status2Label", "status2Value", "status3Label", "status3Value", "status4Label", "status4Value"];
  const suppliedHomepage = req.body?.homepage && typeof req.body.homepage === "object" ? req.body.homepage : {};
  const homepage = {};
  for (const key of homepageKeys) {
    const value = clean(suppliedHomepage[key]);
    if (value) homepage[key] = value;
  }
  const suppliedColors = req.body?.colors && typeof req.body.colors === "object" ? req.body.colors : {};
  const colors = {};
  for (const key of ["primary", "primary2", "bg", "card", "text", "muted", "line", "ok", "warn", "danger"]) {
    const value = String(suppliedColors[key] || "").trim();
    if (/^#[0-9a-fA-F]{6}$/.test(value)) colors[key] = value;
  }
  const replyFee = Math.max(0, Number(req.body?.replyFee ?? db.siteSettings.replyFee ?? 0));
  db.siteSettings = { headerTitle, headerSubtitle, footerText, uiLabels, homepage, colors, logoUrl: db.siteSettings.logoUrl || "", replyFee };
  save(); res.json({ success: true, settings: db.siteSettings });
});
app.post("/api/admin/site-settings/logo", auth, admin, upload.single("logo"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "একটি image নির্বাচন করুন" });
  if (!String(req.file.mimetype || "").startsWith("image/")) return res.status(400).json({ error: "শুধু image file গ্রহণ করা হয়" });
  const safe = path.basename(req.file.originalname || "logo").replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120) || "logo";
  if (process.env.VERCEL && !googleDriveEnabled) return res.status(503).json({ error: "Google Drive storage is not configured" });
  const storedName = googleDriveEnabled ? `${Date.now()}-${crypto.randomBytes(10).toString("hex")}-${safe}` : req.file.filename;
  if (googleDriveEnabled) { const driveFileId = await putGoogleDriveFile(`logo-${storedName}`, req.file, { description: "Land Help Center active website logo" }); db.siteSettings.logoDriveFileId = driveFileId; }
  db.siteSettings.logoUrl = `/api/public/logo/${storedName}`;
  save(); res.json({ success: true, logoUrl: db.siteSettings.logoUrl });
});

// Documents are never public URLs.  The existing authenticated /api/files/:id
// route authorizes each download.  Only the active public logo is exposed here.
app.get("/api/admin/storage-health", auth, admin, async (req, res) => {
  const result = {
    storage: googleDriveEnabled ? "google-drive" : "not-configured",
    database: statePool ? "postgres" : "local-json-fallback",
    driveFolderConfigured: Boolean(GOOGLE_DRIVE_FOLDER_ID)
  };
  if (!googleDriveEnabled) return res.json(result);
  try {
    const token = await googleDriveToken();
    const response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(GOOGLE_DRIVE_FOLDER_ID)}?fields=id,name,mimeType&supportsAllDrives=true`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const folder = await response.json().catch(() => ({}));
    if (!response.ok) return res.status(503).json({ ...result, ok: false, error: "Google Drive folder is not accessible" });
    return res.json({ ...result, ok: true, folder });
  } catch (error) {
    return res.status(503).json({ ...result, ok: false, error: "Google Drive connection failed" });
  }
});

app.get("/api/public/logo/:name", async (req, res) => {
  const expected = path.basename(String(db.siteSettings?.logoUrl || ""));
  const name = path.basename(req.params.name);
  if (!expected || name !== expected) return res.status(404).end();
  if (googleDriveEnabled && db.siteSettings.logoDriveFileId) {
    const content = await getGoogleDriveFile(db.siteSettings.logoDriveFileId);
    if (!content) return res.status(404).end();
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.type(path.extname(name));
    return res.send(content);
  }
  const full = path.join(UPLOAD_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).end();
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.type(path.extname(name));
  res.sendFile(full);
});


app.use((err, req, res, next) => {
  if (err && err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "প্রতিটি file সর্বোচ্চ 50MB হতে পারবে" });
  if (err && err.code === "LIMIT_FILE_COUNT") return res.status(400).json({ error: "সর্বোচ্চ 10টি file দেওয়া যাবে" });
  if (err) {
    console.error("Request error:", err.message);
    return res.status(400).json({ error: IS_PRODUCTION ? "অনুরোধটি গ্রহণ করা যায়নি" : (err.message || "File upload failed") });
  }
  next();
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
if (!process.env.VERCEL) app.listen(PORT, () => console.log(`Customer Management System Phase 5.3 running: http://localhost:${PORT}`));
module.exports = app;
