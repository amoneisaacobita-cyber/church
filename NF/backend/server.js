import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import express from "express";
import multer from "multer";
import pg from "pg";
import Database from "better-sqlite3";

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FRONTEND_DIR = path.join(ROOT, "frontend", "public");
const DATA_DIR = path.resolve(process.env.LFC_DATA_DIR || path.join(ROOT, "data"));
const MEDIA_DIR = path.resolve(process.env.LFC_MEDIA_DIR || path.join(DATA_DIR, "media"));
const PORT = Number(process.env.PORT || process.env.LFC_PORT || 8000);
const MAX_UPLOAD = 100 * 1024 * 1024;
const MAX_VIDEO = 20 * 1024 * 1024 * 1024;
const CHUNK_SIZE = 16 * 1024 * 1024;
const MAX_RECORDING = 500 * 1024 * 1024;
const MEDIA_DISCOVERY_STABILITY_SECONDS = 2;
const UUID_RE = /^[0-9a-f]{32}$/;
const sermonUploadLocks = new Map();
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "64kb" }));

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

class Store {
  constructor() {
    this.isPostgres = Boolean(process.env.DATABASE_URL);
    if (this.isPostgres) {
      this.pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.PGSSL === "1" ? { rejectUnauthorized: false } : undefined,
        max: Number(process.env.DB_POOL_SIZE || 5),
        connectionTimeoutMillis: 15000,
      });
    } else {
      this.sqlite = new Database(path.join(DATA_DIR, "life-fountain.sqlite3"));
      this.sqlite.pragma("foreign_keys = ON");
      this.sqlite.pragma("journal_mode = WAL");
      this.sqlite.pragma("busy_timeout = 15000");
    }
  }

  async query(sql, params = []) {
    if (this.isPostgres) {
      let index = 0;
      const result = await this.pool.query(sql.replace(/\?/g, () => `$${++index}`), params);
      return { rows: result.rows, rowCount: result.rowCount };
    }
    const statement = this.sqlite.prepare(sql);
    if (/^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql)) {
      const rows = statement.all(...params);
      return { rows, rowCount: rows.length };
    }
    const result = statement.run(...params);
    return { rows: [], rowCount: result.changes, lastInsertRowid: result.lastInsertRowid };
  }

  async close() {
    if (this.pool) await this.pool.end();
    this.sqlite?.close();
  }
}

const store = new Store();

function uuid() {
  return crypto.randomBytes(16).toString("hex");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256");
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function passwordMatches(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(":");
    const actual = crypto.pbkdf2Sync(password, Buffer.from(saltHex, "hex"), 600000, 32, "sha256");
    const expected = Buffer.from(hashHex, "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function safeUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.LFC_HTTPS === "1",
    path: "/",
    maxAge: maxAge * 1000,
  };
}

function tokenFromCookie(req, name) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((item) => item.trim().split(/=(.*)/s, 2))
      .filter((pair) => pair.length === 2)
      .map(([key, value]) => [key, decodeURIComponent(value)]),
  );
  return cookies[name] || "";
}

async function currentUser(req) {
  const token = tokenFromCookie(req, "lfc_session");
  if (!token) return null;
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  const { rows } = await store.query(
    `SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.active = 1`,
    [digest, Math.floor(Date.now() / 1000)],
  );
  return rows[0] || null;
}

async function requireUser(req, res, roles = ["admin", "pastor"]) {
  const user = await currentUser(req);
  if (!user) {
    res.status(401).json({ error: "Sign in to continue." });
    return null;
  }
  if (!roles.includes(user.role)) {
    res.status(403).json({ error: "You do not have permission to do that." });
    return null;
  }
  return user;
}

async function requireStudio(req, res) {
  const token = tokenFromCookie(req, "lfc_studio");
  if (!token) {
    res.status(403).json({ error: "Unlock the Streaming studio first." });
    return false;
  }
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  const { rows } = await store.query(
    "SELECT 1 FROM studio_sessions WHERE token_hash = ? AND expires_at > ?",
    [digest, Math.floor(Date.now() / 1000)],
  );
  if (!rows.length) {
    res.status(403).json({ error: "Unlock the Streaming studio first." });
    return false;
  }
  return true;
}

function error(res, status, message) {
  res.status(status).json({ error: message });
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 256;
}

function filePath(...parts) {
  return path.join(MEDIA_DIR, ...parts);
}

function sendFile(res, filename, contentType, cacheControl = "no-store") {
  if (!filename || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) {
    return error(res, 404, "File not found.");
  }
  res.set({ "Content-Type": contentType, "Cache-Control": cacheControl });
  return res.sendFile(path.resolve(filename));
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD, files: 2, fields: 12, fieldSize: 64 * 1024 },
});
const mediaUpload = upload.fields([{ name: "file", maxCount: 1 }, { name: "cover", maxCount: 1 }]);

function uploaded(req, field) {
  return req.files?.[field]?.[0] || null;
}

function signatureOk(file) {
  const b = file.buffer;
  return (
    (file.mimetype === "image/jpeg" && b.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) ||
    (file.mimetype === "image/png" && b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) ||
    (file.mimetype === "image/webp" && b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP")
  );
}

function imageExtension(file) {
  return ({ "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp" })[file.mimetype];
}

async function initialize() {
  const schema = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('admin','pastor')), password_hash TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS studio_credentials (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS studio_sessions (token_hash TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, client_ip TEXT NOT NULL, email TEXT NOT NULL, created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS prayers (id TEXT PRIMARY KEY, name TEXT NOT NULL, message TEXT NOT NULL,
      pastor_id TEXT REFERENCES users(id) ON DELETE SET NULL, client_ip TEXT NOT NULL DEFAULT '',
      created_at BIGINT NOT NULL, response TEXT NOT NULL DEFAULT '',
      responded_by TEXT REFERENCES users(id) ON DELETE SET NULL, responded_at BIGINT)`,
    `CREATE TABLE IF NOT EXISTS church_profile (id INTEGER PRIMARY KEY, name TEXT NOT NULL, leader TEXT NOT NULL DEFAULT '',
      phone TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
      about TEXT NOT NULL DEFAULT '', latitude REAL, longitude REAL, logo_path TEXT, updated_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS announcements (id TEXT PRIMARY KEY, title TEXT NOT NULL, message TEXT NOT NULL,
      audience TEXT NOT NULL CHECK(audience IN ('everyone','pastors')), created_by TEXT NOT NULL REFERENCES users(id),
      created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS church_verses (id TEXT PRIMARY KEY, text TEXT NOT NULL, reference TEXT NOT NULL,
      created_by TEXT NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS streams (id TEXT PRIMARY KEY, title TEXT NOT NULL, mime_type TEXT NOT NULL,
      cover_path TEXT, owner_id TEXT NOT NULL REFERENCES users(id), started_at BIGINT NOT NULL,
      ended_at BIGINT, status TEXT NOT NULL CHECK(status IN ('live','completed','interrupted')),
      view_count INTEGER NOT NULL DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS audio_chunks (stream_id TEXT NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, file_path TEXT NOT NULL, PRIMARY KEY(stream_id,sequence))`,
    `CREATE TABLE IF NOT EXISTS media_items (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
      kind TEXT NOT NULL CHECK(kind IN ('sermon','short')), mime_type TEXT NOT NULL, original_path TEXT NOT NULL,
      audio_path TEXT, cover_path TEXT, view_count INTEGER NOT NULL DEFAULT 0, auto_discovered INTEGER NOT NULL DEFAULT 0,
      created_by TEXT NOT NULL REFERENCES users(id), created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS media_discovery_candidates (file_path TEXT PRIMARY KEY, size BIGINT NOT NULL,
      modified_ns BIGINT NOT NULL, first_seen BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS sermon_uploads (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_filename TEXT NOT NULL, title TEXT NOT NULL, mime_type TEXT NOT NULL, file_size BIGINT NOT NULL,
      uploaded_bytes BIGINT NOT NULL DEFAULT 0, cover_path TEXT, created_at BIGINT NOT NULL)`,
  ];
  for (const statement of schema) {
    const sql = store.isPostgres
      ? statement.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
      : statement;
    await store.query(sql);
  }
  const indexes = [
    "CREATE INDEX IF NOT EXISTS prayer_assignment ON prayers(pastor_id, created_at)",
    "CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at)",
    "CREATE INDEX IF NOT EXISTS login_attempt_window ON login_attempts(client_ip, created_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS one_admin_account ON users(role) WHERE role = 'admin'",
    "CREATE UNIQUE INDEX IF NOT EXISTS one_live_stream ON streams(status) WHERE status = 'live'",
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci ON users(LOWER(email))",
    "CREATE UNIQUE INDEX IF NOT EXISTS unique_auto_discovered_audio_path ON media_items(audio_path) WHERE auto_discovered = 1",
  ];
  for (const statement of indexes) await store.query(statement);
  await store.query(
    "INSERT INTO church_profile(id,name,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO NOTHING",
    ["Life Fountain Church", Math.floor(Date.now() / 1000)],
  );
  await store.query("UPDATE streams SET status='interrupted',ended_at=? WHERE status='live'", [Math.floor(Date.now() / 1000)]);
  await store.query("DELETE FROM sessions WHERE expires_at < ?", [Math.floor(Date.now() / 1000)]);
  const { rows: admins } = await store.query("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
  const setupPath = path.join(DATA_DIR, ".setup-code");
  if (!admins.length && !fs.existsSync(setupPath)) {
    fs.writeFileSync(setupPath, crypto.randomBytes(24).toString("base64url"), { mode: 0o600 });
  }
  if (process.env.LFC_STUDIO_PASSWORD) {
    const { rows } = await store.query("SELECT 1 FROM studio_credentials WHERE id=1");
    if (!rows.length) {
      await store.query("INSERT INTO studio_credentials(id,password_hash) VALUES(1,?)", [hashPassword(process.env.LFC_STUDIO_PASSWORD)]);
    }
  }
}

function validAudioFile(filename, size) {
  if (size < 128) return null;
  const fd = fs.openSync(filename, "r");
  const header = Buffer.alloc(12);
  try { fs.readSync(fd, header, 0, 12, 0); } finally { fs.closeSync(fd); }
  const ext = path.extname(filename).toLowerCase();
  const formats = {
    ".wav": ["audio/wav", header.toString("ascii", 0, 4) === "RIFF" && header.toString("ascii", 8, 12) === "WAVE"],
    ".mp3": ["audio/mpeg", header.toString("ascii", 0, 3) === "ID3" || (header[0] === 0xff && (header[1] & 0xe0) === 0xe0)],
    ".m4a": ["audio/mp4", header.toString("ascii", 4, 8) === "ftyp"],
    ".ogg": ["audio/ogg", header.toString("ascii", 0, 4) === "OggS"],
    ".oga": ["audio/ogg", header.toString("ascii", 0, 4) === "OggS"],
    ".webm": ["audio/webm", header.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))],
    ".flac": ["audio/flac", header.toString("ascii", 0, 4) === "fLaC"],
    ".aac": ["audio/aac", header[0] === 0xff && (header[1] & 0xf6) === 0xf0],
  };
  const item = formats[ext];
  if (!item?.[1]) return null;
  if (ext === ".wav") {
    const riffSize = header.readUInt32LE(4);
    if (riffSize < 36 || riffSize + 8 !== size) return null;
  }
  return item[0];
}

function findCover(audioPath) {
  const folder = path.dirname(audioPath);
  const stem = path.parse(audioPath).name.toLowerCase();
  const supported = new Set([".jpg", ".jpeg", ".png", ".webp"]);
  for (const candidate of fs.readdirSync(folder)) {
    const candidatePath = path.join(folder, candidate);
    const ext = path.extname(candidate).toLowerCase();
    const base = path.parse(candidate).name.toLowerCase();
    if (!supported.has(ext) || !(base === stem || ["cover", "wallpaper", "background"].includes(base))) continue;
    try {
      const stat = fs.statSync(candidatePath);
      if (!stat.isFile() || stat.size > 5 * 1024 * 1024) continue;
      const fd = fs.openSync(candidatePath, "r");
      const header = Buffer.alloc(12);
      try { fs.readSync(fd, header, 0, 12, 0); } finally { fs.closeSync(fd); }
      if (([".jpg", ".jpeg"].includes(ext) && header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff) ||
          (ext === ".png" && header.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) ||
          (ext === ".webp" && header.toString("ascii", 0, 4) === "RIFF" && header.toString("ascii", 8, 12) === "WEBP")) return candidatePath;
    } catch (e) { console.error("Could not inspect sermon wallpaper:", e); }
  }
  return null;
}

async function discoverMediaFiles() {
  if (process.env.LFC_MEDIA_DISCOVERY === "0" || process.env.LFC_MEDIA_DIR) return;
  const { rows: owners } = await store.query("SELECT id FROM users WHERE role='admin' AND active=1 ORDER BY created_at LIMIT 1");
  if (!owners[0]) return;
  const { rows: existing } = await store.query(
    "SELECT original_path,audio_path FROM media_items WHERE kind='sermon'",
  );
  const registered = new Set(existing.flatMap((item) => [item.original_path, item.audio_path].filter(Boolean).map((filename) => path.resolve(filename))));
  const now = Math.floor(Date.now() / 1000);
  const observed = new Set();
  const visit = async (directory, level = 0) => {
    if (level > 12) return;
    let entries;
    try { entries = fs.readdirSync(directory, { withFileTypes: true }); }
    catch (e) { console.error("Could not scan church media directory:", e); return; }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        const relative = path.relative(MEDIA_DIR, full).split(path.sep)[0];
        if (level === 0 && ["media", "church-brand", "large-uploads"].includes(relative)) continue;
        await visit(full, level + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const resolved = path.resolve(full);
      let stat;
      let mime;
      try {
        stat = fs.statSync(resolved);
        mime = validAudioFile(resolved, stat.size);
      } catch (e) { console.error("Could not validate sermon file:", e); continue; }
      if (!mime) continue;
      observed.add(resolved);
      const cover = findCover(resolved);
      if (registered.has(resolved)) {
        if (cover) await store.query(
          "UPDATE media_items SET cover_path=? WHERE auto_discovered=1 AND audio_path=? AND cover_path IS NULL",
          [cover, resolved],
        );
        continue;
      }
      const size = stat.size;
      const modified = Math.trunc(stat.mtimeMs * 1e6);
      const { rows: candidates } = await store.query("SELECT size,modified_ns,first_seen FROM media_discovery_candidates WHERE file_path=?", [resolved]);
      const candidate = candidates[0];
      if (!candidate || Number(candidate.size) !== size || Number(candidate.modified_ns) !== modified) {
        await store.query(
          `INSERT INTO media_discovery_candidates(file_path,size,modified_ns,first_seen) VALUES(?,?,?,?)
           ON CONFLICT(file_path) DO UPDATE SET size=excluded.size,modified_ns=excluded.modified_ns,first_seen=excluded.first_seen`,
          [resolved, size, modified, now],
        );
        continue;
      }
      if (now - Number(candidate.first_seen) < MEDIA_DISCOVERY_STABILITY_SECONDS) continue;
      const title = path.parse(resolved).name.replace(/[_\s]+/g, " ").trim().slice(0, 120) || "Untitled sermon";
      await store.query(
        `INSERT INTO media_items(id,title,description,kind,mime_type,original_path,audio_path,cover_path,auto_discovered,created_by,created_at)
         VALUES(?,?,?,'sermon',?,?,?,?,1,?,?) ON CONFLICT DO NOTHING`,
        [uuid(), title, "", mime, resolved, resolved, cover, owners[0].id, Math.floor(stat.mtimeMs / 1000)],
      );
      registered.add(resolved);
    }
  };
  await visit(MEDIA_DIR);
  const { rows: candidates } = await store.query("SELECT file_path FROM media_discovery_candidates");
  for (const item of candidates) {
    if (!observed.has(item.file_path)) await store.query("DELETE FROM media_discovery_candidates WHERE file_path=?", [item.file_path]);
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res)).catch(next);
}

async function withSermonUploadLock(id, operation) {
  const previous = sermonUploadLocks.get(id) || Promise.resolve();
  let release;
  const current = new Promise((resolve) => { release = resolve; });
  sermonUploadLocks.set(id, current);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (sermonUploadLocks.get(id) === current) sermonUploadLocks.delete(id);
  }
}

app.get("/api/status", asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const [{ rows: admins }, { rows: streams }] = await Promise.all([
    store.query("SELECT 1 FROM users WHERE role='admin' LIMIT 1"),
    store.query("SELECT id,title,mime_type,started_at FROM streams WHERE status='live' LIMIT 1"),
  ]);
  const token = tokenFromCookie(req, "lfc_studio");
  let studio = false;
  if (token) {
    const digest = crypto.createHash("sha256").update(token).digest("hex");
    const result = await store.query("SELECT 1 FROM studio_sessions WHERE token_hash=? AND expires_at>?", [digest, Math.floor(Date.now() / 1000)]);
    studio = result.rows.length > 0;
  }
  res.json({ setup_required: !admins.length, user: user ? safeUser(user) : null, stream: streams[0] || null, studio_unlocked: studio });
}));

app.get("/api/church-profile", asyncRoute(async (_req, res) => {
  const { rows } = await store.query("SELECT name,leader,phone,email,address,about,latitude,longitude,logo_path,updated_at FROM church_profile WHERE id=1");
  const profile = rows[0] || {};
  delete profile.logo_path;
  delete profile.updated_at;
  profile.logo_url = rows[0]?.logo_path ? `/api/church-logo?v=${rows[0].updated_at}` : null;
  res.json(profile);
}));

app.get("/api/church-logo", asyncRoute(async (_req, res) => {
  const { rows } = await store.query("SELECT logo_path FROM church_profile WHERE id=1");
  const filename = rows[0]?.logo_path;
  const ext = path.extname(filename || "").toLowerCase();
  const type = ({ ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp" })[ext];
  if (!type) return error(res, 404, "Church logo not found.");
  return sendFile(res, filename, type);
}));

app.get("/api/announcements", asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const { rows } = await store.query(
    `SELECT announcements.id,announcements.title,announcements.message,announcements.audience,
       announcements.created_at,users.name AS author FROM announcements JOIN users ON users.id=announcements.created_by
       WHERE announcements.audience='everyone' OR ? ORDER BY announcements.created_at DESC LIMIT 100`,
    [user && ["admin", "pastor"].includes(user.role) ? 1 : 0],
  );
  res.json(rows);
}));

app.get("/api/verses", asyncRoute(async (_req, res) => {
  const { rows } = await store.query("SELECT id,text,reference,created_at FROM church_verses ORDER BY created_at DESC,id");
  res.json(rows);
}));

app.get("/api/pastors/public", asyncRoute(async (_req, res) => {
  const { rows } = await store.query("SELECT id,name FROM users WHERE role='pastor' AND active=1 ORDER BY name");
  res.json(rows);
}));
app.get("/api/pastors", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const { rows } = await store.query("SELECT id,name,email,role FROM users WHERE role='pastor' AND active=1 ORDER BY name");
  res.json(rows);
}));

app.get("/api/prayers", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const where = user.role === "admin" ? "" : "WHERE prayers.pastor_id=?";
  const params = user.role === "admin" ? [] : [user.id];
  const { rows } = await store.query(
    `SELECT prayers.id,prayers.name,prayers.message,prayers.pastor_id,prayers.created_at,prayers.response,
      prayers.responded_at,users.name AS pastor_name,responder.name AS responder_name
     FROM prayers LEFT JOIN users ON users.id=prayers.pastor_id LEFT JOIN users AS responder ON responder.id=prayers.responded_by
     ${where} ORDER BY prayers.created_at DESC`,
    params,
  );
  res.json(rows);
}));

app.get("/api/stream", asyncRoute(async (_req, res) => {
  const { rows } = await store.query("SELECT id,title,mime_type,cover_path,started_at FROM streams WHERE status='live' LIMIT 1");
  const stream = rows[0] || null;
  if (stream) {
    stream.cover_url = stream.cover_path ? `/api/streams/${stream.id}/cover` : null;
    delete stream.cover_path;
  }
  res.json({ stream });
}));

app.get("/api/recordings", asyncRoute(async (_req, res) => {
  const { rows } = await store.query(
    "SELECT id,title,mime_type,cover_path,started_at,ended_at,view_count FROM streams WHERE status='completed' ORDER BY ended_at DESC LIMIT 100",
  );
  res.json(rows.map((item) => {
    const recording = { ...item, cover_url: item.cover_path ? `/api/streams/${item.id}/cover` : null };
    delete recording.cover_path;
    return recording;
  }));
}));

app.get("/api/streams/:id/chunks", asyncRoute(async (req, res) => {
  if (!UUID_RE.test(req.params.id)) return error(res, 404, "Stream not found.");
  const after = Math.max(-1, Number(req.query.after ?? -1));
  if (!Number.isInteger(after)) return error(res, 400, "Invalid audio segment cursor.");
  const [{ rows: stream }, { rows: chunks }] = await Promise.all([
    store.query("SELECT status FROM streams WHERE id=?", [req.params.id]),
    store.query("SELECT sequence FROM audio_chunks WHERE stream_id=? AND sequence>? ORDER BY sequence LIMIT 128", [req.params.id, after]),
  ]);
  res.json({ live: stream[0]?.status === "live", sequences: chunks.map((row) => row.sequence) });
}));

app.get("/api/streams/:id/chunks/:sequence", asyncRoute(async (req, res) => {
  if (!UUID_RE.test(req.params.id) || !/^\d+$/.test(req.params.sequence)) return error(res, 404, "Audio segment not found.");
  const { rows } = await store.query("SELECT file_path FROM audio_chunks WHERE stream_id=? AND sequence=?", [req.params.id, Number(req.params.sequence)]);
  return sendFile(res, rows[0]?.file_path, "audio/webm");
}));

app.get("/api/streams/:id/cover", asyncRoute(async (req, res) => {
  const { rows } = await store.query("SELECT cover_path FROM streams WHERE id=?", [req.params.id]);
  const filename = rows[0]?.cover_path;
  const type = ({ ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp" })[path.extname(filename || "").toLowerCase()];
  if (!type) return error(res, 404, "Stream wallpaper not found.");
  return sendFile(res, filename, type);
}));

app.get("/api/recordings/:id", asyncRoute(async (req, res) => {
  const { rows } = await store.query("SELECT status,mime_type FROM streams WHERE id=?", [req.params.id]);
  const mime = rows[0]?.mime_type?.split(";", 1)[0].toLowerCase();
  const extension = ({ "audio/webm": "webm", "audio/ogg": "ogg", "audio/wav": "wav" })[mime];
  if (rows[0]?.status !== "completed" || !extension) return error(res, 404, "Recording not found.");
  return sendFile(res, filePath(req.params.id, `recording.${extension}`), mime);
}));

app.get("/api/media", asyncRoute(async (_req, res) => {
  await discoverMediaFiles();
  const { rows } = await store.query(
    `SELECT media_items.id,media_items.title,media_items.description,media_items.kind,media_items.mime_type,
      media_items.created_at,media_items.view_count,media_items.cover_path,media_items.auto_discovered,
      CASE WHEN media_items.auto_discovered=1 THEN 'Life Fountain Church' ELSE users.name END AS speaker
     FROM media_items LEFT JOIN users ON users.id=media_items.created_by ORDER BY media_items.created_at DESC LIMIT 200`,
  );
  res.json(rows.map((item) => ({
    ...item,
    video_url: `/api/media/${item.id}`,
    audio_url: item.kind === "sermon" ? `/api/media/${item.id}/audio` : null,
    cover_url: item.cover_path ? `/api/media/${item.id}/cover` : null,
    view_url: item.kind === "sermon" ? `/api/media/${item.id}/view` : null,
    title_url: `/api/media/${item.id}/title`,
    delete_url: `/api/media/${item.id}`,
  })));
}));

app.get("/api/media/:id/audio", asyncRoute(async (req, res) => {
  const { rows } = await store.query("SELECT audio_path,mime_type FROM media_items WHERE id=? AND kind='sermon'", [req.params.id]);
  const row = rows[0];
  if (!row?.audio_path) return error(res, 404, "Sermon audio not found.");
  return sendFile(res, row.audio_path, row.mime_type.startsWith("audio/") ? row.mime_type : "audio/mpeg");
}));
app.get("/api/media/:id/cover", asyncRoute(async (req, res) => {
  const { rows } = await store.query("SELECT cover_path FROM media_items WHERE id=?", [req.params.id]);
  const filename = rows[0]?.cover_path;
  const type = ({ ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp" })[path.extname(filename || "").toLowerCase()];
  if (!type) return error(res, 404, "Sermon cover not found.");
  return sendFile(res, filename, type);
}));
app.get("/api/media/:id", asyncRoute(async (req, res) => {
  const { rows } = await store.query("SELECT original_path,mime_type FROM media_items WHERE id=?", [req.params.id]);
  if (!rows[0]) return error(res, 404, "Media not found.");
  return sendFile(res, rows[0].original_path, rows[0].mime_type);
}));

app.get("/api/sermon-uploads/:id", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const { rows } = await store.query("SELECT * FROM sermon_uploads WHERE id=?", [req.params.id]);
  const item = rows[0];
  if (!item) return error(res, 404, "Large sermon upload not found.");
  if (user.role !== "admin" && item.owner_id !== user.id) return error(res, 403, "Only the uploader or an admin can manage this sermon upload.");
  res.json({ id: item.id, uploaded_bytes: item.uploaded_bytes, file_size: item.file_size });
}));

app.post("/api/setup", asyncRoute(async (req, res) => {
  const { setup_code: code, name, email, password } = req.body || {};
  const setupPath = path.join(DATA_DIR, ".setup-code");
  if (!fs.existsSync(setupPath)) return error(res, 409, "Admin setup is already complete.");
  const expected = fs.readFileSync(setupPath, "utf8").trim();
  const submittedCode = Buffer.from(typeof code === "string" ? code : "");
  const expectedCode = Buffer.from(expected);
  if (submittedCode.length !== expectedCode.length || !crypto.timingSafeEqual(submittedCode, expectedCode)) {
    return error(res, 403, "The setup code does not match the code printed by the server.");
  }
  if (typeof name !== "string" || !name.trim() || name.trim().length > 80 ||
      typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim()) ||
      email.trim().length > 254) return error(res, 400, "Enter a name and a valid email address.");
  if (!validatePassword(password)) return error(res, 400, "Use a password with at least 8 characters.");
  const { rows } = await store.query("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
  if (rows.length) return error(res, 409, "Initial setup is already complete.");
  const id = uuid();
  await store.query(
    "INSERT INTO users(id,name,email,role,password_hash,created_at) VALUES(?,?,?,'admin',?,?)",
    [id, name.trim(), email.trim(), hashPassword(password), Math.floor(Date.now() / 1000)],
  );
  fs.rmSync(setupPath, { force: true });
  const token = crypto.randomBytes(32).toString("base64url");
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  await store.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
    [digest, id, Math.floor(Date.now() / 1000) + 7 * 86400]);
  res.cookie("lfc_session", token, cookieOptions(7 * 86400));
  res.status(201).json({ user: { id, name: name.trim(), email: email.trim(), role: "admin" } });
}));

app.post("/api/login", asyncRoute(async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim() : "";
  const password = req.body?.password;
  if (typeof password !== "string") return error(res, 400, "Enter your email and password.");
  const ip = req.ip;
  const now = Math.floor(Date.now() / 1000);
  await store.query("DELETE FROM login_attempts WHERE created_at < ?", [now - 900]);
  const { rows: attemptRows } = await store.query(
    "SELECT COUNT(*) AS total FROM login_attempts WHERE client_ip=? AND created_at>?",
    [ip, now - 900],
  );
  if (Number(attemptRows[0].total) >= 10) return error(res, 429, "Too many sign-in attempts. Try again later.");
  const { rows } = await store.query("SELECT * FROM users WHERE LOWER(email)=LOWER(?) AND active=1", [email]);
  const user = rows[0];
  if (!user || !passwordMatches(password, user.password_hash)) {
    await store.query("INSERT INTO login_attempts(client_ip,email,created_at) VALUES(?,?,?)", [ip, email.slice(0, 254), now]);
    return error(res, 401, "Email or password is incorrect.");
  }
  await store.query("DELETE FROM login_attempts WHERE client_ip=?", [ip]);
  const token = crypto.randomBytes(32).toString("base64url");
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  await store.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", [digest, user.id, now + 7 * 86400]);
  res.cookie("lfc_session", token, cookieOptions(7 * 86400)).json({ user: safeUser(user) });
}));

app.post("/api/logout", asyncRoute(async (req, res) => {
  const token = tokenFromCookie(req, "lfc_session");
  if (token) await store.query("DELETE FROM sessions WHERE token_hash=?", [crypto.createHash("sha256").update(token).digest("hex")]);
  res.clearCookie("lfc_session", cookieOptions(0)).json({ ok: true });
}));

app.post("/api/studio/unlock", asyncRoute(async (req, res) => {
  const password = req.body?.password;
  const ip = req.ip;
  const now = Math.floor(Date.now() / 1000);
  await store.query("DELETE FROM login_attempts WHERE created_at < ?", [now - 900]);
  const { rows: attemptRows } = await store.query(
    "SELECT COUNT(*) AS total FROM login_attempts WHERE client_ip=? AND email='streaming-studio' AND created_at>?",
    [ip, now - 900],
  );
  if (Number(attemptRows[0].total) >= 10) return error(res, 429, "Too many attempts. Try again later.");
  const { rows } = await store.query("SELECT password_hash FROM studio_credentials WHERE id=1");
  if (!rows[0]) return error(res, 503, "The Streaming studio password is not configured. Set LFC_STUDIO_PASSWORD and restart the server.");
  if (!passwordMatches(password, rows[0].password_hash)) {
    await store.query("INSERT INTO login_attempts(client_ip,email,created_at) VALUES(?,'streaming-studio',?)", [ip, now]);
    return error(res, 403, "The Streaming studio password is incorrect.");
  }
  await store.query("DELETE FROM login_attempts WHERE client_ip=? AND email='streaming-studio'", [ip]);
  const token = crypto.randomBytes(32).toString("base64url");
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  await store.query("INSERT INTO studio_sessions(token_hash,expires_at) VALUES(?,?)", [digest, now + 12 * 3600]);
  res.cookie("lfc_studio", token, cookieOptions(12 * 3600)).json({ ok: true });
}));

app.post("/api/pastors", asyncRoute(async (req, res) => {
  const admin = await requireUser(req, res, ["admin"]);
  if (!admin) return;
  const { name, email, password } = req.body || {};
  if (typeof name !== "string" || !name.trim() || name.trim().length > 80 ||
      typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim()) || email.trim().length > 254) {
    return error(res, 400, "Enter a pastor name and valid email address.");
  }
  if (!validatePassword(password)) return error(res, 400, "Set a temporary password with at least 8 characters.");
  const id = uuid();
  await store.query("INSERT INTO users(id,name,email,role,password_hash,created_at) VALUES(?,?,?,'pastor',?,?)",
    [id, name.trim(), email.trim(), hashPassword(password), Math.floor(Date.now() / 1000)]);
  res.status(201).json({ id, name: name.trim(), email: email.trim(), role: "pastor" });
}));

app.post("/api/prayers", asyncRoute(async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 80) || "Church member";
  const message = String(req.body?.message || "").trim();
  const pastorId = String(req.body?.pastor_id || "").trim() || null;
  if (!message || message.length > 5000) return error(res, 400, "Write a prayer request (up to 5,000 characters).");
  const now = Math.floor(Date.now() / 1000);
  const { rows: recent } = await store.query("SELECT COUNT(*) AS total FROM prayers WHERE client_ip=? AND created_at>?",
    [req.ip, now - 600]);
  if (Number(recent[0].total) >= 8) return error(res, 429, "Please wait before submitting another request.");
  if (pastorId) {
    const { rows } = await store.query("SELECT 1 FROM users WHERE id=? AND role='pastor' AND active=1", [pastorId]);
    if (!rows.length) return error(res, 400, "Choose an active pastor or the pastoral care team.");
  }
  const id = uuid();
  await store.query("INSERT INTO prayers(id,name,message,pastor_id,client_ip,created_at) VALUES(?,?,?,?,?,?)",
    [id, name, message, pastorId, req.ip, now]);
  res.status(201).json({ ok: true, id });
}));

app.post("/api/prayers/:id/response", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const response = String(req.body?.response || "").trim();
  if (!response || response.length > 5000) return error(res, 400, "Write a response (up to 5,000 characters).");
  const { rows } = await store.query("SELECT pastor_id FROM prayers WHERE id=?", [req.params.id]);
  if (!rows[0]) return error(res, 404, "Prayer request not found.");
  if (user.role === "pastor" && rows[0].pastor_id !== user.id) return error(res, 403, "You can only respond to requests assigned to you.");
  await store.query("UPDATE prayers SET response=?,responded_by=?,responded_at=? WHERE id=?",
    [response, user.id, Math.floor(Date.now() / 1000), req.params.id]);
  res.json({ ok: true });
}));

app.post("/api/church-profile", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const fields = {};
  for (const key of ["name", "leader", "phone", "email", "address", "about"]) {
    if (typeof (req.body?.[key] ?? "") !== "string") return error(res, 400, `Invalid church ${key}.`);
    fields[key] = (req.body[key] || "").trim();
  }
  if (!fields.name || fields.name.length > 120) return error(res, 400, "Enter a church name up to 120 characters.");
  if (fields.leader.length > 120 || fields.phone.length > 40) return error(res, 400, "Contact name or phone number is too long.");
  if (fields.email && (fields.email.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(fields.email))) return error(res, 400, "Enter a valid contact email address.");
  if (fields.address.length > 500 || fields.about.length > 3000) return error(res, 400, "Church address or About text is too long.");
  const lat = req.body.latitude === "" || req.body.latitude == null ? null : Number(req.body.latitude);
  const lon = req.body.longitude === "" || req.body.longitude == null ? null : Number(req.body.longitude);
  if ((lat === null) !== (lon === null) || (lat !== null && (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180))) {
    return error(res, 400, "Enter valid latitude and longitude coordinates.");
  }
  await store.query(
    "UPDATE church_profile SET name=?,leader=?,phone=?,email=?,address=?,about=?,latitude=?,longitude=?,updated_at=? WHERE id=1",
    [fields.name, fields.leader, fields.phone, fields.email, fields.address, fields.about, lat, lon, Math.floor(Date.now() / 1000)],
  );
  res.json({ ok: true });
}));

app.post("/api/church-logo", mediaUpload, asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const file = uploaded(req, "file");
  if (!file || !signatureOk(file)) return error(res, 400, "Choose a valid JPG, PNG, or WebP logo.");
  if (file.size > 2 * 1024 * 1024) return error(res, 400, "Choose a logo smaller than 2 MB.");
  const filename = filePath("church-brand", `logo-${uuid()}${imageExtension(file)}`);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, file.buffer);
  const { rows } = await store.query("SELECT logo_path FROM church_profile WHERE id=1");
  const updated = Math.floor(Date.now() / 1000);
  await store.query("UPDATE church_profile SET logo_path=?,updated_at=? WHERE id=1", [filename, updated]);
  if (rows[0]?.logo_path && rows[0].logo_path !== filename) fs.rmSync(rows[0].logo_path, { force: true });
  res.status(201).json({ logo_url: `/api/church-logo?v=${updated}` });
}));
app.delete("/api/church-logo", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const { rows } = await store.query("SELECT logo_path FROM church_profile WHERE id=1");
  await store.query("UPDATE church_profile SET logo_path=NULL,updated_at=? WHERE id=1", [Math.floor(Date.now() / 1000)]);
  if (rows[0]?.logo_path) fs.rmSync(rows[0].logo_path, { force: true });
  res.json({ ok: true });
}));

app.post("/api/announcements", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const title = req.body?.title;
  const message = req.body?.message;
  const audience = req.body?.audience;
  if (typeof title !== "string" || !title.trim() || title.trim().length > 120) return error(res, 400, "Enter an announcement heading up to 120 characters.");
  if (typeof message !== "string" || !message.trim() || message.trim().length > 3000) return error(res, 400, "Write an announcement message up to 3,000 characters.");
  if (!["everyone", "pastors"].includes(audience)) return error(res, 400, "Choose whether the announcement is for everyone or pastors.");
  const id = uuid();
  const created = Math.floor(Date.now() / 1000);
  await store.query("INSERT INTO announcements(id,title,message,audience,created_by,created_at) VALUES(?,?,?,?,?,?)",
    [id, title.trim(), message.trim(), audience, user.id, created]);
  res.status(201).json({ id, title: title.trim(), message: message.trim(), audience, created_at: created, author: user.name });
}));

app.post("/api/verses", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res, ["admin"]);
  if (!user) return;
  const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
  const reference = typeof req.body?.reference === "string" ? req.body.reference.trim() : "";
  if (!text || text.length > 2000 || !reference || reference.length > 80) return error(res, 400, "Enter verse text (up to 2,000 characters) and a reference (up to 80 characters).");
  const id = uuid();
  const created = Math.floor(Date.now() / 1000);
  await store.query("INSERT INTO church_verses(id,text,reference,created_by,created_at) VALUES(?,?,?,?,?)", [id, text, reference, user.id, created]);
  res.status(201).json({ id, text, reference, created_at: created });
}));

app.post("/api/media", mediaUpload, asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const file = uploaded(req, "file");
  const cover = uploaded(req, "cover");
  let kind = req.body.kind;
  const description = String(req.body.description || "").trim().slice(0, 2000);
  const title = String(req.body.title || "").trim().slice(0, 120);
  if (!file || !file.size) return error(res, 400, "Choose a valid media file.");
  if (!["sermon", "short", "audio-sermon"].includes(kind)) return error(res, 400, "Choose a sermon, audio sermon, or short video.");
  if (cover && (!signatureOk(cover) || cover.size > 5 * 1024 * 1024)) return error(res, 400, "Choose a valid JPEG, PNG, or WebP wallpaper smaller than 5 MB.");
  const extension = path.extname(path.basename(file.originalname)).toLowerCase();
  let audio = kind === "audio-sermon";
  if (audio) {
    const audioMime = {
      ".mp3": { types: ["audio/mpeg", "audio/mp3"], valid: file.buffer.subarray(0, 3).toString() === "ID3" || (file.buffer[0] === 0xff && (file.buffer[1] & 0xe0) === 0xe0) },
      ".wav": { types: ["audio/wav", "audio/x-wav"], valid: file.buffer.toString("ascii", 0, 4) === "RIFF" && file.buffer.toString("ascii", 8, 12) === "WAVE" },
      ".m4a": { types: ["audio/mp4", "audio/x-m4a"], valid: file.buffer.toString("ascii", 4, 8) === "ftyp" },
      ".mp4": { types: ["audio/mp4"], valid: file.buffer.toString("ascii", 4, 8) === "ftyp" },
      ".ogg": { types: ["audio/ogg", "application/ogg"], valid: file.buffer.toString("ascii", 0, 4) === "OggS" },
      ".oga": { types: ["audio/ogg", "application/ogg"], valid: file.buffer.toString("ascii", 0, 4) === "OggS" },
      ".webm": { types: ["audio/webm"], valid: file.buffer.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])) },
      ".flac": { types: ["audio/flac", "audio/x-flac"], valid: file.buffer.toString("ascii", 0, 4) === "fLaC" },
      ".aac": { types: ["audio/aac", "audio/aacp"], valid: file.buffer[0] === 0xff && (file.buffer[1] & 0xf6) === 0xf0 },
    };
    const expected = audioMime[extension];
    if (!expected?.types.includes(file.mimetype.toLowerCase()) || !expected.valid) return error(res, 400, "Choose a supported audio file (MP3, WAV, M4A, OGG, WebM, FLAC, or AAC).");
    kind = "sermon";
  } else if (!file.mimetype.startsWith("video/")) {
    return error(res, 400, "Choose a valid video file.");
  }
  const id = uuid();
  const folder = filePath("media", id);
  fs.mkdirSync(folder, { recursive: true });
  const safeExt = /^\.[a-z0-9]{1,10}$/.test(extension) ? extension : ".video";
  const original = path.join(folder, `original${safeExt}`);
  const coverPath = cover ? path.join(folder, `cover${imageExtension(cover)}`) : null;
  fs.writeFileSync(original, file.buffer);
  if (cover) fs.writeFileSync(coverPath, cover.buffer);
  let audioPath = audio ? original : null;
  let originalPath = original;
  let mime = audio ? file.mimetype.toLowerCase() : file.mimetype;
  if (audio && [".m4a", ".mp4"].includes(extension)) mime = "audio/mp4";
  if (audio && [".ogg", ".oga"].includes(extension)) mime = "audio/ogg";
  try {
    if (kind === "sermon" && !audio) {
      audioPath = path.join(folder, "sermon.mp3");
      await runFfmpeg(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", original, "-vn", "-codec:a", "libmp3lame", "-b:a", "128k", audioPath], 900000);
      fs.rmSync(original, { force: true });
      originalPath = "";
    }
    await store.query(
      `INSERT INTO media_items(id,title,description,kind,mime_type,original_path,audio_path,cover_path,created_by,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,?)`,
      [id, title || path.parse(file.originalname).name.slice(0, 120), description, kind, mime, originalPath, audioPath, coverPath, user.id, Math.floor(Date.now() / 1000)],
    );
  } catch (e) {
    fs.rmSync(folder, { recursive: true, force: true });
    throw e;
  }
  res.status(201).json({
    id, title: title || path.parse(file.originalname).name.slice(0, 120), kind,
    video_url: kind === "short" ? `/api/media/${id}` : null,
    audio_url: audioPath ? `/api/media/${id}/audio` : null,
    cover_url: coverPath ? `/api/media/${id}/cover` : null,
  });
}));

function runFfmpeg(args, timeout) {
  const configured = process.env.LFC_FFMPEG_PATH || process.env.FFMPEG_PATH || "ffmpeg";
  return new Promise((resolve, reject) => {
    const process = spawn(configured, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    process.stderr.on("data", (chunk) => { stderr = (stderr + chunk.toString()).slice(-4000); });
    const timer = setTimeout(() => {
      process.kill("SIGKILL");
      reject(new Error("Sermon audio conversion took too long. Try a shorter video."));
    }, timeout);
    process.once("error", (e) => { clearTimeout(timer); reject(e); });
    process.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`Could not convert the sermon video: ${stderr.trim().split("\n").pop() || "Unknown conversion error."}`));
    });
  });
}

app.post("/api/sermon-uploads", asyncRoute(async (req, res) => {
  const user = await requireUser(req, res);
  if (!user) return;
  const { filename, mime_type: mime, file_size: size } = req.body || {};
  const safeName = path.basename(String(filename || ""));
  const ext = path.extname(safeName).toLowerCase();
  if (!safeName || !/^\.[a-z0-9]{1,10}$/.test(ext) || typeof mime !== "string" || !mime.startsWith("video/")) {
    return error(res, 400, "Choose a supported video file to convert.");
  }
  if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_VIDEO) return error(res, 400, "Choose a video file up to 20 GB.");
  if (typeof req.body.title !== "string" || req.body.title.trim().length > 120) return error(res, 400, "Enter a sermon title up to 120 characters.");
  const id = uuid();
  fs.mkdirSync(filePath("large-uploads", id), { recursive: false });
  const title = req.body.title.trim() || path.parse(safeName).name.slice(0, 120) || "Sermon";
  await store.query(
    "INSERT INTO sermon_uploads(id,owner_id,original_filename,title,mime_type,file_size,created_at) VALUES(?,?,?,?,?,?,?)",
    [id, user.id, safeName, title, mime.toLowerCase(), size, Math.floor(Date.now() / 1000)],
  );
  res.status(201).json({ id, chunk_size: CHUNK_SIZE, uploaded_bytes: 0, file_size: size });
}));

async function ownedUpload(req, res) {
  const user = await requireUser(req, res);
  if (!user) return null;
  const { rows } = await store.query("SELECT * FROM sermon_uploads WHERE id=?", [req.params.id]);
  const item = rows[0];
  if (!item) { error(res, 404, "Large sermon upload not found."); return null; }
  if (user.role !== "admin" && item.owner_id !== user.id) { error(res, 403, "Only the uploader or an admin can manage this sermon upload."); return null; }
  return { user, item };
}

app.post("/api/sermon-uploads/:id/chunk", express.raw({ type: ["application/octet-stream", "video/*"], limit: "16mb" }), asyncRoute(async (req, res) => {
  const owned = await ownedUpload(req, res);
  if (!owned) return;
  const offset = Number(req.get("x-upload-offset"));
  const chunk = req.body;
  const contentType = req.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (!["application/octet-stream", owned.item.mime_type.split(";", 1)[0].trim().toLowerCase()].includes(contentType)) {
    return error(res, 400, "Invalid video upload chunk content type.");
  }
  await withSermonUploadLock(owned.item.id, async () => {
    const { rows } = await store.query("SELECT * FROM sermon_uploads WHERE id=?", [owned.item.id]);
    const item = rows[0];
    if (!item) return error(res, 404, "Large sermon upload not found.");
    if (!Buffer.isBuffer(chunk) || !chunk.length || offset !== Number(item.uploaded_bytes) ||
        offset >= Number(item.file_size) || chunk.length !== Math.min(CHUNK_SIZE, Number(item.file_size) - offset)) {
      return error(res, 409, "The video upload offset or chunk size is invalid.");
    }
    const source = filePath("large-uploads", item.id, `source${path.extname(item.original_filename).toLowerCase()}`);
    if (fs.existsSync(source) && fs.statSync(source).size > offset) {
      fs.truncateSync(source, offset);
    }
    if (offset > 0 && (!fs.existsSync(source) || fs.statSync(source).size !== offset)) {
      return error(res, 409, "The video upload file is out of sync. Retry the last confirmed chunk.");
    }
    fs.writeFileSync(source, chunk, { flag: offset === 0 ? "w" : "a" });
    const uploaded = offset + chunk.length;
    const result = await store.query("UPDATE sermon_uploads SET uploaded_bytes=?,created_at=? WHERE id=? AND uploaded_bytes=?",
      [uploaded, Math.floor(Date.now() / 1000), item.id, offset]);
    if (!result.rowCount) return error(res, 409, "The video upload offset changed. Retry the last confirmed chunk.");
    res.json({ id: item.id, uploaded_bytes: uploaded, file_size: item.file_size });
  });
}));

app.post("/api/sermon-uploads/:id/cover", mediaUpload, asyncRoute(async (req, res) => {
  const owned = await ownedUpload(req, res);
  if (!owned) return;
  const cover = uploaded(req, "file") || uploaded(req, "cover");
  if (!cover || !signatureOk(cover) || cover.size > 5 * 1024 * 1024) return error(res, 400, "Choose a valid JPEG, PNG, or WebP wallpaper smaller than 5 MB.");
  const filename = filePath("large-uploads", owned.item.id, `cover${imageExtension(cover)}`);
  fs.writeFileSync(filename, cover.buffer);
  await store.query("UPDATE sermon_uploads SET cover_path=? WHERE id=?", [filename, owned.item.id]);
  res.json({ ok: true });
}));

app.post("/api/sermon-uploads/:id/complete", asyncRoute(async (req, res) => {
  const owned = await ownedUpload(req, res);
  if (!owned) return;
  const { item, user } = owned;
  if (Number(item.uploaded_bytes) !== Number(item.file_size)) return error(res, 409, "The video upload is incomplete.");
  const id = uuid();
  const folder = filePath("media", id);
  fs.mkdirSync(folder, { recursive: true });
  const source = filePath("large-uploads", item.id, `source${path.extname(item.original_filename).toLowerCase()}`);
  const audio = path.join(folder, "sermon.mp3");
  try {
    await runFfmpeg(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", source, "-vn", "-codec:a", "libmp3lame", "-b:a", "128k", audio], 24 * 60 * 60 * 1000);
    let coverPath = item.cover_path || null;
    if (coverPath) {
      const target = path.join(folder, path.basename(coverPath));
      fs.copyFileSync(coverPath, target);
      coverPath = target;
    }
    await store.query(
      `INSERT INTO media_items(id,title,description,kind,mime_type,original_path,audio_path,cover_path,created_by,created_at)
       VALUES(?,?,?,'sermon','audio/mpeg','',?,?,?,?)`,
      [id, item.title, "", audio, coverPath, user.id, Math.floor(Date.now() / 1000)],
    );
    await store.query("DELETE FROM sermon_uploads WHERE id=?", [item.id]);
    fs.rmSync(path.dirname(source), { recursive: true, force: true });
  } catch (e) {
    fs.rmSync(folder, { recursive: true, force: true });
    throw e;
  }
  res.status(201).json({ id, title: item.title, kind: "sermon", audio_url: `/api/media/${id}/audio`, cover_url: coverPath ? `/api/media/${id}/cover` : null });
}));

app.delete("/api/sermon-uploads/:id", asyncRoute(async (req, res) => {
  const owned = await ownedUpload(req, res);
  if (!owned) return;
  await store.query("DELETE FROM sermon_uploads WHERE id=?", [owned.item.id]);
  fs.rmSync(filePath("large-uploads", owned.item.id), { recursive: true, force: true });
  res.json({ ok: true });
}));

app.post("/api/media/:id/view", asyncRoute(async (req, res) => {
  await store.query("UPDATE media_items SET view_count=view_count+1 WHERE id=? AND kind='sermon'", [req.params.id]);
  const { rows } = await store.query("SELECT view_count FROM media_items WHERE id=? AND kind='sermon'", [req.params.id]);
  if (!rows[0]) return error(res, 404, "Sermon not found.");
  res.json({ view_count: rows[0].view_count });
}));
app.post("/api/recordings/:id/view", asyncRoute(async (req, res) => {
  await store.query("UPDATE streams SET view_count=view_count+1 WHERE id=? AND status='completed'", [req.params.id]);
  const { rows } = await store.query("SELECT view_count FROM streams WHERE id=? AND status='completed'", [req.params.id]);
  if (!rows[0]) return error(res, 404, "Recording not found.");
  res.json({ view_count: rows[0].view_count });
}));
async function updateTitle(req, res) {
  if (!await requireUser(req, res, ["admin"])) return;
  const title = req.body?.title;
  if (typeof title !== "string" || !title.trim() || title.trim().length > 120) return error(res, 400, "Enter a sermon title up to 120 characters.");
  const table = req.params.collection === "recordings" ? "streams" : "media_items";
  const condition = table === "streams" ? "status='completed'" : "kind='sermon'";
  const { rowCount } = await store.query(`UPDATE ${table} SET title=? WHERE id=? AND ${condition}`, [title.trim(), req.params.id]);
  if (!rowCount) return error(res, 404, "Sermon not found.");
  res.json({ id: req.params.id, title: title.trim() });
}
app.post("/api/media/:id/title", asyncRoute(async (req, res) => {
  req.params.collection = "media";
  await updateTitle(req, res);
}));
app.post("/api/recordings/:id/title", asyncRoute(async (req, res) => {
  req.params.collection = "recordings";
  await updateTitle(req, res);
}));

app.post("/api/streams", mediaUpload, asyncRoute(async (req, res) => {
  if (!await requireStudio(req, res)) return;
  const user = await requireUser(req, res);
  if (!user) return;
  const title = String(req.body.title || "").trim().slice(0, 120);
  const mime = String(req.body.mime_type || "");
  const cover = uploaded(req, "cover");
  if (!title) return error(res, 400, "Enter a title for the stream.");
  if (!["audio/webm;codecs=opus", "audio/webm", "audio/ogg;codecs=opus", "audio/ogg"].includes(mime)) return error(res, 400, "This browser's audio format is not supported.");
  if (uploaded(req, "file")) return error(res, 400, "A live stream accepts a wallpaper, not a video file.");
  if (cover && (!signatureOk(cover) || cover.size > 5 * 1024 * 1024)) return error(res, 400, "Choose a valid JPEG, PNG, or WebP wallpaper.");
  const id = uuid();
  const folder = filePath(id);
  fs.mkdirSync(folder, { recursive: false });
  const coverPath = cover ? path.join(folder, `cover${imageExtension(cover)}`) : null;
  if (cover) fs.writeFileSync(coverPath, cover.buffer);
  try {
    await store.query("INSERT INTO streams(id,title,mime_type,cover_path,owner_id,started_at,status) VALUES(?,?,?,?,?,?,'live')",
      [id, title, mime, coverPath, user.id, Math.floor(Date.now() / 1000)]);
  } catch (e) {
    fs.rmSync(folder, { recursive: true, force: true });
    throw e;
  }
  res.status(201).json({ id, title, mime_type: mime, cover_url: coverPath ? `/api/streams/${id}/cover` : null });
}));

app.post("/api/streams/:id/chunks", express.raw({ type: ["audio/webm", "audio/ogg"], limit: "2mb" }), asyncRoute(async (req, res) => {
  if (!await requireStudio(req, res)) return;
  const user = await requireUser(req, res);
  if (!user) return;
  const { rows } = await store.query("SELECT * FROM streams WHERE id=?", [req.params.id]);
  const stream = rows[0];
  if (!stream) return error(res, 404, "Stream not found.");
  if (stream.status !== "live") return error(res, 409, "This stream is no longer live.");
  if (user.role !== "admin" && stream.owner_id !== user.id) return error(res, 403, "Only the streamer or an admin can control this stream.");
  const sequence = Number(req.get("x-audio-sequence"));
  const chunk = req.body;
  if (!Number.isInteger(sequence) || sequence < 0 || !Buffer.isBuffer(chunk) || !chunk.length || chunk.length > 2 * 1024 * 1024) return error(res, 400, "Audio segment is empty or too large.");
  const filename = filePath(req.params.id, `${String(sequence).padStart(8, "0")}.part`);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  try { fs.writeFileSync(filename, chunk, { flag: "wx" }); }
  catch (e) { if (e.code === "EEXIST") return error(res, 409, "Audio segment was already received."); throw e; }
  try {
    await store.query("INSERT INTO audio_chunks(stream_id,sequence,file_path) VALUES(?,?,?)", [req.params.id, sequence, filename]);
  } catch (e) { fs.rmSync(filename, { force: true }); throw e; }
  res.status(201).json({ sequence });
}));

app.post("/api/streams/:id/stop", express.raw({ type: ["audio/webm", "audio/ogg", "audio/wav"], limit: "500mb" }), asyncRoute(async (req, res) => {
  if (!await requireStudio(req, res)) return;
  const user = await requireUser(req, res);
  if (!user) return;
  const { rows } = await store.query("SELECT * FROM streams WHERE id=?", [req.params.id]);
  const stream = rows[0];
  if (!stream) return error(res, 404, "Stream not found.");
  if (stream.status !== "live") return error(res, 409, "This stream is no longer live.");
  if (user.role !== "admin" && stream.owner_id !== user.id) return error(res, 403, "Only the streamer or an admin can control this stream.");
  const mime = req.get("content-type")?.split(";", 1)[0].toLowerCase();
  const extension = ({ "audio/webm": "webm", "audio/ogg": "ogg", "audio/wav": "wav" })[mime];
  if (!extension || !Buffer.isBuffer(req.body) || req.body.length <= 4 || req.body.length > MAX_RECORDING) return error(res, 400, "The saved recording is empty or larger than 500 MB.");
  if (mime !== "audio/wav" && mime !== stream.mime_type.split(";", 1)[0]) return error(res, 400, "The saved recording format does not match the live stream.");
  const expected = { webm: Buffer.from([0x1a, 0x45, 0xdf, 0xa3]), ogg: Buffer.from("OggS"), wav: Buffer.from("RIFF") }[extension];
  if (!req.body.subarray(0, expected.length).equals(expected)) return error(res, 400, "The saved recording format is invalid.");
  const chunks = req.body;
  fs.writeFileSync(filePath(req.params.id, `recording.${extension}`), chunks);
  await store.query("UPDATE streams SET status='completed',ended_at=?,mime_type=? WHERE id=? AND status='live'",
    [Math.floor(Date.now() / 1000), mime, req.params.id]);
  res.json({ ok: true, recording_url: `/api/recordings/${req.params.id}` });
}));

app.delete("/api/media/:id", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const { rows } = await store.query("SELECT kind,auto_discovered FROM media_items WHERE id=?", [req.params.id]);
  if (!rows[0] || rows[0].kind !== "sermon") return error(res, 404, "Sermon not found.");
  await store.query("DELETE FROM media_items WHERE id=?", [req.params.id]);
  if (!rows[0].auto_discovered) fs.rmSync(filePath("media", req.params.id), { recursive: true, force: true });
  res.json({ ok: true, id: req.params.id });
}));

app.delete("/api/recordings/:id", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const { rows } = await store.query("SELECT status FROM streams WHERE id=?", [req.params.id]);
  if (rows[0]?.status !== "completed") return error(res, 404, "Completed sermon recording not found.");
  await store.query("DELETE FROM streams WHERE id=?", [req.params.id]);
  fs.rmSync(filePath(req.params.id), { recursive: true, force: true });
  res.json({ ok: true, id: req.params.id });
}));

app.delete("/api/verses/:id", asyncRoute(async (req, res) => {
  if (!await requireUser(req, res, ["admin"])) return;
  const { rowCount } = await store.query("DELETE FROM church_verses WHERE id=?", [req.params.id]);
  if (!rowCount) return error(res, 404, "Church verse not found.");
  res.json({ ok: true, id: req.params.id });
}));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return error(res, 404, "API route not found.");
  const file = req.path === "/" ? "index.html" : path.basename(req.path);
  const full = path.join(FRONTEND_DIR, file);
  if (full !== path.join(FRONTEND_DIR, path.basename(full)) || !fs.existsSync(full)) return error(res, 404, "Page not found.");
  res.set("Cache-Control", file === "bible-kjv.json" ? "public, max-age=86400" : "no-store");
  res.sendFile(full);
});

app.use((err, _req, res, _next) => {
  console.error("Request failed:", err);
  if (res.headersSent) return;
  if (err instanceof multer.MulterError || err.type === "entity.too.large") {
    return error(res, 413, "The uploaded file is too large.");
  }
  if (err.message?.includes("FFmpeg")) return error(res, 503, err.message);
  if (err.code === "23505" || err.code === "SQLITE_CONSTRAINT_UNIQUE") {
    return error(res, 409, "That email or stream is already in use.");
  }
  return error(res, 500, "The request could not be completed.");
});

await initialize();
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Life Fountain Church JavaScript backend listening on 0.0.0.0:${PORT}`);
  console.log(`Persistent media directory: ${MEDIA_DIR}`);
  const setupPath = path.join(DATA_DIR, ".setup-code");
  if (fs.existsSync(setupPath)) {
    console.log(`First-time admin setup code (keep it private): ${fs.readFileSync(setupPath, "utf8").trim()}`);
  }
});

async function shutdown() {
  server.close(async () => {
    await store.close();
    process.exit(0);
  });
}
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
