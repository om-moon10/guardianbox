/**
 * services/storageService.js — GuardianBox Local File Storage Service
 *
 * Storage strategy:
 *   - Encrypted ciphertext bytes → saved as binary files in ./uploads/<id>.enc
 *   - Metadata (iv, salt, filename, expiry, etc.) → saved in ./uploads/db.json
 *
 * In production: swap the JSON db with MongoDB/PostgreSQL,
 *               and the local filesystem with AWS S3.
 *
 * The ciphertext files are UNREADABLE without the key. Even if someone
 * gets full disk access to the server, they cannot decrypt the files.
 */

console.log("S3 INIT:", {
  region: process.env.AWS_REGION,
  bucket: process.env.S3_BUCKET_NAME,
});

//changes for s3 service
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.S3_BUCKET_NAME;
//changes for s3 service ends here

const fs   = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

// ── Paths ──────────────────────────────────────────────────────────────────────

const UPLOADS_DIR = path.join(__dirname, "../uploads");
const DB_PATH     = path.join(UPLOADS_DIR, "db.json");

// Ensure uploads directory exists on startup
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  console.log("[STORAGE] Created uploads directory:", UPLOADS_DIR);
}

// ── DB Helpers (JSON-based "database") ────────────────────────────────────────

function readDB() {
  if (!fs.existsSync(DB_PATH)) return {};
  const raw = fs.readFileSync(DB_PATH, "utf-8");
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}

// ── storeFile ─────────────────────────────────────────────────────────────────

/**
 * Saves an encrypted file to disk and records metadata in the DB.
 *
 * @param {Object} params
 * @param {Buffer}  params.ciphertext   - Raw encrypted bytes
 * @param {string}  params.iv           - Base64 IV
 * @param {string|null} params.salt     - Base64 salt (password mode only)
 * @param {string}  params.filename     - Original (sanitized) filename
 * @param {string}  params.mimetype     - MIME type
 * @param {string}  params.mode         - "password" | "keyless"
 * @param {string}  params.expiresAt    - ISO date string
 * @param {number|null} params.maxDownloads
 * @param {number}  params.downloadCount
 * @returns {Promise<string>} The file ID
 */
async function storeFile({ ciphertext, iv, salt, filename, mimetype, mode, expiresAt, maxDownloads, downloadCount }) {
  const id       = uuidv4();
  // Upload encrypted file to S3
await s3.send(new PutObjectCommand({
  Bucket: BUCKET,
  Key: `${id}.enc`,
  Body: ciphertext,
  ContentType: "application/octet-stream",
}));

  // Save metadata to JSON db
  const db = readDB();
  db[id] = {
    id,
    filename,
    mimetype,
    mode,
    iv,
    salt: salt || null,
    size: ciphertext.length,
    expiresAt,
    maxDownloads: maxDownloads || null,
    downloadCount: 0,
    createdAt: new Date().toISOString(),
  };
  writeDB(db);

  return id;
}

// ── loadFileMeta ──────────────────────────────────────────────────────────────

/**
 * Returns metadata for a file without loading the ciphertext.
 * Used for the file info page (before decryption).
 */
async function loadFileMeta(id) {
  if (!isValidId(id)) return null;
  const db = readDB();
  return db[id] || null;
}

// ── loadFileData ──────────────────────────────────────────────────────────────

/**
 * Returns full file data including the ciphertext Buffer.
 * Attaches an incrementDownloads() method for the controller to call.
 */
async function loadFileData(id) {
  if (!isValidId(id)) return null;

  const db   = readDB();
  const meta = db[id];
  if (!meta) return null;

  //update for s3 service

  let ciphertext;

try {
  const response = await s3.send(new GetObjectCommand({
    Bucket: BUCKET,
    Key: `${id}.enc`,
  }));

  const chunks = [];
  for await (const chunk of response.Body) {
    chunks.push(chunk);
  }
  ciphertext = Buffer.concat(chunks);

} catch (err) {
  console.error("S3 fetch error:", err);
  delete db[id];
  writeDB(db);
  return null;
}

  // Attach a method to increment the download counter atomically
  const incrementDownloads = async () => {
    const freshDB = readDB();
    if (freshDB[id]) {
      freshDB[id].downloadCount = (freshDB[id].downloadCount || 0) + 1;
      writeDB(freshDB);
    }
  };

  return {
    ...meta,
    ciphertext,       // Buffer — raw encrypted bytes
    incrementDownloads,
  };
}

// ── removeFile ────────────────────────────────────────────────────────────────

/**
 * Deletes the ciphertext file and removes the metadata entry.
 * @returns {boolean} true if deleted, false if not found
 */
async function removeFile(id) {
  if (!isValidId(id)) return false;

  const db = readDB();
  if (!db[id]) return false;

  // Delete the encrypted file updated for s3 service
  try {
  await s3.send(new DeleteObjectCommand({
    Bucket: BUCKET,
    Key: `${id}.enc`,
  }));
} catch (err) {
  console.error("S3 delete error:", err);
}

  // Remove metadata
  delete db[id];
  writeDB(db);

  return true;
}

// ── deleteExpiredFiles ────────────────────────────────────────────────────────

/**
 * Called by the cron job. Finds all expired files and deletes them.
 * @returns {number} Count of deleted files
 */
async function deleteExpiredFiles() {
  const db  = readDB();
  const now = new Date();
  let count = 0;

  for (const [id, meta] of Object.entries(db)) {
    const expired       = new Date(meta.expiresAt) < now;
    const limitReached  = meta.maxDownloads !== null && meta.downloadCount >= meta.maxDownloads;

    if (expired || limitReached) {
      try {
        console.log("Deleting from S3:", `${id}.enc`);
        console.log("NOW:", new Date().toISOString());
        console.log("EXP:", meta.expiresAt);
        console.log("EXPIRED?", new Date(meta.expiresAt) < new Date());
      await s3.send(new DeleteObjectCommand({
      Bucket: BUCKET,
    Key: `${id}.enc`,
  }));
} catch (err) {
  console.error("S3 delete error:", err);
}
      delete db[id];
      count++;
    }
  }

  if (count > 0) writeDB(db);
  return count;
}

// ── Security: validate ID format ──────────────────────────────────────────────

/**
 * Ensures the ID is a valid UUIDv4.
 * Prevents path traversal attacks like id = "../../etc/passwd"
 */
function isValidId(id) {
  const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return typeof id === "string" && UUID_REGEX.test(id);
}

module.exports = {
  storeFile,
  loadFileMeta,
  loadFileData,
  removeFile,
  deleteExpiredFiles,
};
