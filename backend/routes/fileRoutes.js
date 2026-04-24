/**
 * routes/fileRoutes.js — GuardianBox API Routes
 *
 * POST /api/upload       — Accept encrypted file, store it
 * GET  /api/file/:id/meta — Return file metadata (filename, size, expiry, etc.)
 * GET  /api/file/:id     — Return encrypted file + IV + salt
 * DELETE /api/file/:id  — Manual delete
 */

const express    = require("express");
const multer     = require("multer");
const { uploadFile, getFileMeta, getFileData, deleteFile } = require("../controllers/fileController");

const router = express.Router();

// ── Multer: store encrypted file in memory, then we write it to disk ──────────
// memoryStorage means multer gives us req.file.buffer (the raw ciphertext bytes)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100 MB max
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    // We accept any file type because everything is already ciphertext anyway
    cb(null, true);
  },
});

// ── POST /api/upload ──────────────────────────────────────────────────────────
// Receives: multipart/form-data with:
//   file      (binary ciphertext blob)
//   iv        (base64 string)
//   filename  (original filename — NOT sensitive, but encrypted separately)
//   mimetype  (original MIME type)
//   mode      "password" | "keyless"
//   salt      (base64, only in password mode)
//   expiry    (seconds)
//   maxDownloads (optional integer)
router.post("/upload", upload.single("file"), uploadFile);

// ── GET /api/file/:id/meta ────────────────────────────────────────────────────
// Returns public metadata (no ciphertext) so UI can display file info
// before user enters their password
router.get("/file/:id/meta", getFileMeta);

// ── GET /api/file/:id ─────────────────────────────────────────────────────────
// Returns the full encrypted payload: ciphertext (base64) + iv + salt + filename + mimetype
// Decrements download counter; deletes file if limit reached
router.get("/file/:id", getFileData);

// ── DELETE /api/file/:id ──────────────────────────────────────────────────────
router.delete("/file/:id", deleteFile);

module.exports = router;
