/**
 * controllers/fileController.js — GuardianBox Request Handlers
 *
 * This layer handles HTTP concerns: parsing requests, validating inputs,
 * calling services, and formatting responses.
 *
 * SECURITY REMINDER: We NEVER log passwords, keys, or file contents.
 * We log only IDs, timestamps, and byte counts.
 */

const {
  storeFile,
  loadFileMeta,
  loadFileData,
  removeFile,
} = require("../services/storageService");

// ── Upload Handler ─────────────────────────────────────────────────────────────

/**
 * POST /api/upload
 * Validates the encrypted upload and stores it.
 */
async function uploadFile(req, res, next) {
  try {
    const { iv, filename, mimetype, mode, salt, expiry, maxDownloads } = req.body;

    // ── Input Validation ────────────────────────────────────────────────────────

    if (!req.file) {
      return res.status(400).json({ message: "No file provided." });
    }

    if (!iv || typeof iv !== "string") {
      return res.status(400).json({ message: "IV is required." });
    }

    if (!filename || typeof filename !== "string" || filename.length > 255) {
      return res.status(400).json({ message: "Filename is required (max 255 chars)." });
    }

    if (!mode || !["password", "keyless"].includes(mode)) {
      return res.status(400).json({ message: "Mode must be 'password' or 'keyless'." });
    }

    if (mode === "password" && !salt) {
      return res.status(400).json({ message: "Salt is required for password mode." });
    }

    const expirySeconds = parseInt(expiry, 10);
    if (isNaN(expirySeconds) || expirySeconds < 60 || expirySeconds > 2592000) {
      return res.status(400).json({ message: "Expiry must be between 60s and 30 days." });
    }

    const maxDl = maxDownloads ? parseInt(maxDownloads, 10) : null;
    if (maxDl !== null && (isNaN(maxDl) || maxDl < 1 || maxDl > 1000)) {
      return res.status(400).json({ message: "maxDownloads must be between 1 and 1000." });
    }

    // ── Store File ──────────────────────────────────────────────────────────────
    // req.file.buffer = raw ciphertext bytes (never plaintext)
    const id = await storeFile({
      ciphertext:   req.file.buffer,  // encrypted bytes
      iv,                              // base64 IV (not secret — needed for decryption)
      salt:         salt || null,      // base64 salt (not secret — needed for key derivation)
      filename:     sanitizeFilename(filename),
      mimetype:     mimetype || "application/octet-stream",
      mode,
      expiresAt:    new Date(Date.now() + expirySeconds * 1000).toISOString(),
      maxDownloads: maxDl,
      downloadCount: 0,
    });

    console.log(`[UPLOAD] id=${id} size=${req.file.size}B mode=${mode} expires=${new Date(Date.now() + expirySeconds * 1000).toISOString()}`);

    res.status(201).json({ id });

  } catch (err) {
    next(err);
  }
}

// ── Get Metadata ───────────────────────────────────────────────────────────────

/**
 * GET /api/file/:id/meta
 * Returns public metadata without the ciphertext.
 * Used by the download page to show file info before decryption.
 */
async function getFileMeta(req, res, next) {
  try {
    const meta = await loadFileMeta(req.params.id);

    if (!meta) {
      return res.status(404).json({ error: "not_found" });
    }

    if (isExpired(meta)) {
      // Clean up and report expired
      await removeFile(req.params.id).catch(() => {});
      return res.status(410).json({ error: "expired" });
    }

    // Return only the fields the UI needs — NOT the ciphertext
    res.json({
      filename:      meta.filename,
      mimetype:      meta.mimetype,
      size:          meta.size,
      mode:          meta.mode,
      expiresAt:     meta.expiresAt,
      downloadsLeft: meta.maxDownloads !== null
                       ? meta.maxDownloads - meta.downloadCount
                       : null,
    });

  } catch (err) {
    next(err);
  }
}

// ── Get Full Encrypted File ────────────────────────────────────────────────────

/**
 * GET /api/file/:id
 * Returns the full encrypted payload for decryption in the browser.
 * Increments download counter; deletes if limit reached.
 */
async function getFileData(req, res, next) {
  try {
    const data = await loadFileData(req.params.id);

    if (!data) {
      return res.status(404).json({ message: "File not found or already deleted." });
    }

    if (isExpired(data)) {
      await removeFile(req.params.id).catch(() => {});
      return res.status(410).json({ message: "This file has expired." });
    }

    // Check download limit
    if (data.maxDownloads !== null && data.downloadCount >= data.maxDownloads) {
      await removeFile(req.params.id).catch(() => {});
      return res.status(410).json({ message: "Download limit reached. File deleted." });
    }

    // Increment download count BEFORE responding (prevents race conditions from being catastrophic)
    await data.incrementDownloads();

    console.log(`[DOWNLOAD] id=${req.params.id} count=${data.downloadCount + 1}`);

    // Burn after read: delete if this was the last allowed download
    if (data.maxDownloads !== null && data.downloadCount + 1 >= data.maxDownloads) {
      // Delete asynchronously — don't block the response
      removeFile(req.params.id)
        .then(() => console.log(`[DELETE] Burn-after-read: ${req.params.id}`))
        .catch(console.error);
    }

    // Return ciphertext as base64 + metadata needed for decryption
    // The client will decrypt this entirely in the browser
    res.json({
      ciphertext: data.ciphertext.toString("base64url"), // binary → base64
      iv:         data.iv,
      salt:       data.salt || null,
      filename:   data.filename,
      mimetype:   data.mimetype,
    });

  } catch (err) {
    next(err);
  }
}

// ── Delete Handler ─────────────────────────────────────────────────────────────

/**
 * DELETE /api/file/:id
 * Manual deletion. In production, add authentication here.
 */
async function deleteFile(req, res, next) {
  try {
    const deleted = await removeFile(req.params.id);
    if (!deleted) {
      return res.status(404).json({ message: "File not found." });
    }
    res.json({ message: "File deleted." });
  } catch (err) {
    next(err);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function isExpired(meta) {
  return new Date(meta.expiresAt) < new Date();
}

/**
 * Strip dangerous characters from filenames to prevent path traversal.
 * Only allow alphanumeric, dots, dashes, underscores, and spaces.
 */
function sanitizeFilename(name) {
  return name
    .replace(/[^a-zA-Z0-9.\-_ ]/g, "_") // replace bad chars with underscore
    .replace(/\.{2,}/g, "_")              // prevent ".." (path traversal)
    .slice(0, 255);                       // max length
}

module.exports = { uploadFile, getFileMeta, getFileData, deleteFile };
