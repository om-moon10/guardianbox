/**
 * server.js — GuardianBox Backend Entry Point
 *
 * What this server does:
 *   ✅ Accepts encrypted file uploads (ciphertext only — NEVER plaintext)
 *   ✅ Stores metadata in a JSON file (or swap with MongoDB easily)
 *   ✅ Serves encrypted files on request
 *   ✅ Runs a cron job to delete expired files
 *   ✅ Enforces download limits (burn-after-read)
 *
 * What this server NEVER does:
 *   ❌ Receives or stores passwords
 *   ❌ Receives or stores encryption keys
 *   ❌ Can decrypt any file
 */

require("dotenv").config();
console.log("ENV:", {
  region: process.env.AWS_REGION,
  bucket: process.env.S3_BUCKET_NAME,
});

//update update 
const cron = require("node-cron");
const { deleteExpiredFiles } = require("./services/storageService");

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const fileRoutes = require("./routes/fileRoutes");

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Security Headers ──────────────────────────────────────────────────────────
// helmet sets sensible HTTP security headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }, // allow file downloads
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
// In production: replace '*' with your actual frontend domain
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://guardianbox.vercel.app"
  ]
}));

// ── Body parsers ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "1mb" }));  // For JSON bodies
// Large file uploads handled by multer inside routes

// ── Routes ───────────────────────────────────────────────────────────────────
app.use("/api", fileRoutes);

app.listen(4000, () => {
  console.log("Server running...");
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "GuardianBox", timestamp: new Date().toISOString() });
});

// ── Cron: Delete expired files every 5 minutes ────────────────────────────────
// "*/1 * * * *" = every 1 minute
// Run every hour
cron.schedule("*/1 * * * *", async () => {
  console.log("[CRON] Checking for expired files...");

  try {
    const deleted = await deleteExpiredFiles();
    if (deleted > 0) {
      console.log(`[CRON] Deleted ${deleted} expired files`);
    }
  } catch (err) {
    console.error("[CRON ERROR]", err);
  }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(err.status || 500).json({ message: err.message || "Internal server error" });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🛡️  GuardianBox backend running on http://localhost:${PORT}`);
  console.log(`   Mode: ${process.env.NODE_ENV || "development"}`);
  console.log(`   Storage: local filesystem (./uploads/)`);
});
