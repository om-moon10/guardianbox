/**
 * UploadPage.jsx
 *
 * Flow:
 *   1. User picks a file
 *   2. User enters password OR chooses "generate shareable link" (keyless)
 *   3. encryptFileWithPassword / encryptFile runs in browser
 *   4. Ciphertext + IV + salt sent to POST /api/upload
 *   5. Server returns a file ID
 *   6. We build the share URL: /file/:id#base64(key or password-hint)
 */

import React, { useState, useRef, useCallback } from "react";
import {
  encryptFileWithPassword,
  generateShareableKey,
  encryptFile,
  bytesToBase64,
} from "../utils/cryptoUtils";
import "./UploadPage.css";

const API_BASE = process.env.REACT_APP_API_URL || "https://guardianbox-backend-fxtn.onrender.com";

const EXPIRY_OPTIONS = [
  { value: 60, label: "1 Minute (Test)" },
  { label: "1 Hour",   value: 3600 },
  { label: "24 Hours", value: 86400 },
  { label: "7 Days",   value: 604800 },
  { label: "30 Days",  value: 2592000 },
];

export default function UploadPage() {
  const [file,          setFile]          = useState(null);
  const [password,      setPassword]      = useState("");
  const [usePassword,   setUsePassword]   = useState(true);
  const [expiry,        setExpiry]        = useState(86400);
  const [maxDownloads,  setMaxDownloads]  = useState("");
  const [status,        setStatus]        = useState("idle"); // idle | encrypting | uploading | done | error
  const [shareURL,      setShareURL]      = useState("");
  const [error,         setError]         = useState("");
  const [progress,      setProgress]      = useState(0);
  const [dragOver,      setDragOver]      = useState(false);

  const fileInputRef = useRef(null);

  // ── Drag & Drop ─────────────────────────────────────────────────────────────

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  }, []);

  const handleDragOver = (e) => { e.preventDefault(); setDragOver(true); };
  const handleDragLeave = ()   => setDragOver(false);

  // ── Upload Flow ──────────────────────────────────────────────────────────────

  const handleUpload = async () => {
    setError("");

    // Validation
    if (!file) return setError("Please select a file.");
    if (usePassword && password.length < 6)
      return setError("Password must be at least 6 characters.");

    try {
      // ── Step 1: Encrypt in browser ──────────────────────────────────────────
      setStatus("encrypting");
      setProgress(20);

      let ciphertext, iv, salt, shareKey;

      if (usePassword) {
        const result = await encryptFileWithPassword(file, password);
        ciphertext   = result.ciphertext;
        iv           = result.iv;
        salt         = result.salt;
      } else {
        const { key, rawKey } = await generateShareableKey();
        const result = await encryptFile(file, key);
        ciphertext   = result.ciphertext;
        iv           = result.iv;
        salt         = null;
        shareKey     = rawKey; 
      }

      setProgress(50);

      // ── Step 2: Build FormData payload ──────────────────────────────────────
      setStatus("uploading");

      const formData = new FormData();

      formData.append("file",     new Blob([ciphertext], { type: "application/octet-stream" }));
      formData.append("iv",       bytesToBase64(iv));
      formData.append("filename", file.name);
      formData.append("mimetype", file.type || "application/octet-stream");
      formData.append("expiry",   expiry.toString());
      formData.append("mode",     usePassword ? "password" : "keyless");

      if (salt)         formData.append("salt",         bytesToBase64(salt));
      if (maxDownloads) formData.append("maxDownloads", maxDownloads.toString());

      // ── Step 3: POST to backend ─────────────────────────────────────────────
      const response = await fetch(`${API_BASE}/api/upload`, {
        method: "POST",
        body:   formData,
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.message || `Server error ${response.status}`);
      }

      const { id } = await response.json();
      setProgress(90);

      // ── Step 4: Build share URL ─────────────────────────────────────────────
      let hash = "";
      if (!usePassword && shareKey) {
        hash = `#key:${bytesToBase64(shareKey)}`;
      }


      const url = `${window.location.origin}/file/${id}${hash}`;
      setShareURL(url);
      setProgress(100);
      setStatus("done");

    } catch (err) {
      console.error(err);
      setError(err.message || "Something went wrong.");
      setStatus("error");
      setProgress(0);
    }
  };

  const copyURL = () => {
    navigator.clipboard.writeText(shareURL);
  };

  const reset = () => {
    setFile(null);
    setPassword("");
    setShareURL("");
    setError("");
    setStatus("idle");
    setProgress(0);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  if (status === "done") {
    return (
      <div className="upload-success">
        <div className="success-icon">🔒</div>
        <h2>File Encrypted & Uploaded</h2>
        <p className="success-sub">
          Your file was encrypted <strong>in your browser</strong> before leaving your device.
          The server only holds ciphertext it cannot read.
        </p>

        <div className="share-box">
          <label>Share Link</label>
          <div className="share-url-row">
            <input readOnly value={shareURL} className="share-url-input" />
            <button onClick={copyURL} className="btn-copy">Copy</button>
          </div>
          {usePassword && (
            <p className="password-note">
              ⚠️ This link alone is NOT enough — you must also share your password
              through a separate secure channel (e.g. Signal, in person).
            </p>
          )}
          {!usePassword && (
            <p className="password-note green">
              ✅ The decryption key is embedded in the URL hash — share this link and anyone
              with it can decrypt the file. The server never sees the key.
            </p>
          )}
        </div>

        <button onClick={reset} className="btn-secondary">Upload Another File</button>
      </div>
    );
  }

  return (
    <div className="upload-page">
      <div className="upload-header">
        <h2>Encrypt & Share</h2>
        <p>Your file is encrypted <em>before</em> it leaves your browser.</p>
      </div>

      {/* Drop Zone */}
      <div
        className={`dropzone ${dragOver ? "drag-over" : ""} ${file ? "has-file" : ""}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          hidden
          onChange={(e) => setFile(e.target.files[0])}
        />
        {file ? (
          <div className="file-info">
            <span className="file-icon">📄</span>
            <div>
              <p className="file-name">{file.name}</p>
              <p className="file-size">{formatBytes(file.size)}</p>
            </div>
            <button className="btn-remove" onClick={(e) => { e.stopPropagation(); setFile(null); }}>✕</button>
          </div>
        ) : (
          <>
            <div className="drop-icon">🛡️</div>
            <p>Drop file here or <span className="link">browse</span></p>
            <p className="drop-sub">Any file type · Max 100 MB</p>
          </>
        )}
      </div>

      {/* Encryption Mode Toggle */}
      <div className="mode-toggle">
        <button
          className={`mode-btn ${usePassword ? "active" : ""}`}
          onClick={() => setUsePassword(true)}
        >🔑 Password Protected</button>
        <button
          className={`mode-btn ${!usePassword ? "active" : ""}`}
          onClick={() => setUsePassword(false)}
        >🔗 Link-Only (Random Key)</button>
      </div>

      {usePassword && (
        <div className="field-group">
          <label>Encryption Password</label>
          <input
            type="password"
            placeholder="Min 6 characters — never sent to server"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="text-input"
          />
          <p className="field-hint">
            Recipient will need this password to decrypt. Share it via a separate channel.
          </p>
        </div>
      )}

      {/* Expiry */}
      <div className="field-row">
        <div className="field-group">
          <label>File Expires After</label>
          <select value={expiry} onChange={(e) => setExpiry(Number(e.target.value))} className="select-input">
            {EXPIRY_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>

        <div className="field-group">
          <label>Max Downloads (optional)</label>
          <input
            type="number"
            min="1"
            max="100"
            placeholder="e.g. 1 for burn-after-read"
            value={maxDownloads}
            onChange={(e) => setMaxDownloads(e.target.value)}
            className="text-input"
          />
        </div>
      </div>

      {/* Error */}
      {error && <div className="error-box">⚠️ {error}</div>}

      {/* Progress */}
      {(status === "encrypting" || status === "uploading") && (
        <div className="progress-wrap">
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <p className="progress-label">
            {status === "encrypting" ? "🔐 Encrypting in your browser..." : "📤 Uploading ciphertext..."}
          </p>
        </div>
      )}

      <button
        className="btn-primary"
        onClick={handleUpload}
        disabled={status === "encrypting" || status === "uploading"}
      >
        {status === "encrypting" ? "Encrypting..." :
         status === "uploading"  ? "Uploading..."  :
         "🔐 Encrypt & Upload"}
      </button>

      <div className="security-badges">
        <span>🔒 AES-256-GCM</span>
        <span>🧬 PBKDF2-SHA256</span>
        <span>🚫 Zero-Knowledge</span>
        <span>🌐 Client-Side Only</span>
        <a href="https://github.com/om-moon10"><span>👾 GitHub om-moon10</span> </a>
      </div>
    </div>
  );
}

function formatBytes(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
