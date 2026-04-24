/**
 * DownloadPage.jsx
 *
 * Flow:
 *   1. Read file ID from URL path (/file/:id)
 *   2. Read key from URL hash (#key:base64) if keyless mode
 *   3. Fetch encrypted file from GET /api/file/:id
 *   4. Decrypt in browser using Web Crypto API
 *   5. Trigger browser download of plaintext file
 *
 * SECURITY: The URL hash (#...) is NEVER sent to the server by browsers.
 * The key embedded in the hash stays 100% client-side.
 */

import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import {
  decryptFileWithPassword,
  decryptFile,
  importRawKey,
  downloadFile,
} from "../utils/cryptoUtils";
import "./DownloadPage.css";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:4000";

export default function DownloadPage() {
  const { id } = useParams();

  const [meta,      setMeta]      = useState(null);   // file metadata from server
  const [password,  setPassword]  = useState("");
  const [status,    setStatus]    = useState("idle"); // idle | fetching | decrypting | done | error | expired
  const [error,     setError]     = useState("");
  const [mode,      setMode]      = useState(null);   // "password" | "keyless"
  const [hashKey,   setHashKey]   = useState(null);   // raw key bytes from URL hash

  // â??â?? Parse URL hash on mount â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??

  useEffect(() => {
    const hash = window.location.hash; // e.g. "#key:abc123..."
    if (hash.startsWith("#key:")) {
      const b64 = hash.slice(5); // strip "#key:"
      try {
        const rawKey = base64ToBytes(b64);
        setHashKey(rawKey);
        setMode("keyless");
      } catch {
        setError("Invalid key in URL hash.");
      }
    } else {
      setMode("password");
    }
  }, []);

  // â??â?? Fetch file metadata (no ciphertext yet â?? just info) â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??

  useEffect(() => {
    if (!id) return;

    fetch(`${API_BASE}/api/file/${id}/meta`)
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          setStatus(data.error === "expired" ? "expired" : "error");
          setError(data.error);
        } else {
          setMeta(data);
        }
      })
      .catch(() => {
        setStatus("error");
        setError("Could not reach server.");
      });
  }, [id]);

  // â??â?? Keyless mode: auto-decrypt once we have the hash key and metadata â??â??â??â??â??â??â??â??

  useEffect(() => {
    if (mode === "keyless" && hashKey && meta && status === "idle") {
      handleDecrypt();
    }
  
  }, [mode, hashKey, meta]);

  // â??â?? Main decrypt flow â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??

  const handleDecrypt = async () => {
    setError("");
    setStatus("fetching");

    try {
      // â??â?? Step 1: Fetch encrypted blob from server â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??
      const response = await fetch(`${API_BASE}/api/file/${id}`);

      if (response.status === 404) {
        setStatus("expired");
        return;
      }
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.message || `Server error ${response.status}`);
      }

      // Server returns JSON with base64 ciphertext + iv + salt + filename
      const data = await response.json();

      // Decode server data back to bytes
      const ciphertext = base64ToArrayBuffer(data.ciphertext);
      const iv         = base64ToBytes(data.iv);

      // â??â?? Step 2: Decrypt in browser â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??
      setStatus("decrypting");

      let plaintext;

      if (mode === "keyless") {
        // Re-import the raw key from the URL hash
        const key = await importRawKey(hashKey);
        plaintext = await decryptFile(ciphertext, key, iv);
      } else {
        // Password mode: re-derive key from password + salt
        if (!password || password.length < 1) {
          setStatus("idle");
          setError("Please enter the decryption password.");
          return;
        }
        const salt = base64ToBytes(data.salt);
        plaintext  = await decryptFileWithPassword(ciphertext, password, iv, salt);
      }

      // â”€â”€ Step 3: Trigger browser download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
      downloadFile(plaintext, data.filename, data.mimetype);
      setStatus("done");

    } catch (err) {
      console.error(err);
      setError(err.message || "Decryption failed.");
      setStatus("error");
    }
  };

  // â”€â”€ Render â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  if (status === "expired") {
    return (
      <div className="download-page">
        <div className="status-card expired">
          <div className="status-icon">â°</div>
          <h2>File Expired or Not Found</h2>
          <p>This link has expired, the file was deleted, or the download limit was reached.</p>
        </div>
      </div>
    );
  }

  if (status === "done") {
    return (
      <div className="download-page">
        <div className="status-card success">
          <div className="status-icon">âœ…</div>
          <h2>File Decrypted Successfully</h2>
          <p>Your file was decrypted entirely in your browser. Check your downloads folder.</p>
          <p className="security-note">
            ðŸ” The decryption key <strong>never left your browser</strong>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="download-page">
      <div className="download-card">
        <div className="lock-icon">ðŸ”</div>
        <h2>Encrypted File</h2>

        {meta && (
          <div className="meta-box">
            <div className="meta-row">
              <span className="meta-label">File</span>
              <span className="meta-value">{meta.filename}</span>
            </div>
            <div className="meta-row">
              <span className="meta-label">Size</span>
              <span className="meta-value">{formatBytes(meta.size)}</span>
            </div>
            <div className="meta-row">
              <span className="meta-label">Expires</span>
              <span className="meta-value">{new Date(meta.expiresAt).toLocaleString()}</span>
            </div>
            {meta.downloadsLeft !== null && (
              <div className="meta-row">
                <span className="meta-label">Downloads Left</span>
                <span className="meta-value">{meta.downloadsLeft}</span>
              </div>
            )}
          </div>
        )}

        {mode === "keyless" && (
          <div className="auto-decrypt-notice">
            <div className="spinner" />
            <p>
              {status === "fetching"    ? "Fetching encrypted file..." :
               status === "decrypting"  ? "Decrypting in your browser..." :
               "Preparing to decrypt..."}
            </p>
          </div>
        )}

        {mode === "password" && (
          <>
            <p className="download-sub">
              This file is password protected. Enter the password to decrypt and download it.
              <br />
              <em>Decryption happens entirely in your browser.</em>
            </p>

            <div className="field-group">
              <label>Decryption Password</label>
              <input
                type="password"
                placeholder="Enter password from sender"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleDecrypt()}
                className="text-input"
                disabled={status === "fetching" || status === "decrypting"}
              />
            </div>

            {error && <div className="error-box">â??ï?? {error}</div>}

            {(status === "fetching" || status === "decrypting") && (
              <div className="progress-label">
                <div className="spinner" />
                {status === "fetching" ? "Fetching encrypted file..." : "Decrypting..."}
              </div>
            )}

            <button
              className="btn-primary"
              onClick={handleDecrypt}
              disabled={status === "fetching" || status === "decrypting"}
            >
              {status === "fetching"   ? "Fetching..."   :
               status === "decrypting" ? "Decrypting..." :
               "ð??? Decrypt & Download"}
            </button>
          </>
        )}

        <div className="security-badges">
          <span>ð??? AES-256-GCM</span>
          <span>ð??? Zero-Knowledge</span>
          <span>ð??? Client-Side Decrypt</span>
        </div>
      </div>
    </div>
  );
}

// â??â?? Helpers â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??â??

function base64ToArrayBuffer(b64) {
  const bytes = base64ToBytes(b64);
  return bytes.buffer;
}

function base64ToBytes(b64) {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function formatBytes(bytes) {
  if (!bytes) return "â??";
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 * 1024)  return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
