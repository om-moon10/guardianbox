# 🛡️ GuardianBox — End-to-End Encrypted File Sharing

A **zero-knowledge** file sharing system. Files are encrypted entirely in the browser
before being uploaded. The server stores only unreadable ciphertext and **never** sees
your files, passwords, or encryption keys.

## 🌐 Live Demo

* 🔗 Frontend: https://guardianbox.vercel.app
* 🔗 Backend API: https://guardianbox-backend-fxtn.onrender.com

---

##  Security Architecture

```
USER BROWSER                         SERVER
─────────────────────────────────    ──────────────────────────
File + Password                      
    │                                
    ▼                                
PBKDF2-SHA256 (310,000 iterations)  
    │                                
    ▼                                
AES-256-GCM Key (never leaves)      
    │                                
    ▼                                
Encrypt file → Ciphertext + IV      
    │                                
    └──────────────────────────────► Store { ciphertext, IV, salt }
                                              (UNREADABLE without key)

Share URL: /file/<id>#key:<base64-key>
                              │
                    Stays in browser hash
                    NEVER sent to server
```

**What the server stores:**
- ✅ Encrypted ciphertext (unreadable)
- ✅ IV (public — needed for AES-GCM, not secret)
- ✅ Salt (public — needed for PBKDF2, not secret)
- ✅ Filename, MIME type, expiry, download count

**What the server NEVER sees:**
- ❌ Passwords
- ❌ Encryption keys
- ❌ Plaintext file content

---

##  Project Structure

```
guardianbox/
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── utils/
│   │   │   └── cryptoUtils.js        ←  ALL crypto happens here
│   │   ├── components/
│   │   │   ├── UploadPage.jsx        ← Encrypt + upload UI
│   │   │   ├── UploadPage.css
│   │   │   ├── DownloadPage.jsx      ← Fetch + decrypt UI
│   │   │   └── DownloadPage.css
│   │   ├── App.jsx                   ← Router + layout
│   │   ├── App.css                   ← Global styles
│   │   └── index.js
│   └── package.json
│
└── backend/
    ├── routes/
    │   └── fileRoutes.js             ← API route definitions
    ├── controllers/
    │   └── fileController.js         ← Request/response handling
    ├── services/
    │   └── storageService.js         ← File I/O + metadata DB
    ├── uploads/                      ← Encrypted .enc files + db.json
    ├── server.js                     ← Express app + cron job
    └── package.json
```

---

## Quick Start

### 1. Backend

```bash
cd backend
npm install
npm run dev          # Uses nodemon for hot reload
# Server starts on http://localhost:4000
```

### 2. Frontend

```bash
cd frontend
npm install
npm start            # React dev server on http://localhost:3000
```

### 3. Open your browser

Go to `http://localhost:3000`

---

##  Two Sharing Modes

### Mode 1: Link-Only (Random Key)
The app generates a random AES-256 key, encrypts your file, then embeds the key
in the URL hash:

```
http://localhost:3000/file/abc123#key:xK8mP2...
                                  ──────────────
                                  Browser hash — NEVER sent to server
```

**Share this link and anyone with it can decrypt the file.**

### Mode 2: Password Protected
The app derives a key from your password using PBKDF2. The key never leaves your browser.
The URL has no key in it:

```
http://localhost:3000/file/abc123
```

**You must share the password via a separate secure channel (Signal, in person, etc.)**

---

##  API Reference

### POST /api/upload
```
Content-Type: multipart/form-data

file        (binary)  — encrypted ciphertext
iv          (string)  — base64 IV
filename    (string)  — original filename
mimetype    (string)  — original MIME type
mode        (string)  — "password" | "keyless"
salt        (string)  — base64 salt (password mode only)
expiry      (number)  — seconds until expiry (60–2592000)
maxDownloads (number) — optional download limit
```

Response: `{ id: "uuid-v4" }`

### GET /api/file/:id/meta
Returns public metadata (no ciphertext):
```json
{
  "filename":      "report.pdf",
  "mimetype":      "application/pdf",
  "size":          102400,
  "mode":          "password",
  "expiresAt":     "2024-12-31T23:59:59.000Z",
  "downloadsLeft": 3
}
```

### GET /api/file/:id
Returns encrypted payload:
```json
{
  "ciphertext": "base64url-encoded...",
  "iv":         "base64url-encoded...",
  "salt":       "base64url-encoded...",
  "filename":   "report.pdf",
  "mimetype":   "application/pdf"
}
```

### DELETE /api/file/:id
Manually delete a file.

---

## ⏳ Expiration System

Files are automatically deleted by a **cron job** that runs every 5 minutes.

A file is deleted when:
1. Its expiry time has passed
2. Its `maxDownloads` limit has been reached (burn-after-read)

Files are also checked on every download request.

---

## 🧪 Testing cryptoUtils.js

Open browser devtools console and run:

```javascript
import { selfTest } from './utils/cryptoUtils.js';
await selfTest();
```

This runs:
1. ✅ Password-based encrypt → decrypt round-trip
2. ✅ Wrong password correctly rejected
3. ✅ Shareable key round-trip

---

##  Production Upgrade Path

| Feature | Development | Production |
|---------|-------------|------------|
| Metadata DB | JSON file | MongoDB / PostgreSQL |
| File storage | Local disk | AWS S3 / GCS |
| CORS | localhost:3000 | Your domain |
| Rate limiting | None | express-rate-limit |
| Authentication | None | JWT / OAuth for delete |
| HTTPS | HTTP | TLS (required) |

### Swap in MongoDB
Replace `storageService.js` DB helpers with Mongoose:
```js
const File = mongoose.model('File', fileSchema);
await File.create({ id, filename, iv, ... });
```

### Swap in AWS S3
Replace `fs.writeFileSync` with:
```js
await s3.send(new PutObjectCommand({ Bucket, Key: id, Body: ciphertext }));
```

---

##  Cryptographic Details

| Property | Value |
|----------|-------|
| Encryption | AES-256-GCM |
| Key size | 256 bits |
| IV size | 96 bits (12 bytes) |
| IV generation | `crypto.getRandomValues` (CSPRNG) |
| Key derivation | PBKDF2-SHA256 |
| PBKDF2 iterations | 310,000 (OWASP 2023 minimum) |
| Salt size | 128 bits (16 bytes) |
| Authentication | AES-GCM built-in (detects tampering) |
| Key in URL | Fragment only (`#key:...`) — never in path/query |

---

##  Security Notes

1. **HTTPS is mandatory in production.** Without TLS, URL hashes can be exposed to
   network attackers in some scenarios.

2. **The URL hash (#) is never sent to the server by browsers.** This is a fundamental
   browser security property — it's what makes the keyless sharing mode safe.

3. **Password mode requires out-of-band key exchange.** The link alone is useless
   without the password. Tell users to share it via Signal or in person.

4. **AES-GCM detects tampering.** If the ciphertext is modified on the server, decryption
   will throw an error — it cannot be silently corrupted.

5. **IV uniqueness.** A new random IV is generated for each upload, ensuring the same
   file encrypted twice produces different ciphertext.

---

---



---

## 📸 Screenshots

### Upload Page

![Upload](./screenshots/upload.png)

### Shareable Link

![Link](./screenshots/share-link.png)

### Download Page

![Download](./screenshots/download.png)

### Successful Decryption

![Success](./screenshots/success.png)

### Encrypted File in S3 (Proof of Security)

![S3](./screenshots/s3-encrypted.png)

---


---

##  Security Audit

This section analyzes potential attack vectors and how GuardianBox mitigates them.

### 1.  Key Loss (Critical Trade-off)

If a user loses the sharing link (in keyless mode) or forgets the password (in password mode), the file is permanently unrecoverable.

* This is an intentional design choice in zero-knowledge systems.
* The server cannot assist in recovery because it never stores the key.

**Impact:** Data loss
**Mitigation:** Users must securely store or share keys

---

### 2.  Server or S3 Compromise

If an attacker gains access to the backend or AWS S3 storage:

* They only obtain encrypted `.enc` files
* Without the encryption key, data remains unreadable

**Impact:** No data exposure
**Mitigation:** Strong client-side encryption (AES-256-GCM)

---

### 3.  Link Interception

If a sharing link is intercepted:

* **Keyless mode:** attacker gains access (link contains key)
* **Password mode:** attacker cannot decrypt without password

**Impact:** Depends on mode
**Mitigation:**

* Use password mode for sensitive data
* Share links over secure channels

---

### 4.  Brute-Force Attacks (Password Mode)

An attacker may attempt to guess the password:

* PBKDF2 (310,000 iterations) significantly slows brute-force attempts
* Each file uses a unique salt

**Impact:** Computationally expensive attack
**Mitigation:** Strong password selection recommended

---

### 5.  Data Integrity (Tampering)

If ciphertext is modified in storage or transit:

* AES-GCM authentication fails during decryption
* The file cannot be silently altered

**Impact:** Decryption fails safely
**Mitigation:** Built-in authenticated encryption

---

### 6.  Expired File Access

Expired or download-limited files:

* Are deleted from storage via cron job
* Are also blocked at API level

**Impact:** No access after expiry
**Mitigation:** Dual-layer enforcement (cron + runtime checks)

---

### 7.  Man-in-the-Middle (MITM) Attacks

Without HTTPS:

* Data and URL fragments could be exposed

With HTTPS:

* Data in transit is encrypted
* Combined with client-side encryption, adds defense-in-depth

**Impact:** High if HTTP, low if HTTPS
**Mitigation:** HTTPS is mandatory in production

---

### 8.  Client-Side Threats (XSS)

If the frontend is compromised:

* Malicious scripts could access keys or plaintext

**Impact:** High
**Mitigation:**

* Avoid unsafe HTML rendering
* Use secure React practices
* Implement Content Security Policy (future improvement)

---

### 9.  Replay or Link Reuse

Links can be reused until:

* Expiry time is reached
* Download limit is exceeded

**Impact:** Limited reuse
**Mitigation:** Burn-after-read and expiration controls

---

##  Security Summary

GuardianBox follows a **zero-knowledge architecture**, ensuring:

* Encryption keys never leave the client
* Servers store only encrypted data
* Data remains secure even in case of backend compromise

The main trade-off is **usability vs security**, where users are responsible for managing their keys.

---


Built with ❤️ and Web Crypto API. Zero-knowledge by design.
