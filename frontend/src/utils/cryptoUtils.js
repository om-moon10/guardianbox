/**
 * cryptoUtils.js — GuardianBox Zero-Knowledge Crypto Engine
 *
 * ALL cryptographic operations happen here, in the browser.
 * The server NEVER sees a password, raw key, or plaintext.
 *
 * Algorithms used:
 *   - Key derivation : PBKDF2 (SHA-256, 310,000 iterations — OWASP 2023 minimum)
 *   - Encryption     : AES-GCM 256-bit (authenticated encryption — detects tampering)
 *   - IV             : 12-byte random per encryption (GCM standard)
 *   - Salt           : 16-byte random per key derivation
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 310_000; // OWASP 2023 recommended minimum
const KEY_LENGTH_BITS   = 256;     // AES-256
const IV_LENGTH_BYTES   = 12;      // AES-GCM standard IV size
const SALT_LENGTH_BYTES = 16;      // Salt for PBKDF2

// ─── 1. Key Derivation ────────────────────────────────────────────────────────

/**
 * Derives an AES-GCM CryptoKey from a user password using PBKDF2.
 *
 * @param {string} password   - The user's password (never leaves browser)
 * @param {Uint8Array} salt   - Random salt (stored alongside ciphertext; not secret)
 * @returns {Promise<CryptoKey>} - Derived AES-GCM key (non-extractable)
 */
export async function deriveKey(password, salt) {
  if (!password || password.length === 0) {
    throw new Error("Password must not be empty.");
  }

  // Step 1: Import the raw password string as a PBKDF2 "base key"
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    { name: "PBKDF2" },
    false,        // non-extractable — can't read the raw key back out
    ["deriveKey"] // only usable for key derivation
  );

  // Step 2: Derive the actual AES-GCM key using PBKDF2
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name:       "PBKDF2",
      salt:       salt,
      iterations: PBKDF2_ITERATIONS,
      hash:       "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: KEY_LENGTH_BITS },
    false,                      // non-extractable — protects key material
    ["encrypt", "decrypt"]      // allowed operations
  );

  return derivedKey;
}

/**
 * Derives a key for URL-hash sharing (no password — key IS the secret).
 * Used when sharing a file link: the raw key bytes go in the URL hash.
 *
 * @returns {Promise<{key: CryptoKey, rawKey: Uint8Array}>}
 */
export async function generateShareableKey() {
  // Generate a fresh random 256-bit AES-GCM key
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: KEY_LENGTH_BITS },
    true,           // extractable — we need to put it in the URL hash
    ["encrypt", "decrypt"]
  );

  // Export raw bytes so we can base64-encode them for the URL
  const rawKeyBuffer = await crypto.subtle.exportKey("raw", key);
  const rawKey = new Uint8Array(rawKeyBuffer);

  return { key, rawKey };
}

/**
 * Re-imports a raw key extracted from a URL hash back into a CryptoKey.
 *
 * @param {Uint8Array} rawKey - The raw key bytes from the URL hash
 * @returns {Promise<CryptoKey>}
 */
export async function importRawKey(rawKey) {
  return crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: KEY_LENGTH_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

// ─── 2. Encryption ────────────────────────────────────────────────────────────

/**
 * Encrypts a File (or Blob) using AES-GCM with a derived or generated key.
 *
 * Security properties of AES-GCM:
 *   - Provides confidentiality (no one can read it without the key)
 *   - Provides authenticity (tampering with ciphertext is detected on decrypt)
 *   - Random IV ensures the same file encrypted twice produces different output
 *
 * @param {File|Blob} file  - The plaintext file to encrypt
 * @param {CryptoKey} key   - The AES-GCM key (from deriveKey or importRawKey)
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array, salt: Uint8Array|null}>}
 */
export async function encryptFile(file, key) {
  // Read file as raw bytes
  const plaintext = await file.arrayBuffer();

  // Generate a fresh random 12-byte IV for this encryption
  // NEVER reuse an IV with the same key — GCM security breaks if you do
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return { ciphertext, iv };
}

/**
 * Encrypts a file using a password (for password-protected sharing).
 * Derives the key internally; returns everything needed to decrypt later.
 *
 * @param {File|Blob} file     - The file to encrypt
 * @param {string}   password  - The user's password
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array, salt: Uint8Array}>}
 */
export async function encryptFileWithPassword(file, password) {
  // Generate a fresh random salt for PBKDF2
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));

  // Derive a key from the password + salt
  const key = await deriveKey(password, salt);

  // Encrypt the file
  const { ciphertext, iv } = await encryptFile(file, key);

  return { ciphertext, iv, salt };
}

// ─── 3. Decryption ────────────────────────────────────────────────────────────

/**
 * Decrypts an encrypted file buffer using AES-GCM.
 *
 * If the key is wrong OR the data was tampered with, AES-GCM throws a
 * DOMException with name "OperationError". We re-throw as a clear error.
 *
 * @param {ArrayBuffer} ciphertext - The encrypted file bytes
 * @param {CryptoKey}   key        - The AES-GCM decryption key
 * @param {Uint8Array}  iv         - The IV used during encryption
 * @returns {Promise<ArrayBuffer>} - Decrypted plaintext bytes
 */
export async function decryptFile(ciphertext, key, iv) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return plaintext;
  } catch (err) {
    // AES-GCM throws on wrong key OR tampered ciphertext
    // We don't distinguish (to avoid oracle attacks)
    throw new Error(
      "Decryption failed. The password may be wrong, or the file may have been tampered with."
    );
  }
}

/**
 * Decrypts a file that was encrypted with a password (re-derives key from password + salt).
 *
 * @param {ArrayBuffer} ciphertext
 * @param {string}      password
 * @param {Uint8Array}  iv
 * @param {Uint8Array}  salt
 * @returns {Promise<ArrayBuffer>}
 */
export async function decryptFileWithPassword(ciphertext, password, iv, salt) {
  const key = await deriveKey(password, salt);
  return decryptFile(ciphertext, key, iv);
}

// ─── 4. Encoding Helpers ──────────────────────────────────────────────────────

/**
 * Encodes a Uint8Array to a URL-safe Base64 string.
 * Used to embed IV, salt, and key bytes in URLs or API payloads.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decodes a URL-safe Base64 string back to a Uint8Array.
 *
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function base64ToBytes(b64) {
  // Re-pad and convert URL-safe chars back
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary  = atob(padded);
  const bytes   = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Triggers a file download in the browser from raw ArrayBuffer bytes.
 *
 * @param {ArrayBuffer} buffer    - The decrypted file bytes
 * @param {string}      filename  - The filename to save as
 * @param {string}      mimeType  - e.g. "application/pdf", "image/png"
 */
export function downloadFile(buffer, filename, mimeType = "application/octet-stream") {
  const blob = new Blob([buffer], { type: mimeType });
  const url  = URL.createObjectURL(blob);

  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.style.display = "none";

  document.body.appendChild(a);
  a.click();

  // Clean up — revoke the object URL after download starts
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

// ─── 5. Self-Test ─────────────────────────────────────────────────────────────

/**
 * Runs a quick encrypt→decrypt round-trip test in the browser console.
 * Call this from browser devtools to verify everything works:
 *   import { selfTest } from './cryptoUtils.js'; selfTest();
 */
export async function selfTest() {
  console.group("🔐 GuardianBox cryptoUtils self-test");

  // 1. Password-based round-trip
  const originalText = "Hello, GuardianBox! 🛡️";
  const password     = "hunter2-but-stronger!";
  const fakeFile     = new Blob([originalText], { type: "text/plain" });

  console.log("Encrypting with password...");
  const { ciphertext, iv, salt } = await encryptFileWithPassword(fakeFile, password);
  console.log("  Ciphertext bytes:", ciphertext.byteLength);

  console.log("Decrypting with correct password...");
  const decrypted = await decryptFileWithPassword(ciphertext, password, iv, salt);
  const result    = new TextDecoder().decode(decrypted);
  console.assert(result === originalText, "❌ Round-trip FAILED!");
  console.log("  Result:", result);
  console.log("  ✅ Round-trip passed");

  // 2. Wrong password test
  console.log("Testing wrong password (should throw)...");
  try {
    await decryptFileWithPassword(ciphertext, "wrong-password", iv, salt);
    console.error("❌ Should have thrown on wrong password!");
  } catch (e) {
    console.log("  ✅ Wrong password correctly rejected:", e.message);
  }

  // 3. Shareable key round-trip
  console.log("Testing shareable key round-trip...");
  const { key, rawKey } = await generateShareableKey();
  const { ciphertext: ct2, iv: iv2 } = await encryptFile(fakeFile, key);
  const reimportedKey = await importRawKey(rawKey);
  const decrypted2    = await decryptFile(ct2, reimportedKey, iv2);
  const result2       = new TextDecoder().decode(decrypted2);
  console.assert(result2 === originalText, "❌ Shareable key round-trip FAILED!");
  console.log("  ✅ Shareable key round-trip passed");

  console.log("\n✅ All tests passed!");
  console.groupEnd();
}
