/**
 * FORGE Keys — Ed25519 Digital Signatures
 *
 * This module provides cryptographic identity for TrustAtoms.
 * Each atom is signed with the creator's private key, proving
 * that only the key holder could have created it.
 *
 * Key storage: ~/.forge/keys/
 *   - private.key  (NEVER share — this proves your identity)
 *   - public.key   (Share freely — others use this to verify your atoms)
 *
 * Algorithm: Ed25519 (same as SSH, Signal, Bitcoin Taproot)
 *   - Fast signing and verification
 *   - Small keys (32 bytes) and signatures (64 bytes)
 *   - Deterministic (same input = same signature)
 *   - Resistant to side-channel attacks
 */

import { generateKeyPairSync, sign, verify, createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";

const KEYS_DIR = join(process.env.HOME || "/tmp", ".forge", "keys");
const PRIVATE_KEY_PATH = join(KEYS_DIR, "private.key");
const PUBLIC_KEY_PATH = join(KEYS_DIR, "public.key");
const IDENTITY_PATH = join(KEYS_DIR, "identity.json");

/**
 * Generate a new Ed25519 key pair.
 * Returns { publicKey, privateKey } in PEM format.
 */
export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

/**
 * Get the fingerprint of a public key (short identifier).
 * Format: forge:ed25519:<first 16 chars of sha256>
 */
export function getFingerprint(publicKeyPem) {
  const hash = createHash("sha256").update(publicKeyPem).digest("hex");
  return `forge:ed25519:${hash.slice(0, 16)}`;
}

/**
 * Sign data with a private key.
 * Returns base64-encoded signature.
 */
export function signData(data, privateKeyPem) {
  const signature = sign(null, Buffer.from(data), privateKeyPem);
  return signature.toString("base64");
}

/**
 * Verify a signature.
 * Returns true if valid, false otherwise.
 */
export function verifySignature(data, signatureBase64, publicKeyPem) {
  try {
    const signature = Buffer.from(signatureBase64, "base64");
    return verify(null, Buffer.from(data), publicKeyPem, signature);
  } catch {
    return false;
  }
}

/**
 * Initialize keys — generate new key pair and save to disk.
 * Will NOT overwrite existing keys (safety measure).
 */
export function initializeKeys(identity = {}) {
  // Ensure keys directory exists
  if (!existsSync(KEYS_DIR)) {
    mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  }

  // Check if keys already exist
  if (existsSync(PRIVATE_KEY_PATH)) {
    throw new Error(
      "Keys already exist. To regenerate, first run: rm -rf ~/.forge/keys\n" +
      "WARNING: This will invalidate all your previous signed atoms!"
    );
  }

  // Generate new key pair
  const { publicKey, privateKey } = generateKeyPair();
  const fingerprint = getFingerprint(publicKey);

  // Save private key (restrictive permissions)
  writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  try {
    chmodSync(PRIVATE_KEY_PATH, 0o600); // Extra safety
  } catch {}

  // Save public key (can be shared)
  writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

  // Save identity metadata
  const identityData = {
    fingerprint,
    created_at: Date.now(),
    algorithm: "ed25519",
    ...identity,
  };
  writeFileSync(IDENTITY_PATH, JSON.stringify(identityData, null, 2));

  return {
    fingerprint,
    publicKey,
    privateKey,
    identity: identityData,
  };
}

/**
 * Load existing keys from disk.
 * Returns null if keys don't exist.
 */
export function loadKeys() {
  if (!existsSync(PRIVATE_KEY_PATH) || !existsSync(PUBLIC_KEY_PATH)) {
    return null;
  }

  try {
    const privateKey = readFileSync(PRIVATE_KEY_PATH, "utf8");
    const publicKey = readFileSync(PUBLIC_KEY_PATH, "utf8");
    const fingerprint = getFingerprint(publicKey);

    let identity = { fingerprint };
    if (existsSync(IDENTITY_PATH)) {
      identity = JSON.parse(readFileSync(IDENTITY_PATH, "utf8"));
    }

    return { privateKey, publicKey, fingerprint, identity };
  } catch {
    return null;
  }
}

/**
 * Check if keys are initialized.
 */
export function hasKeys() {
  return existsSync(PRIVATE_KEY_PATH) && existsSync(PUBLIC_KEY_PATH);
}

/**
 * Get public key only (for sharing/verification).
 */
export function getPublicKey() {
  if (!existsSync(PUBLIC_KEY_PATH)) {
    return null;
  }
  return readFileSync(PUBLIC_KEY_PATH, "utf8");
}

/**
 * Export public key and identity for sharing.
 */
export function exportIdentity() {
  const publicKey = getPublicKey();
  if (!publicKey) {
    return null;
  }

  const fingerprint = getFingerprint(publicKey);
  let identity = { fingerprint, algorithm: "ed25519" };

  if (existsSync(IDENTITY_PATH)) {
    identity = JSON.parse(readFileSync(IDENTITY_PATH, "utf8"));
  }

  return {
    public_key: publicKey,
    fingerprint,
    identity,
    exported_at: Date.now(),
  };
}

/**
 * Import a public key for verification.
 * Saves to ~/.forge/keys/trusted/<fingerprint>.key
 */
export function importTrustedKey(publicKeyPem, alias = null) {
  const fingerprint = getFingerprint(publicKeyPem);
  const trustedDir = join(KEYS_DIR, "trusted");

  if (!existsSync(trustedDir)) {
    mkdirSync(trustedDir, { recursive: true });
  }

  const keyPath = join(trustedDir, `${fingerprint}.key`);
  const metaPath = join(trustedDir, `${fingerprint}.json`);

  writeFileSync(keyPath, publicKeyPem);
  writeFileSync(metaPath, JSON.stringify({
    fingerprint,
    alias,
    imported_at: Date.now(),
  }, null, 2));

  return { fingerprint, alias };
}

/**
 * Get a trusted public key by fingerprint.
 */
export function getTrustedKey(fingerprint) {
  const keyPath = join(KEYS_DIR, "trusted", `${fingerprint}.key`);
  if (!existsSync(keyPath)) {
    return null;
  }
  return readFileSync(keyPath, "utf8");
}

/**
 * List all trusted keys.
 */
export function listTrustedKeys() {
  const trustedDir = join(KEYS_DIR, "trusted");
  if (!existsSync(trustedDir)) {
    return [];
  }

  const { readdirSync } = require("node:fs");
  const files = readdirSync(trustedDir).filter(f => f.endsWith(".json"));

  return files.map(f => {
    const meta = JSON.parse(readFileSync(join(trustedDir, f), "utf8"));
    return meta;
  });
}
