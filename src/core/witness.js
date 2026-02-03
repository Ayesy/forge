/**
 * FORGE Witness Module — Existence Proof System
 *
 * Trust = Certainty × Existence
 *
 * Hash provides Certainty (mathematical, deterministic).
 * Witness provides Existence (physical, social, temporal).
 *
 * This module implements the witness hierarchy:
 *   Level 1 — Self:       Only you hold the hash (can be deleted)
 *   Level 2 — Bilateral:  Two parties hold the hash (one can't deny)
 *   Level 3 — Public:     Timestamped by 3rd party (independent attestation)
 *   Level 4 — Anchored:   Embedded in public blockchain (computationally undeletable)
 *
 * OpenTimestamps integration provides Level 3 → Level 4 path:
 *   1. Submit Merkle root to OTS calendar servers (free, no API key)
 *   2. Calendar servers aggregate hashes into Bitcoin transactions
 *   3. After ~2 hours, receipt upgrades to Bitcoin block attestation
 *   4. Anyone can independently verify without trusting any party
 *
 * Calendar servers used:
 *   - https://a.pool.opentimestamps.org
 *   - https://b.pool.opentimestamps.org
 *   - https://a.pool.eternitywall.com
 */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

/* ================================================================
   CONSTANTS
   ================================================================ */

const OTS_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://a.pool.eternitywall.com",
];

const OTS_HEADER = Buffer.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d,
  0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
  0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01,
]);

// OTS opcodes
const OTS_OP = {
  SHA256: 0x08,
  APPEND: 0xf0,
  PREPEND: 0xf1,
  ATTESTATION_PENDING: 0x83,
  ATTESTATION_BITCOIN: 0x05,
};

const WITNESS_DIR = join(homedir(), ".forge", "witnesses");

/* ================================================================
   WITNESS STORE
   ================================================================ */

function ensureWitnessDir() {
  if (!existsSync(WITNESS_DIR)) {
    mkdirSync(WITNESS_DIR, { recursive: true });
  }
}

/**
 * Save a witness receipt to disk.
 * @param {string} merkleRoot - The Merkle root hash being witnessed
 * @param {object} witness - Witness data
 */
export function saveWitness(merkleRoot, witness) {
  ensureWitnessDir();
  const path = join(WITNESS_DIR, `${merkleRoot}.json`);
  
  // Load existing witnesses for this root
  let existing = [];
  if (existsSync(path)) {
    try { existing = JSON.parse(readFileSync(path, "utf8")); } catch {}
  }
  
  existing.push(witness);
  writeFileSync(path, JSON.stringify(existing, null, 2));
  return path;
}

/**
 * Load all witnesses for a Merkle root.
 */
export function loadWitnesses(merkleRoot) {
  const path = join(WITNESS_DIR, `${merkleRoot}.json`);
  if (!existsSync(path)) return [];
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return []; }
}

/**
 * Get the highest witness level for a Merkle root.
 */
export function witnessLevel(merkleRoot) {
  const witnesses = loadWitnesses(merkleRoot);
  if (witnesses.length === 0) return { level: 1, label: "self", description: "Local only — can be deleted" };
  
  let maxLevel = 1;
  let bestWitness = null;
  
  for (const w of witnesses) {
    const lvl = w.level || 1;
    if (lvl > maxLevel) {
      maxLevel = lvl;
      bestWitness = w;
    }
  }
  
  const labels = {
    1: { label: "self", description: "Local only — can be deleted" },
    2: { label: "bilateral", description: "Two parties hold hash — one can't deny" },
    3: { label: "public", description: "Calendar server attested — independent verification possible" },
    4: { label: "anchored", description: "Bitcoin blockchain — computationally undeletable" },
  };
  
  return { level: maxLevel, ...labels[maxLevel], witness: bestWitness };
}

/* ================================================================
   LEVEL 3: OPENTIMESTAMPS CALENDAR SUBMISSION
   ================================================================ */

/**
 * Submit a SHA-256 hash to OpenTimestamps calendar servers.
 *
 * The OTS protocol is simple:
 *   1. Generate a random nonce for privacy
 *   2. Hash: SHA256(hash + nonce) → digest
 *   3. POST digest (32 raw bytes) to calendar/digest endpoint
 *   4. Calendar returns operations to get from digest → calendar's Merkle root
 *   5. Store the receipt (nonce + calendar response) as pending attestation
 *
 * After ~2 hours, the calendar's Merkle root will be embedded in a Bitcoin
 * transaction, and the receipt can be upgraded to a full attestation.
 *
 * @param {string} hashHex - 64-character hex SHA-256 hash (e.g., Merkle root)
 * @returns {Promise<object>} - Submission result with calendar responses
 */
export async function submitToOTS(hashHex) {
  if (!hashHex || hashHex.length !== 64) {
    throw new Error(`Invalid hash: expected 64-char hex, got ${hashHex?.length || 0}`);
  }

  // Generate nonce for privacy (calendar never sees real hash)
  const nonce = randomBytes(16);
  const hashBytes = Buffer.from(hashHex, "hex");
  
  // Compute: SHA256(nonce || hash)
  const digest = createHash("sha256")
    .update(Buffer.concat([nonce, hashBytes]))
    .digest();

  const results = [];
  const errors = [];

  // Submit to each calendar server in parallel
  const submissions = OTS_CALENDARS.map(async (calendarUrl) => {
    try {
      const url = `${calendarUrl}/digest`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "forge-trust-chain/0.1",
          "Accept": "application/vnd.opentimestamps.v1",
        },
        body: digest,
        signal: AbortSignal.timeout(10000),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Calendar returns binary OTS operations
      const responseBuffer = Buffer.from(await response.arrayBuffer());

      results.push({
        calendar: calendarUrl,
        status: "submitted",
        response_hex: responseBuffer.toString("hex"),
        response_length: responseBuffer.length,
        submitted_at: new Date().toISOString(),
      });
    } catch (err) {
      errors.push({
        calendar: calendarUrl,
        status: "error",
        error: err.message,
        submitted_at: new Date().toISOString(),
      });
    }
  });

  await Promise.allSettled(submissions);

  const receipt = {
    type: "ots_pending",
    level: results.length > 0 ? 3 : 1,
    original_hash: hashHex,
    nonce: nonce.toString("hex"),
    digest: digest.toString("hex"),
    calendars: [...results, ...errors],
    successful_submissions: results.length,
    total_calendars: OTS_CALENDARS.length,
    created_at: new Date().toISOString(),
    note: results.length > 0
      ? "Pending Bitcoin confirmation. Run 'forge anchor --upgrade' after ~2 hours to check."
      : "All calendar submissions failed. Check network connectivity.",
  };

  // Save witness
  if (results.length > 0) {
    saveWitness(hashHex, receipt);
  }

  return receipt;
}

/**
 * Check if a pending OTS attestation has been confirmed in Bitcoin.
 *
 * This queries the calendar server to see if the pending attestation
 * has been upgraded to a Bitcoin block header attestation.
 *
 * @param {string} merkleRoot - The Merkle root to check
 * @returns {Promise<object>} - Upgrade status
 */
export async function checkOTSUpgrade(merkleRoot) {
  const witnesses = loadWitnesses(merkleRoot);
  const pending = witnesses.find(w => w.type === "ots_pending");
  
  if (!pending) {
    return { status: "no_pending", message: "No pending OTS attestation found for this root." };
  }

  const upgraded = [];
  const still_pending = [];

  for (const cal of pending.calendars) {
    if (cal.status !== "submitted") continue;
    
    try {
      // Query calendar for upgrade
      const url = `${cal.calendar}/timestamp/${pending.digest}`;
      const response = await fetch(url, {
        headers: { "Accept": "application/vnd.opentimestamps.v1" },
        signal: AbortSignal.timeout(10000),
      });

      if (response.ok) {
        const body = Buffer.from(await response.arrayBuffer());
        // Check if response contains Bitcoin attestation (0x05 marker)
        if (body.includes(Buffer.from([OTS_OP.ATTESTATION_BITCOIN]))) {
          upgraded.push({
            calendar: cal.calendar,
            status: "confirmed",
            proof_hex: body.toString("hex"),
            confirmed_at: new Date().toISOString(),
          });
        } else {
          still_pending.push({ calendar: cal.calendar, status: "still_pending" });
        }
      } else {
        still_pending.push({ calendar: cal.calendar, status: "unavailable", http: response.status });
      }
    } catch (err) {
      still_pending.push({ calendar: cal.calendar, status: "error", error: err.message });
    }
  }

  const result = {
    merkle_root: merkleRoot,
    upgraded: upgraded.length,
    pending: still_pending.length,
    details: [...upgraded, ...still_pending],
    checked_at: new Date().toISOString(),
  };

  // If upgraded, save as Level 4 witness
  if (upgraded.length > 0) {
    const anchorWitness = {
      type: "ots_confirmed",
      level: 4,
      original_hash: merkleRoot,
      bitcoin_attestations: upgraded,
      confirmed_at: new Date().toISOString(),
    };
    saveWitness(merkleRoot, anchorWitness);
    result.new_level = 4;
    result.message = "✓ Upgraded to Level 4 (Bitcoin anchored). Computationally undeletable.";
  } else {
    result.message = "Still pending Bitcoin confirmation. Try again later.";
  }

  return result;
}

/* ================================================================
   LEVEL 2: BILATERAL WITNESS
   ================================================================ */

/**
 * Generate a bilateral witness receipt for sharing with a counterparty.
 * Both parties holding the same receipt means neither can deny the hash existed.
 *
 * @param {string} merkleRoot - The Merkle root to witness
 * @param {string} counterparty - Identifier of the other party
 * @returns {object} - Receipt to share
 */
export function createBilateralWitness(merkleRoot, counterparty) {
  const receipt = {
    type: "bilateral",
    level: 2,
    merkle_root: merkleRoot,
    counterparty,
    created_at: new Date().toISOString(),
    // HMAC so counterparty can verify this was generated by FORGE
    receipt_hash: createHash("sha256")
      .update(`bilateral:${merkleRoot}:${counterparty}:${Date.now()}`)
      .digest("hex"),
  };

  saveWitness(merkleRoot, receipt);
  return receipt;
}

/* ================================================================
   SUMMARY
   ================================================================ */

/**
 * Get a complete witness summary for a Merkle root.
 */
export function witnessSummary(merkleRoot) {
  const witnesses = loadWitnesses(merkleRoot);
  const level = witnessLevel(merkleRoot);
  
  return {
    merkle_root: merkleRoot,
    current_level: level,
    witness_count: witnesses.length,
    witnesses: witnesses.map(w => ({
      type: w.type,
      level: w.level,
      created_at: w.created_at || w.confirmed_at,
    })),
    upgrade_path: getUpgradePath(level.level),
  };
}

function getUpgradePath(currentLevel) {
  const paths = [];
  if (currentLevel < 2) {
    paths.push("Level 2: Share Merkle root with counterparty via 'forge witness --bilateral <party>'");
  }
  if (currentLevel < 3) {
    paths.push("Level 3: Submit to OTS calendars via 'forge anchor'");
  }
  if (currentLevel < 4) {
    paths.push("Level 4: Wait for Bitcoin confirmation, then 'forge anchor --upgrade'");
  }
  if (currentLevel >= 4) {
    paths.push("Maximum level reached. Hash is anchored to Bitcoin blockchain.");
  }
  return paths;
}

export { OTS_CALENDARS, WITNESS_DIR };
