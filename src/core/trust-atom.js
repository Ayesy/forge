/**
 * TrustAtom — One verifiable state transition.
 *
 * A Turing machine's minimum operation: State A → Action → State B
 * A TrustAtom records exactly this, with identity and chain integrity.
 *
 * Structure:
 *   who     hash(identity)       — who did it
 *   from    hash(state_before)   — starting state
 *   action  hash(operation)      — what was done
 *   to      hash(state_after)    — ending state
 *   when    timestamp            — when
 *   prev    previous atom hash   — chain link (array for DAG)
 *   proof   hash(all above)      — the atom's fingerprint
 *
 * Every field is a TrustPixel's hash. The atom itself is a composition.
 */

import { hash, hashMany, selfWitness } from "./trust-pixel.js";
import { signData, verifySignature, loadKeys, getFingerprint } from "./keys.js";

/* ================================================================
   CREATE
   ================================================================ */

/**
 * @param {object} params
 * @param {string} params.who       - Identity string (will be hashed)
 * @param {any}    params.from      - Pre-state (will be hashed)
 * @param {string} params.action    - Operation description (will be hashed)
 * @param {any}    params.to        - Post-state (will be hashed)
 * @param {string|string[]} [params.prev] - Previous atom proof(s), or "genesis"
 * @returns {object} TrustAtom
 */
export function createAtom({ who, from, action, to, prev = "genesis" }) {
  const when = Date.now();

  // Normalise prev to array (DAG-ready)
  const prevArr = Array.isArray(prev) ? prev : [prev];

  const atom = {
    who: hash(who),
    from: hash(from),
    action: hash(action),
    to: hash(to),
    when,
    prev: prevArr,
  };

  // Proof = hash of all fields concatenated in deterministic order
  atom.proof = hashMany(
    atom.who,
    atom.from,
    atom.action,
    atom.to,
    atom.when,
    ...atom.prev
  );

  // Keep raw values for debugging / local use (not transmitted)
  atom._raw = { who, action, when };

  return atom;
}

/**
 * Create a SIGNED TrustAtom — cryptographically proves creator identity.
 *
 * @param {object} params - Same as createAtom
 * @param {string} [params.privateKey] - Private key PEM (uses stored key if omitted)
 * @param {string} [params.publicKey] - Public key PEM (uses stored key if omitted)
 * @returns {object} Signed TrustAtom with signature and signer fields
 */
export function createSignedAtom({ who, from, action, to, prev = "genesis", privateKey, publicKey }) {
  // Load keys if not provided
  if (!privateKey || !publicKey) {
    const keys = loadKeys();
    if (!keys) {
      throw new Error(
        "No signing keys found. Run 'forge init' first to create your identity."
      );
    }
    privateKey = privateKey || keys.privateKey;
    publicKey = publicKey || keys.publicKey;
  }

  // Create base atom
  const atom = createAtom({ who, from, action, to, prev });

  // Add signature
  atom.signature = signData(atom.proof, privateKey);
  atom.signer = getFingerprint(publicKey);

  return atom;
}

/**
 * Verify a signed atom's signature.
 *
 * @param {object} atom - The atom to verify
 * @param {string} [publicKey] - Public key PEM (looks up by fingerprint if omitted)
 * @returns {object} { valid, reason }
 */
export function verifyAtomSignature(atom, publicKey = null) {
  // Check if atom has signature
  if (!atom.signature || !atom.signer) {
    return { valid: false, reason: "unsigned" };
  }

  // Get public key
  if (!publicKey) {
    // Try to load our own key first
    const keys = loadKeys();
    if (keys && keys.fingerprint === atom.signer) {
      publicKey = keys.publicKey;
    } else {
      // Try trusted keys
      const { getTrustedKey } = require("./keys.js");
      publicKey = getTrustedKey(atom.signer);
    }
  }

  if (!publicKey) {
    return { valid: false, reason: "unknown_signer", signer: atom.signer };
  }

  // Verify fingerprint matches
  const expectedFingerprint = getFingerprint(publicKey);
  if (expectedFingerprint !== atom.signer) {
    return { valid: false, reason: "fingerprint_mismatch" };
  }

  // Verify signature
  const isValid = verifySignature(atom.proof, atom.signature, publicKey);
  if (!isValid) {
    return { valid: false, reason: "invalid_signature" };
  }

  return { valid: true, signer: atom.signer };
}

/* ================================================================
   VERIFY
   ================================================================ */

/** Verify a single atom's self-consistency — O(1). */
export function verifyAtom(atom) {
  const expected = hashMany(
    atom.who,
    atom.from,
    atom.action,
    atom.to,
    atom.when,
    ...atom.prev
  );
  return expected === atom.proof;
}

/** Verify a chain of atoms — O(n). */
export function verifyChain(atoms, { requireSignature = false } = {}) {
  if (atoms.length === 0) return { valid: true, broken_at: -1, signatures: [] };

  const signatureResults = [];

  for (let i = 0; i < atoms.length; i++) {
    // 1. Self-consistency (hash proof)
    if (!verifyAtom(atoms[i])) {
      return { valid: false, broken_at: i, reason: "proof_mismatch", signatures: signatureResults };
    }

    // 2. Chain link (skip genesis)
    if (i > 0) {
      if (!atoms[i].prev.includes(atoms[i - 1].proof)) {
        return { valid: false, broken_at: i, reason: "chain_break", signatures: signatureResults };
      }
    }

    // 3. Temporal order
    if (i > 0 && atoms[i].when < atoms[i - 1].when) {
      return { valid: false, broken_at: i, reason: "time_reversal", signatures: signatureResults };
    }

    // 4. Signature verification (if present or required)
    if (atoms[i].signature) {
      const sigResult = verifyAtomSignature(atoms[i]);
      signatureResults.push({ index: i, ...sigResult });

      if (!sigResult.valid && requireSignature) {
        return { valid: false, broken_at: i, reason: `signature_${sigResult.reason}`, signatures: signatureResults };
      }
    } else if (requireSignature) {
      signatureResults.push({ index: i, valid: false, reason: "unsigned" });
      return { valid: false, broken_at: i, reason: "unsigned", signatures: signatureResults };
    }
  }

  return { valid: true, broken_at: -1, signatures: signatureResults };
}

/* ================================================================
   UTILITY
   ================================================================ */

/** Strip raw data for transmission (only hashes travel). */
export function stripAtom(atom) {
  const { _raw, ...clean } = atom;
  return clean;
}

/** Pretty-print an atom for CLI. */
export function formatAtom(atom, index = 0) {
  const who = atom._raw?.who || atom.who.slice(0, 12) + "…";
  const act = atom._raw?.action || atom.action.slice(0, 12) + "…";
  const time = new Date(atom.when).toISOString();
  const proof = atom.proof.slice(0, 16) + "…";
  return `#${index} [${time}] ${who} → ${act}  proof:${proof}`;
}
