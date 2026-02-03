/**
 * TrustPixel — The smallest indivisible unit of trust.
 *
 * First principle:  Trust = Certainty × Existence
 *
 *   Certainty  → SHA-256 hash  (mathematical: deterministic, irreversible)
 *   Existence  → Witness        (physical: an independent copy survives deletion)
 *
 * A hash without a witness can be silently deleted.
 * A witness without a hash can be forged.
 * Together they produce an undeniable fact.
 */

import { createHash } from "node:crypto";

/* ================================================================
   CERTAINTY  —  the mathematical half
   ================================================================ */

export function hash(input) {
  if (input === undefined || input === null) input = "";
  if (typeof input === "object")
    input = JSON.stringify(input, Object.keys(input).sort());
  return createHash("sha256").update(String(input)).digest("hex");
}

export function hashMany(...parts) {
  return hash(
    parts
      .map((p) =>
        typeof p === "object" ? JSON.stringify(p, Object.keys(p).sort()) : String(p)
      )
      .join("|")
  );
}

/* ================================================================
   EXISTENCE  —  the physical / social half
   ================================================================ */

export function selfWitness(loc = "local") {
  return { type: "self", location: loc, at: Date.now() };
}

export function bilateralWitness(counterparty, loc = "remote") {
  return { type: "bilateral", counterparty, location: loc, at: Date.now() };
}

export function publicWitness(service, receipt = null) {
  return { type: "public", service, receipt, at: Date.now() };
}

export function anchoredWitness(chain, txid) {
  return { type: "anchored", chain, txid, at: Date.now() };
}

/* ================================================================
   TRUST PIXEL  —  Certainty × Existence
   ================================================================ */

export function createPixel(content, witnesses) {
  const h = hash(content);
  if (!witnesses || witnesses.length === 0) witnesses = [selfWitness()];
  return { hash: h, witnesses, created_at: Date.now() };
}

export function verifyPixel(pixel, content) {
  const certain = hash(content) === pixel.hash;
  const exists = pixel.witnesses && pixel.witnesses.length > 0;
  return { valid: certain && exists, certain, exists, strongest: bestWitness(pixel) };
}

export function bestWitness(pixel) {
  const rank = { anchored: 4, public: 3, bilateral: 2, self: 1 };
  let best = { level: 0, label: "none" };
  for (const w of pixel.witnesses || []) {
    const r = rank[w.type] || 0;
    if (r > best.level) best = { level: r, label: w.type };
  }
  return best;
}
