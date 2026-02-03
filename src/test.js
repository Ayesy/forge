/**
 * FORGE Test Suite — verify all core components.
 */

import { hash, hashMany, createPixel, verifyPixel, bestWitness, selfWitness, bilateralWitness } from "./core/trust-pixel.js";
import { createAtom, verifyAtom, verifyChain } from "./core/trust-atom.js";
import { buildMerkleTree, getMerkleProof, verifyMerkleProof } from "./core/merkle.js";
import { TrustChain, findDivergence } from "./core/chain.js";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, msg = "assertion failed") {
  if (!condition) throw new Error(msg);
}

console.log("\n  FORGE Test Suite\n");

// ---- TrustPixel ----
console.log("  ── TrustPixel ──");

test("hash is deterministic", () => {
  assert(hash("hello") === hash("hello"));
});

test("hash is collision-resistant", () => {
  assert(hash("hello") !== hash("hello1"));
});

test("hash handles objects", () => {
  assert(hash({ a: 1, b: 2 }) === hash({ b: 2, a: 1 }), "key order should not matter");
});

test("hashMany combines inputs", () => {
  const h = hashMany("a", "b", "c");
  assert(h.length === 64);
  assert(hashMany("a", "b", "c") === hashMany("a", "b", "c"));
});

test("createPixel creates valid pixel", () => {
  const pixel = createPixel("test content");
  assert(pixel.hash.length === 64);
  assert(pixel.witnesses.length === 1);
  assert(pixel.witnesses[0].type === "self");
});

test("verifyPixel validates correctly", () => {
  const pixel = createPixel("test content");
  const result = verifyPixel(pixel, "test content");
  assert(result.valid === true);
  assert(result.certain === true);
});

test("verifyPixel rejects wrong content", () => {
  const pixel = createPixel("test content");
  const result = verifyPixel(pixel, "wrong content");
  assert(result.valid === false);
  assert(result.certain === false);
});

test("bestWitness ranks correctly", () => {
  const pixel = createPixel("test", [selfWitness(), bilateralWitness("other")]);
  const best = bestWitness(pixel);
  assert(best.label === "bilateral");
  assert(best.level === 2);
});

// ---- TrustAtom ----
console.log("\n  ── TrustAtom ──");

test("createAtom produces valid atom", () => {
  const atom = createAtom({ who: "user", from: "state1", action: "deploy", to: "state2" });
  assert(atom.proof.length === 64);
  assert(atom.prev[0] === "genesis");
  assert(atom._raw.who === "user");
});

test("verifyAtom validates self-consistency", () => {
  const atom = createAtom({ who: "user", from: "a", action: "b", to: "c" });
  assert(verifyAtom(atom) === true);
});

test("verifyAtom detects tampering", () => {
  const atom = createAtom({ who: "user", from: "a", action: "b", to: "c" });
  atom.action = hash("tampered");
  assert(verifyAtom(atom) === false);
});

test("verifyChain validates linked atoms", () => {
  const a1 = createAtom({ who: "u", from: "s0", action: "a1", to: "s1" });
  const a2 = createAtom({ who: "u", from: "s1", action: "a2", to: "s2", prev: a1.proof });
  const a3 = createAtom({ who: "u", from: "s2", action: "a3", to: "s3", prev: a2.proof });
  const result = verifyChain([a1, a2, a3]);
  assert(result.valid === true);
});

test("verifyChain detects broken link", () => {
  const a1 = createAtom({ who: "u", from: "s0", action: "a1", to: "s1" });
  const a2 = createAtom({ who: "u", from: "s1", action: "a2", to: "s2", prev: "wrong_hash" });
  const result = verifyChain([a1, a2]);
  assert(result.valid === false);
  assert(result.broken_at === 1);
});

// ---- Merkle ----
console.log("\n  ── Merkle Tree ──");

test("buildMerkleTree produces root", () => {
  const proofs = ["aaa", "bbb", "ccc", "ddd"].map(hash);
  const tree = buildMerkleTree(proofs);
  assert(tree.root.length === 64);
  assert(tree.layers.length > 1);
});

test("Merkle proof verifies correctly", () => {
  const proofs = ["a", "b", "c", "d", "e"].map(hash);
  const tree = buildMerkleTree(proofs);
  const proof = getMerkleProof(tree.layers, 2);
  const valid = verifyMerkleProof(proofs[2], proof, tree.root);
  assert(valid === true);
});

test("Merkle proof rejects wrong leaf", () => {
  const proofs = ["a", "b", "c", "d"].map(hash);
  const tree = buildMerkleTree(proofs);
  const proof = getMerkleProof(tree.layers, 2);
  const valid = verifyMerkleProof(hash("wrong"), proof, tree.root);
  assert(valid === false);
});

// ---- Chain ----
console.log("\n  ── TrustChain ──");

test("TrustChain records and verifies", () => {
  const chain = new TrustChain("test-user");
  chain.record({ action: "deploy", from: "s0", to: "s1" });
  chain.record({ action: "configure", from: "s1", to: "s2" });
  chain.record({ action: "enable ssl", from: "s2", to: "s3" });
  assert(chain.length === 3);
  assert(chain.verify().valid === true);
});

test("TrustChain detects tampering", () => {
  const chain = new TrustChain("test-user");
  chain.record({ action: "deploy", from: "s0", to: "s1" });
  chain.record({ action: "configure", from: "s1", to: "s2" });
  chain.atoms[1].action = hash("tampered");
  assert(chain.verify().valid === false);
});

test("TrustChain seals into Merkle block", () => {
  const chain = new TrustChain("test-user");
  chain.record({ action: "a1", from: "s0", to: "s1" });
  chain.record({ action: "a2", from: "s1", to: "s2" });
  const block = chain.seal();
  assert(block !== null);
  assert(block.root.length === 64);
  assert(block.atom_count === 2);
});

test("TrustChain Merkle proof works", () => {
  const chain = new TrustChain("test-user");
  for (let i = 0; i < 8; i++) {
    chain.record({ action: `action-${i}`, from: `s${i}`, to: `s${i + 1}` });
  }
  chain.seal();
  const proof = chain.proveAtom(3);
  assert(proof !== null);
  const valid = chain.verifyProof(proof.atom.proof, proof.merkle_proof, proof.merkle_root);
  assert(valid === true);
});

test("findDivergence detects cross-party disagreement", () => {
  const chainA = new TrustChain("customer");
  const chainB = new TrustChain("provider");
  chainA.record({ action: "deploy", from: "s0", to: "s1" });
  chainB.record({ action: "deploy", from: "s0", to: "s1" });
  chainA.record({ action: "configure", from: "s1", to: "s2" });
  chainB.record({ action: "terminate", from: "s1", to: "deleted" });
  const div = findDivergence(chainA, chainB);
  assert(div.diverged === true);
  assert(div.at_index === 1);
});

// ══════════════════════════════════════
// WITNESS TESTS
// ══════════════════════════════════════

import { saveWitness, loadWitnesses, witnessLevel, witnessSummary, createBilateralWitness } from "./core/witness.js";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// Clean witness test data
const testWitnessDir = join(homedir(), ".forge", "witnesses");

test("witnessLevel returns Level 1 when no witnesses exist", () => {
  const lvl = witnessLevel("ff".repeat(32));
  assert(lvl.level === 1);
  assert(lvl.label === "self");
});

test("createBilateralWitness creates Level 2 witness", () => {
  const testRoot = "ee".repeat(32);
  const receipt = createBilateralWitness(testRoot, "counterparty@test.com");
  assert(receipt.type === "bilateral");
  assert(receipt.level === 2);
  assert(receipt.counterparty === "counterparty@test.com");
  assert(receipt.receipt_hash.length === 64);
  // Clean up
  try { rmSync(join(testWitnessDir, `${testRoot}.json`)); } catch {}
});

test("witnessLevel upgrades after bilateral witness", () => {
  const testRoot = "dd".repeat(32);
  const lvl1 = witnessLevel(testRoot);
  assert(lvl1.level === 1);
  createBilateralWitness(testRoot, "partner@firm.com");
  const lvl2 = witnessLevel(testRoot);
  assert(lvl2.level === 2);
  assert(lvl2.label === "bilateral");
  // Clean up
  try { rmSync(join(testWitnessDir, `${testRoot}.json`)); } catch {}
});

test("witnessSummary includes upgrade path", () => {
  const testRoot = "cc".repeat(32);
  const summary = witnessSummary(testRoot);
  assert(summary.current_level.level === 1);
  assert(summary.upgrade_path.length === 3); // L2, L3, L4
  assert(summary.upgrade_path[0].includes("Level 2"));
});

test("loadWitnesses returns empty for unknown root", () => {
  const witnesses = loadWitnesses("bb".repeat(32));
  assert(Array.isArray(witnesses));
  assert(witnesses.length === 0);
});

test("saveWitness and loadWitnesses round-trip", () => {
  const testRoot = "aa".repeat(32);
  saveWitness(testRoot, { type: "test", level: 3, data: "hello" });
  const loaded = loadWitnesses(testRoot);
  assert(loaded.length === 1);
  assert(loaded[0].type === "test");
  assert(loaded[0].level === 3);
  // Clean up
  try { rmSync(join(testWitnessDir, `${testRoot}.json`)); } catch {}
});

// ---- Summary ----
console.log("\n  ────────────────────");
console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
console.log("");
