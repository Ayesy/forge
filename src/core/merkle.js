/**
 * Merkle Tree — Efficient batch verification for TrustAtoms.
 *
 * Single atom in batch: O(log n) via Merkle proof
 * Entire batch:         O(1) via root hash
 *
 * This is the "paragraph" level: atoms are letters, Merkle tree is the sentence.
 */

import { hash } from "./trust-pixel.js";

/* ================================================================
   BUILD
   ================================================================ */

/**
 * Build a Merkle tree from an array of TrustAtom proof hashes.
 *
 * Returns { root, layers } where:
 *   root   = single hash representing the entire batch
 *   layers = array of arrays, from leaves (bottom) to root (top)
 */
export function buildMerkleTree(proofs) {
  if (proofs.length === 0) return { root: hash("empty"), layers: [[]] };
  if (proofs.length === 1) return { root: proofs[0], layers: [proofs] };

  const layers = [proofs.slice()]; // layer 0 = leaves

  let current = proofs.slice();
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hash(current[i] + current[i + 1]));
      } else {
        // Odd node: promote as-is (self-pair)
        next.push(hash(current[i] + current[i]));
      }
    }
    layers.push(next);
    current = next;
  }

  return { root: current[0], layers };
}

/* ================================================================
   PROOF — Selective disclosure (ZKP application)
   ================================================================ */

/**
 * Generate a Merkle proof for a leaf at given index.
 *
 * Returns an array of { hash, direction } pairs.
 * "direction" tells the verifier which side to concatenate on.
 */
export function getMerkleProof(layers, leafIndex) {
  const proof = [];
  let idx = leafIndex;

  for (let layer = 0; layer < layers.length - 1; layer++) {
    const nodes = layers[layer];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;

    if (siblingIdx < nodes.length) {
      proof.push({
        hash: nodes[siblingIdx],
        direction: isRight ? "left" : "right",
      });
    } else {
      // No sibling (odd node), paired with itself
      proof.push({
        hash: nodes[idx],
        direction: isRight ? "left" : "right",
      });
    }

    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verify a Merkle proof — O(log n).
 *
 * Proves that a specific leaf hash belongs to the tree
 * WITHOUT revealing any other leaves.
 */
export function verifyMerkleProof(leafHash, proof, expectedRoot) {
  let current = leafHash;

  for (const step of proof) {
    if (step.direction === "left") {
      current = hash(step.hash + current);
    } else {
      current = hash(current + step.hash);
    }
  }

  return current === expectedRoot;
}

/* ================================================================
   CONVENIENCE
   ================================================================ */

/**
 * Build tree from atoms (extracts proof hashes automatically).
 */
export function treeFromAtoms(atoms) {
  return buildMerkleTree(atoms.map((a) => a.proof));
}

/**
 * Create a time-block: a Merkle tree with metadata.
 */
export function createBlock(atoms, prevBlockHash = "genesis") {
  const tree = treeFromAtoms(atoms);
  const blockHash = hash(tree.root + prevBlockHash + Date.now());

  return {
    root: tree.root,
    layers: tree.layers,
    atom_count: atoms.length,
    prev_block: prevBlockHash,
    block_hash: blockHash,
    created_at: Date.now(),
  };
}
