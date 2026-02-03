/**
 * Chain — Temporal chain of TrustAtoms and Merkle blocks.
 *
 * The "page" level: atoms are letters, Merkle trees are sentences,
 * and the chain is the full document — ordered in time, linked by hashes.
 *
 * This is the in-memory runtime. For persistence, see store.
 */

import { createAtom, verifyAtom, verifyChain, formatAtom } from "./trust-atom.js";
import { treeFromAtoms, createBlock, getMerkleProof, verifyMerkleProof } from "./merkle.js";

export class TrustChain {
  constructor(identity) {
    this.identity = identity;
    this.atoms = [];
    this.blocks = [];
  }

  /* ---- Record ---- */

  /**
   * Append a new state transition to the chain.
   */
  record({ action, from, to }) {
    const prev =
      this.atoms.length > 0
        ? this.atoms[this.atoms.length - 1].proof
        : "genesis";

    const atom = createAtom({
      who: this.identity,
      from,
      action,
      to,
      prev,
    });

    this.atoms.push(atom);
    return atom;
  }

  /**
   * Seal current atoms into a Merkle block.
   * Call periodically (e.g. every N atoms or every M seconds).
   */
  seal() {
    if (this.atoms.length === 0) return null;

    const prevBlockHash =
      this.blocks.length > 0
        ? this.blocks[this.blocks.length - 1].block_hash
        : "genesis";

    // Seal only atoms not yet in a block
    const unsealed = this.atoms.slice(this._lastSealedIndex() + 1);
    if (unsealed.length === 0) return null;

    const block = createBlock(unsealed, prevBlockHash);
    block.atom_range = [
      this._lastSealedIndex() + 1,
      this.atoms.length - 1,
    ];
    this.blocks.push(block);
    return block;
  }

  /* ---- Verify ---- */

  /** Verify entire atom chain integrity — O(n). */
  verify() {
    return verifyChain(this.atoms);
  }

  /** Generate Merkle proof for a specific atom index. */
  proveAtom(globalIndex) {
    // Find which block contains this atom
    const block = this.blocks.find(
      (b) => globalIndex >= b.atom_range[0] && globalIndex <= b.atom_range[1]
    );
    if (!block) return null;

    const localIndex = globalIndex - block.atom_range[0];
    const proof = getMerkleProof(block.layers, localIndex);
    return {
      atom: this.atoms[globalIndex],
      merkle_proof: proof,
      merkle_root: block.root,
      block_hash: block.block_hash,
    };
  }

  /** Verify a Merkle proof for an atom. */
  verifyProof(atomProofHash, merkleProof, expectedRoot) {
    return verifyMerkleProof(atomProofHash, merkleProof, expectedRoot);
  }

  /* ---- Query ---- */

  get length() {
    return this.atoms.length;
  }

  last() {
    return this.atoms[this.atoms.length - 1] || null;
  }

  /** Export chain as portable JSON (no raw data). */
  export() {
    return {
      identity_hash: this.atoms[0]?.who || null,
      atom_count: this.atoms.length,
      block_count: this.blocks.length,
      atoms: this.atoms.map(({ _raw, ...a }) => a),
      blocks: this.blocks.map(({ layers, ...b }) => b),
      exported_at: Date.now(),
    };
  }

  /** Print chain summary to console. */
  summary() {
    const lines = [
      `Chain: ${this.identity}`,
      `Atoms: ${this.atoms.length}`,
      `Blocks: ${this.blocks.length}`,
      `Integrity: ${this.verify().valid ? "✓ VALID" : "✗ BROKEN"}`,
      "",
      "Recent atoms:",
    ];
    const recent = this.atoms.slice(-5);
    const offset = this.atoms.length - recent.length;
    for (let i = 0; i < recent.length; i++) {
      lines.push("  " + formatAtom(recent[i], offset + i));
    }
    return lines.join("\n");
  }

  /* ---- Internal ---- */

  _lastSealedIndex() {
    if (this.blocks.length === 0) return -1;
    return this.blocks[this.blocks.length - 1].atom_range[1];
  }
}

/* ================================================================
   CROSS-CHAIN DISPUTE RESOLUTION
   ================================================================ */

/**
 * Compare two chains for the same system and find divergence.
 * This is the "cryptographic double-entry bookkeeping" from the whitepaper.
 */
export function findDivergence(chainA, chainB) {
  const minLen = Math.min(chainA.atoms.length, chainB.atoms.length);

  for (let i = 0; i < minLen; i++) {
    const a = chainA.atoms[i];
    const b = chainB.atoms[i];

    // Same action at same time should produce same from/to hashes
    if (a.action !== b.action || a.from !== b.from || a.to !== b.to) {
      return {
        diverged: true,
        at_index: i,
        time_a: a.when,
        time_b: b.when,
        action_match: a.action === b.action,
        state_match: a.from === b.from && a.to === b.to,
      };
    }
  }

  // Length difference = one party has operations the other doesn't
  if (chainA.atoms.length !== chainB.atoms.length) {
    return {
      diverged: true,
      at_index: minLen,
      reason: "length_mismatch",
      length_a: chainA.atoms.length,
      length_b: chainB.atoms.length,
    };
  }

  return { diverged: false };
}
