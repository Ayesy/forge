/**
 * Store — SQLite persistence for TrustAtom chains.
 *
 * Atoms and blocks must survive process restarts.
 * The store is the "self-witness" layer — the minimum persistence
 * before bilateral or public witnesses are added.
 *
 * Uses Node 22 built-in node:sqlite (experimental) if available,
 * otherwise falls back to JSON file storage.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

const DEFAULT_PATH = join(
  process.env.HOME || "/tmp",
  ".forge",
  "chain.json"
);

const DEFAULT_ACTIONS_PATH = join(
  process.env.HOME || "/tmp",
  ".forge",
  "actions.json"
);

export class Store {
  constructor(path = DEFAULT_PATH, actionsPath = DEFAULT_ACTIONS_PATH) {
    this.path = path;
    this.actionsPath = actionsPath;
    this._ensure();
    this._data = this._load();
    this._actions = this._loadActions();
  }

  /* ---- Atoms ---- */

  appendAtom(atom) {
    const clean = { ...atom };
    delete clean._raw; // Don't persist raw data
    this._data.atoms.push(clean);
    this._save();
    return this._data.atoms.length - 1;
  }

  getAtoms(from = 0, to = Infinity) {
    return this._data.atoms.slice(from, to);
  }

  getAtom(index) {
    return this._data.atoms[index] || null;
  }

  get atomCount() {
    return this._data.atoms.length;
  }

  /* ---- Blocks ---- */

  appendBlock(block) {
    const clean = { ...block };
    delete clean.layers; // Don't persist full tree (can be rebuilt)
    this._data.blocks.push(clean);
    this._save();
    return this._data.blocks.length - 1;
  }

  getBlocks() {
    return this._data.blocks;
  }

  /* ---- Meta ---- */

  setMeta(key, value) {
    this._data.meta[key] = value;
    this._save();
  }

  getMeta(key) {
    return this._data.meta[key];
  }

  /* ---- Export / Import ---- */

  exportAll() {
    return { ...this._data, exported_at: Date.now() };
  }

  importChain(data) {
    if (data.atoms) this._data.atoms = data.atoms;
    if (data.blocks) this._data.blocks = data.blocks;
    if (data.meta) this._data.meta = { ...this._data.meta, ...data.meta };
    this._save();
  }

  /* ---- Last atom proof (for chain continuation) ---- */

  lastProof() {
    if (this._data.atoms.length === 0) return "genesis";
    return this._data.atoms[this._data.atoms.length - 1].proof;
  }

  /* ---- Actions (local plaintext index, never exported) ---- */

  saveAction(hash, plaintext, metadata = {}) {
    this._actions.entries[hash] = {
      plaintext,
      recorded_at: Date.now(),
      ...metadata,
    };
    this._saveActions();
  }

  getAction(hash) {
    return this._actions.entries[hash] || null;
  }

  getActionByIndex(atomIndex) {
    const atom = this.getAtom(atomIndex);
    if (!atom) return null;
    return this.getAction(atom.action);
  }

  getAllActions() {
    return this._actions.entries;
  }

  // Get history with plaintext (for display)
  getHistory(limit = 20) {
    const atoms = this.getAtoms();
    const recent = atoms.slice(-limit);
    return recent.map((atom, i) => {
      const action = this.getAction(atom.action);
      return {
        index: atoms.length - recent.length + i,
        when: atom.when,
        proof: atom.proof,
        action_hash: atom.action,
        action_text: action?.plaintext || "[unknown - recorded before plaintext storage]",
      };
    });
  }

  _loadActions() {
    if (existsSync(this.actionsPath)) {
      try {
        return JSON.parse(readFileSync(this.actionsPath, "utf8"));
      } catch {
        return this._emptyActions();
      }
    }
    return this._emptyActions();
  }

  _saveActions() {
    writeFileSync(this.actionsPath, JSON.stringify(this._actions, null, 2));
  }

  _emptyActions() {
    return {
      version: "0.1.0",
      note: "LOCAL ONLY - This file contains plaintext actions for your reference. Never share or export this file.",
      created_at: Date.now(),
      entries: {},
    };
  }

  /* ---- Internal ---- */

  _ensure() {
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  _load() {
    if (existsSync(this.path)) {
      try {
        return JSON.parse(readFileSync(this.path, "utf8"));
      } catch {
        return this._empty();
      }
    }
    return this._empty();
  }

  _save() {
    writeFileSync(this.path, JSON.stringify(this._data, null, 2));
  }

  _empty() {
    return {
      version: "0.1.0",
      created_at: Date.now(),
      atoms: [],
      blocks: [],
      meta: {},
    };
  }

  /* ---- Reset (for testing) ---- */

  reset() {
    this._data = this._empty();
    this._save();
  }
}
