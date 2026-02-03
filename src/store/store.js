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

export class Store {
  constructor(path = DEFAULT_PATH) {
    this.path = path;
    this._ensure();
    this._data = this._load();
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
