#!/usr/bin/env node

/**
 * FORGE MCP Server — The AI Agent Trust Layer
 *
 * This is the "SSL of AI agent operations."
 *
 * When an AI agent connects to this MCP server, every tool call
 * automatically generates a TrustAtom. The agent doesn't need to
 * explicitly "log" — trust recording is embedded in the protocol.
 *
 * Tools:
 *   forge_scan    — Enumerate trust assumptions on this system
 *   forge_log     — Explicitly record a state transition
 *   forge_verify  — Verify chain integrity
 *   forge_seal    — Seal atoms into a Merkle block
 *   forge_status  — Show chain status and recent atoms
 *   forge_prove   — Generate Merkle proof for a specific atom
 *   forge_export  — Export full chain as JSON
 *
 * Transport: stdio (works directly with Claude Code / claude desktop)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync } from "node:child_process";
import { hostname, userInfo } from "node:os";

import { hash } from "../core/trust-pixel.js";
import { createAtom, verifyAtom, formatAtom } from "../core/trust-atom.js";
import { TrustChain, findDivergence } from "../core/chain.js";
import { Store } from "../store/store.js";
import { scan, formatScanResults } from "../scanner/index.js";
import { submitToOTS, checkOTSUpgrade, witnessSummary, createBilateralWitness } from "../core/witness.js";

/* ================================================================
   SHARED STATE
   ================================================================ */

const store = new Store();

function getIdentity() {
  try {
    return `ai-agent@${hostname()}`;
  } catch {
    return "ai-agent@unknown";
  }
}

function stateSnapshot() {
  const parts = {};
  try {
    parts.processes = execSync("ps aux 2>/dev/null | wc -l", { encoding: "utf8" }).trim();
  } catch { parts.processes = "unknown"; }
  try {
    parts.connections = execSync("ss -s 2>/dev/null | head -1", { encoding: "utf8" }).trim();
  } catch { parts.connections = "unknown"; }
  parts.timestamp = Date.now();
  return parts;
}

/**
 * Core function: record a TrustAtom.
 * Called by every tool to create automatic audit trail.
 */
function recordAtom(action, fromState, toState) {
  const prev = store.lastProof();
  const atom = createAtom({
    who: getIdentity(),
    from: fromState || stateSnapshot(),
    action,
    to: toState || stateSnapshot(),
    prev,
  });
  const index = store.appendAtom(atom);

  // Save plaintext action to local index (never exported)
  store.saveAction(atom.action, action, { who: getIdentity(), source: "mcp" });

  return { atom, index };
}

/* ================================================================
   MCP SERVER
   ================================================================ */

const server = new McpServer({
  name: "forge-trust-chain",
  version: "0.1.0",
});

/* ---- forge_scan ---- */

server.tool(
  "forge_scan",
  "Scan the current system for trust assumptions — exposed ports, weak auth, firewall gaps, management panels, etc. Returns a categorized risk assessment.",
  {},
  async () => {
    const results = scan();
    
    // Auto-record this scan as a TrustAtom
    recordAtom("forge_scan", { type: "pre-scan" }, { type: "scan-complete", summary: results.summary });

    const text = formatScanResults(results)
      .replace(/\x1b\[[0-9;]*m/g, ""); // strip ANSI colors for MCP

    return {
      content: [{ type: "text", text }],
    };
  }
);

/* ---- forge_log ---- */

server.tool(
  "forge_log",
  "Record a TrustAtom — one verifiable state transition. Use this to log any operation: deployment, config change, package install, etc. Each log entry is chained to the previous one via cryptographic hash, making the timeline tamper-evident.",
  {
    action: z.string().describe("Description of the operation performed"),
    from_state: z.string().optional().describe("Description of state before (auto-captured if omitted)"),
    to_state: z.string().optional().describe("Description of state after (auto-captured if omitted)"),
  },
  async ({ action, from_state, to_state }) => {
    const fromState = from_state ? { description: from_state, ...stateSnapshot() } : stateSnapshot();
    const toState = to_state ? { description: to_state, ...stateSnapshot() } : stateSnapshot();
    
    const { atom, index } = recordAtom(action, fromState, toState);

    return {
      content: [{
        type: "text",
        text: [
          "✓ TrustAtom recorded",
          `  Index:  #${index}`,
          `  Action: ${action}`,
          `  Proof:  ${atom.proof}`,
          `  Chain:  ${store.atomCount} atoms total`,
          `  Prev:   ${atom.prev[0] === "genesis" ? "genesis" : atom.prev[0].slice(0, 32) + "…"}`,
          "",
          "  Witness: self (local). Use forge_seal to create Merkle block for anchoring.",
        ].join("\n"),
      }],
    };
  }
);

/* ---- forge_verify ---- */

server.tool(
  "forge_verify",
  "Verify the integrity of the entire TrustAtom chain. Checks that every atom's proof hash is correct and every chain link is unbroken. Returns VALID or identifies the exact point of tampering.",
  {},
  async () => {
    const atoms = store.getAtoms();
    
    if (atoms.length === 0) {
      return {
        content: [{ type: "text", text: "No atoms to verify. Use forge_log to record operations first." }],
      };
    }

    let broken = -1;
    let reason = "";
    for (let i = 0; i < atoms.length; i++) {
      if (!verifyAtom(atoms[i])) {
        broken = i;
        reason = "proof_mismatch";
        break;
      }
      if (i > 0 && !atoms[i].prev.includes(atoms[i - 1].proof)) {
        broken = i;
        reason = "chain_break";
        break;
      }
    }

    // Record the verification itself
    recordAtom("forge_verify", { atoms: atoms.length }, { valid: broken < 0, broken_at: broken });

    if (broken >= 0) {
      return {
        content: [{
          type: "text",
          text: `✗ CHAIN BROKEN at atom #${broken}\n  Reason: ${reason}\n  This indicates records have been tampered with.`,
        }],
      };
    }

    return {
      content: [{
        type: "text",
        text: `✓ CHAIN VALID\n  ${atoms.length} atoms verified, all proofs correct, all links intact.`,
      }],
    };
  }
);

/* ---- forge_seal ---- */

server.tool(
  "forge_seal",
  "Seal current TrustAtoms into a Merkle block. The block's root hash can be anchored to a public timestamp service (like OpenTimestamps) for independent existence proof, upgrading trust from Level 1 (self) to Level 3 (public).",
  {},
  async () => {
    const atoms = store.getAtoms();
    if (atoms.length === 0) {
      return {
        content: [{ type: "text", text: "No atoms to seal." }],
      };
    }

    const chain = new TrustChain(getIdentity());
    chain.atoms = atoms;
    const block = chain.seal();

    if (!block) {
      return {
        content: [{ type: "text", text: "No new atoms to seal since last block." }],
      };
    }

    store.appendBlock(block);

    // Record the seal operation
    recordAtom("forge_seal", { unsealed_atoms: block.atom_count }, { merkle_root: block.root, block_hash: block.block_hash });

    return {
      content: [{
        type: "text",
        text: [
          "✓ Merkle block sealed",
          `  Root:       ${block.root}`,
          `  Atoms:      ${block.atom_count}`,
          `  Block hash: ${block.block_hash}`,
          "",
          "  This Merkle root can now be anchored to a public timestamp service.",
          "  Anyone with the root can verify any atom in this block in O(log n).",
        ].join("\n"),
      }],
    };
  }
);

/* ---- forge_status ---- */

server.tool(
  "forge_status",
  "Show current trust chain status: identity, atom count, block count, and recent operations.",
  {},
  async () => {
    const atoms = store.getAtoms();
    const blocks = store.getBlocks();

    const lines = [
      "── FORGE Chain Status ──",
      `  Identity: ${getIdentity()}`,
      `  Atoms:    ${atoms.length}`,
      `  Blocks:   ${blocks.length}`,
      `  Store:    ~/.forge/chain.json`,
    ];

    if (atoms.length > 0) {
      lines.push("");
      lines.push("  Recent atoms:");
      const recent = atoms.slice(-5);
      const offset = atoms.length - recent.length;
      for (let i = 0; i < recent.length; i++) {
        const a = recent[i];
        const time = new Date(a.when).toISOString().slice(0, 19);
        lines.push(`    #${offset + i} [${time}] proof:${a.proof.slice(0, 32)}…`);
      }
    }

    if (blocks.length > 0) {
      lines.push("");
      lines.push("  Latest block:");
      const b = blocks[blocks.length - 1];
      lines.push(`    Root: ${b.root.slice(0, 32)}…`);
      lines.push(`    Hash: ${b.block_hash.slice(0, 32)}…`);
    }

    return {
      content: [{ type: "text", text: lines.join("\n") }],
    };
  }
);

/* ---- forge_prove ---- */

server.tool(
  "forge_prove",
  "Generate a Merkle proof for a specific atom by index. This proves the atom exists in a sealed block WITHOUT revealing other atoms (zero-knowledge principle). Requires atoms to be sealed first.",
  {
    atom_index: z.number().int().min(0).describe("The index of the atom to prove"),
  },
  async ({ atom_index }) => {
    const atoms = store.getAtoms();
    const blocks = store.getBlocks();

    if (atom_index >= atoms.length) {
      return {
        content: [{ type: "text", text: `Atom #${atom_index} does not exist. Chain has ${atoms.length} atoms.` }],
      };
    }

    if (blocks.length === 0) {
      return {
        content: [{ type: "text", text: "No sealed blocks. Run forge_seal first to create Merkle blocks." }],
      };
    }

    // Rebuild chain for proof generation
    const chain = new TrustChain(getIdentity());
    chain.atoms = atoms;
    // Re-seal to rebuild layers (store doesn't persist full layers)
    chain.blocks = []; // reset
    const block = chain.seal();
    if (!block) {
      return {
        content: [{ type: "text", text: "Could not rebuild Merkle tree." }],
      };
    }

    const proof = chain.proveAtom(atom_index);
    if (!proof) {
      return {
        content: [{ type: "text", text: `Atom #${atom_index} is not in any sealed block.` }],
      };
    }

    const verified = chain.verifyProof(proof.atom.proof, proof.merkle_proof, proof.merkle_root);

    // Record the prove operation
    recordAtom("forge_prove", { atom_index }, { verified, merkle_root: proof.merkle_root });

    return {
      content: [{
        type: "text",
        text: [
          `Merkle proof for atom #${atom_index}:`,
          `  Atom proof:   ${proof.atom.proof}`,
          `  Merkle root:  ${proof.merkle_root}`,
          `  Path length:  ${proof.merkle_proof.length} steps`,
          `  Verified:     ${verified ? "✓ YES" : "✗ NO"}`,
          "",
          "  This proof demonstrates atom #" + atom_index + " exists in the sealed block",
          "  without revealing any other atom's content.",
          "",
          JSON.stringify({
            atom_proof: proof.atom.proof,
            merkle_root: proof.merkle_root,
            merkle_path: proof.merkle_proof,
            verified,
          }, null, 2),
        ].join("\n"),
      }],
    };
  }
);

/* ---- forge_history ---- */

server.tool(
  "forge_history",
  "Show recent operations with plaintext action descriptions. This data is LOCAL ONLY and never exported or shared. Use this to understand what operations were recorded.",
  {
    limit: z.number().int().min(1).max(100).optional().describe("Number of recent entries to show (default 20)"),
  },
  async ({ limit }) => {
    const history = store.getHistory(limit || 20);

    if (history.length === 0) {
      return {
        content: [{ type: "text", text: "No history. Use forge_log to record operations first." }],
      };
    }

    const lines = [
      "── FORGE History (local plaintext) ──",
      "⚠️  This data is LOCAL ONLY. Never share actions.json.",
      "",
    ];

    for (const entry of history) {
      const time = new Date(entry.when).toISOString().slice(0, 19);
      lines.push(`#${entry.index} [${time}]`);
      lines.push(`   ${entry.action_text}`);
      lines.push(`   proof: ${entry.proof.slice(0, 24)}…`);
      lines.push("");
    }

    return {
      content: [{ type: "text", text: lines.join("\n") }],
    };
  }
);

/* ---- forge_export ---- */

server.tool(
  "forge_export",
  "Export the entire trust chain as JSON (NO plaintext actions). This can be shared with a counterparty for cross-chain verification, or archived for dispute resolution. Plaintext actions are stored locally in actions.json and never exported.",
  {},
  async () => {
    const data = store.exportAll();

    // Record the export
    recordAtom("forge_export", { atoms: data.atoms.length }, { exported: true });

    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2),
      }],
    };
  }
);

/* ---- forge_anchor ---- */

server.tool(
  "forge_anchor",
  "Anchor a sealed Merkle block to the Bitcoin blockchain via OpenTimestamps. This upgrades trust from Level 1 (self-witness) to Level 3 (public attestation), and eventually Level 4 (Bitcoin anchored). Free, no API key needed. Requires a sealed block first.",
  {
    upgrade: z.boolean().optional().describe("If true, check if pending attestations have been confirmed in Bitcoin"),
  },
  async ({ upgrade }) => {
    const blocks = store.getBlocks();
    if (blocks.length === 0) {
      return {
        content: [{ type: "text", text: "No sealed blocks. Run forge_seal first." }],
      };
    }

    const latestBlock = blocks[blocks.length - 1];
    const merkleRoot = latestBlock.root;

    if (upgrade) {
      // Check if pending attestation has been upgraded
      const result = await checkOTSUpgrade(merkleRoot);
      recordAtom("forge_anchor_upgrade_check", { merkle_root: merkleRoot }, { result: result.message });

      return {
        content: [{
          type: "text",
          text: [
            `Checking OTS upgrade for Merkle root: ${merkleRoot.slice(0, 32)}…`,
            `  Upgraded: ${result.upgraded}`,
            `  Pending:  ${result.pending}`,
            `  ${result.message}`,
            "",
            JSON.stringify(result.details, null, 2),
          ].join("\n"),
        }],
      };
    }

    // Submit to OTS calendars
    const result = await submitToOTS(merkleRoot);
    recordAtom("forge_anchor", { merkle_root: merkleRoot }, { level: result.level, calendars: result.successful_submissions });

    const lines = [
      result.successful_submissions > 0
        ? `✓ Submitted to ${result.successful_submissions}/${result.total_calendars} OTS calendars`
        : "✗ Failed to submit to any calendar",
      `  Merkle root: ${merkleRoot.slice(0, 32)}…`,
      `  Digest:      ${result.digest.slice(0, 32)}… (privacy-protected)`,
      `  Trust level: ${result.level === 3 ? "Level 3 (public attestation — pending)" : "Level 1 (self)"}`,
      "",
    ];

    for (const cal of result.calendars) {
      const icon = cal.status === "submitted" ? "✓" : "✗";
      lines.push(`  ${icon} ${cal.calendar}: ${cal.status}${cal.error ? " — " + cal.error : ""}`);
    }

    if (result.successful_submissions > 0) {
      lines.push("");
      lines.push("  Next: Wait ~2 hours, then run forge_anchor with upgrade=true");
      lines.push("  to check for Bitcoin confirmation (Level 4).");
    }

    return {
      content: [{ type: "text", text: lines.join("\n") }],
    };
  }
);

/* ---- forge_witness ---- */

server.tool(
  "forge_witness",
  "Show witness status for the latest sealed block. Displays current trust level, all witnesses, and the upgrade path to higher trust levels.",
  {
    bilateral_party: z.string().optional().describe("If provided, create a bilateral witness receipt for this counterparty"),
  },
  async ({ bilateral_party }) => {
    const blocks = store.getBlocks();
    if (blocks.length === 0) {
      return {
        content: [{ type: "text", text: "No sealed blocks. Run forge_seal first." }],
      };
    }

    const latestBlock = blocks[blocks.length - 1];
    const merkleRoot = latestBlock.root;

    if (bilateral_party) {
      const receipt = createBilateralWitness(merkleRoot, bilateral_party);
      recordAtom("forge_witness_bilateral", { merkle_root: merkleRoot }, { counterparty: bilateral_party });

      return {
        content: [{
          type: "text",
          text: [
            `✓ Bilateral witness created`,
            `  Counterparty: ${bilateral_party}`,
            `  Receipt hash: ${receipt.receipt_hash}`,
            `  Trust level:  Level 2 (bilateral — neither party can deny)`,
            "",
            "  Share this receipt with the counterparty:",
            JSON.stringify(receipt, null, 2),
          ].join("\n"),
        }],
      };
    }

    const summary = witnessSummary(merkleRoot);

    const lines = [
      `── Witness Status ──`,
      `  Merkle root: ${merkleRoot.slice(0, 32)}…`,
      `  Trust level: Level ${summary.current_level.level} (${summary.current_level.label})`,
      `  ${summary.current_level.description}`,
      `  Witnesses:   ${summary.witness_count}`,
    ];

    if (summary.witnesses.length > 0) {
      lines.push("");
      for (const w of summary.witnesses) {
        lines.push(`    [L${w.level}] ${w.type} — ${w.created_at}`);
      }
    }

    if (summary.upgrade_path.length > 0) {
      lines.push("");
      lines.push("  Upgrade path:");
      for (const p of summary.upgrade_path) {
        lines.push(`    → ${p}`);
      }
    }

    return {
      content: [{ type: "text", text: lines.join("\n") }],
    };
  }
);

/* ================================================================
   START
   ================================================================ */

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  // Record that MCP server started
  recordAtom("mcp_server_started", { type: "startup" }, { type: "ready", identity: getIdentity() });
}

main().catch((err) => {
  console.error("FORGE MCP Server error:", err);
  process.exit(1);
});
