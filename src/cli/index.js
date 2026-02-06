#!/usr/bin/env node

/**
 * FORGE CLI — Trust Chain Protocol
 *
 * Commands:
 *   forge scan              Enumerate trust assumptions on this system
 *   forge log <action>      Record a TrustAtom (state transition)
 *   forge verify            Verify chain integrity
 *   forge prove <index>     Generate Merkle proof for a specific atom
 *   forge seal              Seal current atoms into a Merkle block
 *   forge status            Show chain status
 *   forge export            Export chain as JSON
 *   forge demo              Run full demonstration
 */

import { scan, formatScanResults } from "../scanner/index.js";
import { TrustChain, findDivergence } from "../core/chain.js";
import { Store } from "../store/store.js";
import { hash } from "../core/trust-pixel.js";
import { verifyAtom, formatAtom, createAtom } from "../core/trust-atom.js";
import { execSync } from "node:child_process";
import { hostname, userInfo } from "node:os";
import { submitToOTS, checkOTSUpgrade, witnessSummary, createBilateralWitness, witnessLevel } from "../core/witness.js";

/* ================================================================
   STATE SNAPSHOT — captures system state for from/to fields
   ================================================================ */

function stateSnapshot() {
  const parts = {};
  try {
    parts.uptime = execSync("uptime -s 2>/dev/null", { encoding: "utf8" }).trim();
  } catch { parts.uptime = "unknown"; }
  try {
    parts.processes = execSync("ps aux 2>/dev/null | wc -l", { encoding: "utf8" }).trim();
  } catch { parts.processes = "unknown"; }
  try {
    parts.connections = execSync("ss -s 2>/dev/null | head -1", { encoding: "utf8" }).trim();
  } catch { parts.connections = "unknown"; }
  try {
    parts.disk = execSync("df -h / 2>/dev/null | tail -1", { encoding: "utf8" }).trim();
  } catch { parts.disk = "unknown"; }
  parts.timestamp = Date.now();
  return parts;
}

function getIdentity() {
  try {
    const user = userInfo().username;
    const host = hostname();
    return `${user}@${host}`;
  } catch {
    return "unknown@unknown";
  }
}

/* ================================================================
   COMMANDS
   ================================================================ */

function cmdScan() {
  const results = scan();
  console.log(formatScanResults(results));
  return results;
}

function cmdLog(action) {
  if (!action) {
    console.error("Usage: forge log <action description>");
    console.error('Example: forge log "deployed nginx config"');
    process.exit(1);
  }

  const store = new Store();
  const identity = getIdentity();
  const stateBefore = stateSnapshot();

  const prev = store.lastProof();

  const atom = createAtom({
    who: identity,
    from: stateBefore,
    action,
    to: stateSnapshot(),
    prev,
  });

  const index = store.appendAtom(atom);

  // Save plaintext action to local index (never exported)
  store.saveAction(atom.action, action, { who: identity });

  console.log("");
  console.log("  ✓ TrustAtom recorded");
  console.log(`  Index:  #${index}`);
  console.log(`  Who:    ${identity} → ${atom.who.slice(0, 16)}…`);
  console.log(`  Action: ${action}`);
  console.log(`  Proof:  ${atom.proof.slice(0, 32)}…`);
  console.log(`  Chain:  ${store.atomCount} atoms total`);
  console.log(`  Prev:   ${prev === "genesis" ? "genesis" : prev.slice(0, 16) + "…"}`);
  console.log("");
  console.log("  Witness: self (local only)");
  console.log("  → Run 'forge seal' to create Merkle block");
  console.log("");
}

function cmdVerify() {
  const store = new Store();
  const atoms = store.getAtoms();

  if (atoms.length === 0) {
    console.log("\n  No atoms to verify. Run 'forge log' first.\n");
    return;
  }

  console.log("");
  console.log("  Verifying chain integrity…");
  console.log(`  Atoms: ${atoms.length}`);

  // Verify each atom
  let broken = -1;
  for (let i = 0; i < atoms.length; i++) {
    if (!verifyAtom(atoms[i])) {
      broken = i;
      break;
    }
    if (i > 0 && !atoms[i].prev.includes(atoms[i - 1].proof)) {
      broken = i;
      break;
    }
  }

  if (broken >= 0) {
    console.log(`  ✗ CHAIN BROKEN at atom #${broken}`);
    console.log(`    This means records have been tampered with.`);
  } else {
    console.log("  ✓ CHAIN VALID — all atoms verified, all links intact.");
  }
  console.log("");
}

function cmdSeal() {
  // For now, seal is informational (full Merkle block in store)
  const store = new Store();
  const atoms = store.getAtoms();
  if (atoms.length === 0) {
    console.log("\n  No atoms to seal.\n");
    return;
  }

  // Build a lightweight chain to seal
  const chain = new TrustChain(getIdentity());
  // Replay atoms into chain (they already have proofs)
  chain.atoms = atoms;
  const block = chain.seal();

  if (!block) {
    console.log("\n  No new atoms to seal.\n");
    return;
  }

  store.appendBlock(block);

  console.log("");
  console.log("  ✓ Merkle block sealed");
  console.log(`  Root:       ${block.root.slice(0, 32)}…`);
  console.log(`  Atoms:      ${block.atom_count}`);
  console.log(`  Block hash: ${block.block_hash.slice(0, 32)}…`);
  console.log("");
  console.log("  This root can be anchored to a public timestamp service");
  console.log("  for independent existence proof.");
  console.log("");
}

function cmdStatus() {
  const store = new Store();
  const atoms = store.getAtoms();
  const blocks = store.getBlocks();

  console.log("");
  console.log("  ── FORGE Chain Status ──");
  console.log(`  Identity: ${getIdentity()}`);
  console.log(`  Atoms:    ${atoms.length}`);
  console.log(`  Blocks:   ${blocks.length}`);
  console.log(`  Store:    ~/.forge/chain.json`);
  console.log("");

  if (atoms.length > 0) {
    console.log("  Recent atoms:");
    const recent = atoms.slice(-5);
    const offset = atoms.length - recent.length;
    for (let i = 0; i < recent.length; i++) {
      const a = recent[i];
      const time = new Date(a.when).toISOString().slice(0, 19);
      console.log(`    #${offset + i} [${time}] proof:${a.proof.slice(0, 24)}…`);
    }
    console.log("");
  }
}

function cmdExport() {
  const store = new Store();
  const data = store.exportAll();
  console.log(JSON.stringify(data, null, 2));
}

async function cmdAnchor(upgrade) {
  const store = new Store();
  const blocks = store.getBlocks();

  if (blocks.length === 0) {
    console.log("  No sealed blocks. Run 'forge seal' first.");
    return;
  }

  const latestBlock = blocks[blocks.length - 1];
  const merkleRoot = latestBlock.root;

  if (upgrade) {
    console.log(`  Checking OTS upgrade for: ${merkleRoot.slice(0, 32)}…`);
    try {
      const result = await checkOTSUpgrade(merkleRoot);
      console.log(`  Upgraded: ${result.upgraded}  Pending: ${result.pending}`);
      console.log(`  ${result.message}`);
      for (const d of result.details) {
        const icon = d.status === "confirmed" ? "✓" : "⏳";
        console.log(`    ${icon} ${d.calendar}: ${d.status}`);
      }
    } catch (err) {
      console.log(`  Error: ${err.message}`);
    }
    return;
  }

  console.log(`  Submitting Merkle root to OpenTimestamps calendars…`);
  console.log(`  Root: ${merkleRoot.slice(0, 32)}…`);
  console.log("");

  try {
    const result = await submitToOTS(merkleRoot);
    for (const cal of result.calendars) {
      const icon = cal.status === "submitted" ? "✓" : "✗";
      console.log(`  ${icon} ${cal.calendar}: ${cal.status}${cal.error ? " — " + cal.error : ""}`);
    }
    console.log("");
    if (result.successful_submissions > 0) {
      console.log(`  ✓ Trust upgraded to Level 3 (public attestation — pending)`);
      console.log(`  Next: Run 'forge anchor --upgrade' after ~2 hours for Bitcoin confirmation.`);
    } else {
      console.log(`  ✗ All submissions failed. Check network connectivity.`);
    }
  } catch (err) {
    console.log(`  Error: ${err.message}`);
  }
}

function cmdWitness(subArgs) {
  const store = new Store();
  const blocks = store.getBlocks();

  if (blocks.length === 0) {
    console.log("  No sealed blocks. Run 'forge seal' first.");
    return;
  }

  const latestBlock = blocks[blocks.length - 1];
  const merkleRoot = latestBlock.root;

  // Check for --bilateral flag
  const biIdx = subArgs.indexOf("--bilateral");
  if (biIdx >= 0) {
    const party = subArgs[biIdx + 1];
    if (!party) {
      console.log("  Usage: forge witness --bilateral <counterparty-id>");
      return;
    }
    const receipt = createBilateralWitness(merkleRoot, party);
    console.log(`  ✓ Bilateral witness created`);
    console.log(`  Counterparty: ${party}`);
    console.log(`  Receipt hash: ${receipt.receipt_hash}`);
    console.log(`  Trust level:  Level 2 (bilateral)`);
    console.log("");
    console.log("  Share this receipt with the counterparty:");
    console.log(JSON.stringify(receipt, null, 2));
    return;
  }

  // Show witness status
  const summary = witnessSummary(merkleRoot);
  console.log(`  ── Witness Status ──`);
  console.log(`  Merkle root: ${merkleRoot.slice(0, 32)}…`);
  console.log(`  Trust level: Level ${summary.current_level.level} (${summary.current_level.label})`);
  console.log(`  ${summary.current_level.description}`);
  console.log(`  Witnesses:   ${summary.witness_count}`);

  if (summary.witnesses.length > 0) {
    console.log("");
    for (const w of summary.witnesses) {
      console.log(`    [L${w.level}] ${w.type} — ${w.created_at}`);
    }
  }

  if (summary.upgrade_path.length > 0) {
    console.log("");
    console.log("  Upgrade path:");
    for (const p of summary.upgrade_path) {
      console.log(`    → ${p}`);
    }
  }
}

function cmdHistory(limit = 20) {
  const store = new Store();
  const history = store.getHistory(parseInt(limit) || 20);

  if (history.length === 0) {
    console.log("\n  No history. Run 'forge log' first.\n");
    return;
  }

  console.log("");
  console.log("  ── FORGE History (local plaintext) ──");
  console.log("  ⚠️  This data is LOCAL ONLY. Never share actions.json.");
  console.log("");

  for (const entry of history) {
    const time = new Date(entry.when).toISOString().slice(0, 19);
    console.log(`  #${entry.index} [${time}]`);
    console.log(`     ${entry.action_text}`);
    console.log(`     proof: ${entry.proof.slice(0, 24)}…`);
    console.log("");
  }
}

function cmdDemo() {
  console.log("");
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║            FORGE — Full Demonstration               ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log("");

  // ---- 1. Theory ----
  console.log("━━━ 1. TRUST PIXEL: The smallest unit of trust ━━━");
  console.log("");
  console.log("  Trust = Certainty × Existence");
  console.log("");

  const content = "server deployed nginx 1.24";
  const h = hash(content);
  console.log(`  Content:    "${content}"`);
  console.log(`  Hash:       ${h}`);
  console.log(`  Same input: ${hash(content) === h ? "✓ same hash (deterministic)" : "✗ different"}`);
  console.log(`  Diff input: ${hash(content + "x") === h ? "✗ same (collision!)" : "✓ different hash (collision-resistant)"}`);
  console.log("");
  console.log("  This hash is CERTAINTY. But it can be deleted.");
  console.log("  We need a WITNESS to make it undeniable.");
  console.log("");

  // ---- 2. TrustAtom ----
  console.log("━━━ 2. TRUSTATOM: One verifiable state transition ━━━");
  console.log("");

  const chain = new TrustChain("demo-user@forge");

  const ops = [
    { action: "apt update && apt upgrade", from: { packages: "outdated" }, to: { packages: "current" } },
    { action: "install nginx", from: { nginx: "absent" }, to: { nginx: "1.24.0" } },
    { action: "configure firewall", from: { ufw: "inactive" }, to: { ufw: "active", rules: ["22/tcp", "80/tcp", "443/tcp"] } },
    { action: "deploy app to /var/www", from: { app: "absent" }, to: { app: "v1.0.0", path: "/var/www" } },
    { action: "enable SSL via certbot", from: { ssl: false }, to: { ssl: true, cert: "letsencrypt" } },
  ];

  for (const op of ops) {
    chain.record(op);
  }

  console.log("  Recorded 5 operations:");
  for (let i = 0; i < chain.atoms.length; i++) {
    console.log("    " + formatAtom(chain.atoms[i], i));
  }
  console.log("");

  // ---- 3. Chain verification ----
  console.log("━━━ 3. CHAIN VERIFICATION ━━━");
  console.log("");

  const result = chain.verify();
  console.log(`  Chain valid: ${result.valid ? "✓ YES" : "✗ NO"}`);
  console.log(`  All ${chain.length} atoms verified, all links intact.`);
  console.log("");

  // Tamper test
  console.log("  Tampering test — modifying atom #2…");
  const originalAction = chain.atoms[2].action;
  chain.atoms[2].action = hash("something else");
  const tampered = chain.verify();
  console.log(`  Chain valid after tamper: ${tampered.valid ? "✓ (BAD — tamper undetected)" : "✗ BROKEN at #" + tampered.broken_at + " — tamper detected!"}`);
  chain.atoms[2].action = originalAction; // restore
  console.log("");

  // ---- 4. Merkle tree ----
  console.log("━━━ 4. MERKLE TREE: Batch verification ━━━");
  console.log("");

  const block = chain.seal();
  console.log(`  Sealed ${block.atom_count} atoms into Merkle block`);
  console.log(`  Root: ${block.root.slice(0, 32)}…`);
  console.log(`  Tree depth: ${block.layers.length} layers`);
  console.log("");

  // Merkle proof
  const proof = chain.proveAtom(2); // prove atom #2 exists
  if (proof) {
    console.log("  Merkle proof for atom #2:");
    console.log(`    Atom proof:  ${proof.atom.proof.slice(0, 24)}…`);
    console.log(`    Path length: ${proof.merkle_proof.length} steps (O(log n))`);
    const verified = chain.verifyProof(proof.atom.proof, proof.merkle_proof, proof.merkle_root);
    console.log(`    Verified:    ${verified ? "✓ atom #2 is in this block" : "✗ INVALID"}`);
    console.log("");
    console.log("  → This proves atom #2 exists WITHOUT revealing atoms 0,1,3,4.");
    console.log("    Zero-knowledge principle applied to operational trust.");
  }
  console.log("");

  // ---- 5. Cross-party dispute ----
  console.log("━━━ 5. CROSS-PARTY DISPUTE RESOLUTION ━━━");
  console.log("");

  const customerChain = new TrustChain("customer@myserver");
  const providerChain = new TrustChain("provider@zeabur");

  // Both record the same first 3 operations
  for (let i = 0; i < 3; i++) {
    customerChain.record(ops[i]);
    providerChain.record(ops[i]);
  }

  // Customer records 2 more operations
  customerChain.record(ops[3]);
  customerChain.record(ops[4]);

  // Provider's chain diverges — they see "malicious activity"
  providerChain.record({ action: "malicious outbound traffic detected", from: { alert: false }, to: { alert: true } });
  providerChain.record({ action: "server terminated", from: { status: "running" }, to: { status: "deleted" } });

  const divergence = findDivergence(customerChain, providerChain);
  console.log("  Customer's chain: 5 atoms (normal operations)");
  console.log("  Provider's chain: 5 atoms (includes termination)");
  console.log(`  Divergence found: ${divergence.diverged ? "YES" : "NO"}`);
  if (divergence.diverged) {
    console.log(`  Diverges at:      atom #${divergence.at_index}`);
    console.log(`  Actions match:    ${divergence.action_match ? "yes" : "NO — different operations recorded"}`);
    console.log(`  States match:     ${divergence.state_match ? "yes" : "NO — different state transitions"}`);
  }
  console.log("");
  console.log("  → With both chains, a third party can determine:");
  console.log("    - Operations agreed upon (atoms 0-2)");
  console.log("    - Point of disagreement (atom 3)");
  console.log("    - What each party claims happened after");
  console.log("    - If anchored publicly: which chain's timestamps are authentic");
  console.log("");

  // ---- 6. Trust levels ----
  console.log("━━━ 6. TRUST LEVELS (Witness strength) ━━━");
  console.log("");
  console.log("  Level 1 — Self:       Only I hold the hash.       (diary)");
  console.log("  Level 2 — Bilateral:  Both parties hold it.       (contract)");
  console.log("  Level 3 — Public:     Timestamped by 3rd party.   (notary)");
  console.log("  Level 4 — Anchored:   In a public blockchain.     (law of physics)");
  console.log("");
  console.log("  Current chain: Level 1 (self-witnessed)");
  console.log("  → 'forge seal' creates Merkle root for public anchoring");
  console.log("  → Future: OpenTimestamps anchoring for Level 3-4");
  console.log("");

  // ---- Summary ----
  console.log("━━━ SUMMARY ━━━");
  console.log("");
  console.log("  Hash      = pixel of trust  (certainty: mathematical)");
  console.log("  Witness   = existence proof  (persistence: physical)");
  console.log("  TrustAtom = one state change (who/from/action/to/when/prev/proof)");
  console.log("  Merkle    = batch verify     (O(log n) proof, O(1) batch)");
  console.log("  Chain     = timeline         (temporal ordering, tamper detection)");
  console.log("  DAG       = multi-agent      (cross-boundary trust graph)");
  console.log("");
  console.log("  Trust = Certainty × Existence");
  console.log("  FORGE makes both computable.");
  console.log("");
}

/* ================================================================
   MAIN
   ================================================================ */

const args = process.argv.slice(2);
const command = args[0] || "help";

switch (command) {
  case "scan":
    cmdScan();
    break;

  case "log":
    cmdLog(args.slice(1).join(" "));
    break;

  case "verify":
    cmdVerify();
    break;

  case "seal":
    cmdSeal();
    break;

  case "anchor":
    cmdAnchor(args.includes("--upgrade"));
    break;

  case "witness":
    cmdWitness(args.slice(1));
    break;

  case "status":
    cmdStatus();
    break;

  case "export":
    cmdExport();
    break;

  case "demo":
    cmdDemo();
    break;

  case "history":
    cmdHistory(args[1]);
    break;

  case "mcp":
    // Start MCP server
    import("../mcp/server.js");
    break;

  case "help":
  default:
    console.log(`
  FORGE — Trust Chain Protocol v0.1

  Trust = Certainty × Existence
  Every operation produces a verifiable, undeniable fact.

  Commands:
    forge scan                       Enumerate trust assumptions on this system
    forge log <action>               Record a TrustAtom (one state transition)
    forge verify                     Verify chain integrity
    forge seal                       Seal atoms into a Merkle block
    forge anchor                     Submit Merkle root to OTS calendars (Level 3)
    forge anchor --upgrade           Check for Bitcoin confirmation (Level 4)
    forge witness                    Show witness status for latest block
    forge witness --bilateral <id>   Create bilateral witness receipt
    forge status                     Show chain status
    forge history [n]                Show recent operations with plaintext (local only)
    forge export                     Export chain as JSON (no plaintext)
    forge demo                       Run full demonstration
    forge mcp                        Start MCP server (for Claude Code)

  Witness Hierarchy:
    Level 1: Self        — Only you hold the hash (can be deleted)
    Level 2: Bilateral   — Two parties hold it (one can't deny)
    Level 3: Public      — OTS calendar attested (independent verification)
    Level 4: Anchored    — Bitcoin blockchain (computationally undeletable)

  Examples:
    forge scan
    forge log "deployed nginx config"
    forge log "opened port 443"
    forge verify
    forge seal
    forge anchor
    forge witness --bilateral ops@provider.com
`);
    break;
}
