# FORGE — Trust Chain Protocol v0.4

> **Trust = Certainty × Existence**

The trust layer for cloud operations and AI agents. Every operation produces a verifiable, undeniable, cryptographically chained fact anchored to the Bitcoin blockchain.

**Rust core in development!** High-performance native implementation coming soon.

---

## Why Forge?

| Problem | Forge Solution |
|---------|----------------|
| "Who changed the config?" | Every operation is signed and timestamped |
| "Can you prove you deployed at 3pm?" | Bitcoin-anchored proof, undeniable |
| "Someone deleted the audit log" | Hash chain + blockchain = impossible to delete |
| "I need compliance evidence" | Export verifiable JSON, anyone can validate |

---

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/your-repo/forge.git
cd forge
npm install

# Setup global CLI (recommended)
sudo ln -sf $(pwd)/src/cli/index.js /usr/local/bin/forge
```

### Basic Usage (Like Git!)

```bash
# Record operations
forge log "deployed nginx v1.24"
forge log "configured firewall rules"
forge log "enabled SSL certificates"

# Seal into Merkle block
forge seal

# Anchor to Bitcoin (permanent, undeletable)
forge anchor

# Check status
forge status
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `forge scan` | Scan system for trust assumptions (ports, SSH, Docker, etc.) |
| `forge log "<action>"` | Record an operation (TrustAtom) |
| `forge verify` | Verify chain integrity |
| `forge seal` | Seal atoms into a Merkle block |
| `forge anchor` | Submit Merkle root to Bitcoin via OpenTimestamps |
| `forge anchor --upgrade` | Check Bitcoin confirmation (~2 hours) |
| `forge witness` | Show witness status |
| `forge witness --bilateral <email>` | Create bilateral witness with counterparty |
| `forge status` | Show chain status and recent atoms |
| `forge export` | Export full chain as JSON |
| `forge help` | Show all commands |

---

## Forge vs Git

| | Git | Forge |
|--|-----|-------|
| **Tracks** | Code changes | Operations/Events |
| **Unit** | commit | atom |
| **Package** | push | seal |
| **Proof** | Remote repo | Bitcoin blockchain |
| **Deletable** | Yes (force push) | No (blockchain) |
| **Use case** | Version control | Audit trail / Compliance |

```bash
# Git workflow
git add . && git commit -m "deployed" && git push

# Forge workflow
forge log "deployed" && forge seal && forge anchor
```

---

## Witness Hierarchy (4 Levels of Trust)

```
┌─────────────────────────────────────────────────────────┐
│  Level 4: ANCHORED  — Bitcoin blockchain                │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Level 3: PUBLIC — OpenTimestamps calendars       │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │  Level 2: BILATERAL — You + Counterparty   │  │  │
│  │  │  ┌───────────────────────────────────────┐  │  │  │
│  │  │  │  Level 1: SELF — Only you (deletable) │  │  │  │
│  │  │  └───────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

| Level | Name | Who Can Verify | Can Be Deleted? |
|-------|------|----------------|-----------------|
| 1 | Self | Only you | Yes |
| 2 | Bilateral | You + counterparty | No (one party has copy) |
| 3 | Public | Anyone (OTS calendars) | No (independent servers) |
| 4 | Anchored | Everyone (Bitcoin) | No (computationally impossible) |

---

## How Others Verify Your Records

### Method 1: Share Merkle Root (Simplest)

```bash
forge status
# Root: c273ed77e3a06623238d0774211fe6f2…
```

Give this hash to anyone. After Bitcoin confirmation, they can verify on blockchain.

### Method 2: Bilateral Witness

```bash
forge witness --bilateral auditor@company.com
```

Both parties receive a receipt. Neither can deny the record exists.

### Method 3: Export Full Chain

```bash
forge export > chain.json
# Send chain.json to verifier
```

Verifier runs:
```bash
forge verify --file chain.json
```

### Method 4: OpenTimestamps Verification

After ~2 hours (Bitcoin confirmation):

```bash
# Anyone can verify with OTS tools
ots verify proof.ots
```

---

## MCP Server (AI Agent Integration)

Forge integrates with Claude Code and Claude Desktop as an MCP server.

### Claude Code Configuration

Add to project's MCP settings:

```json
{
  "mcpServers": {
    "forge": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/forge/src/mcp/server.js"]
    }
  }
}
```

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "forge": {
      "command": "node",
      "args": ["/path/to/forge/src/mcp/server.js"]
    }
  }
}
```

### MCP Tools (9 total)

| Tool | Description |
|------|-------------|
| `forge_scan` | Enumerate trust assumptions |
| `forge_log` | Record a TrustAtom |
| `forge_verify` | Verify chain integrity |
| `forge_seal` | Seal atoms into Merkle block |
| `forge_anchor` | Submit to Bitcoin via OTS |
| `forge_witness` | Show/create witness |
| `forge_prove` | Generate Merkle proof |
| `forge_status` | Show chain status |
| `forge_export` | Export chain as JSON |

---

## Security Scanner

Forge includes a system scanner to enumerate trust assumptions:

```bash
forge scan
```

Detects:
- Open ports (Redis, databases, management panels)
- SSH configuration (root login, password auth)
- Docker misconfigurations
- Firewall status
- Running processes
- Cron jobs
- Recent logins

Risk levels: 🔴 HIGH, 🟡 MEDIUM, 🔵 LOW, 🟢 INFO

---

## Use Cases

### DevOps Audit Trail

```bash
forge log "deployed app v2.1.0 to production"
forge log "scaled replicas from 3 to 5"
forge log "rolled back to v2.0.9"
forge seal && forge anchor
```

### Compliance Evidence

```bash
forge log "completed security audit - 0 critical issues"
forge log "updated SSL certificates - expires 2027-01-15"
forge witness --bilateral compliance@auditor.com
forge seal && forge anchor
```

### Incident Response

```bash
forge log "detected anomaly in auth service"
forge log "isolated affected nodes"
forge log "patched vulnerability CVE-2024-1234"
forge log "restored service - RCA completed"
forge seal && forge anchor
```

### Configuration Management

```bash
forge scan  # Baseline system state
forge log "configured firewall - allow 80,443 only"
forge log "disabled root SSH login"
forge log "enabled UFW"
forge seal && forge anchor
```

---

## Theory: Trust = Certainty × Existence

Hash alone is NOT trust. Hash is only half:

- **Certainty** (mathematical): SHA-256 hash — deterministic, irreversible
- **Existence** (physical/social): Witness — independent copy that survives deletion

```
Hash without witness → can be silently deleted
Witness without hash → can be forged
Trust = Certainty × Existence
```

The fundamental question: **"What is the smallest thing that, if removed, trust collapses?"**

Answer: A hash that at least one independent party witnessed.

---

## Architecture

```
src/
├── core/
│   ├── trust-pixel.js   (81)   — Hash operations
│   ├── trust-atom.js    (125)  — Atomic state transitions
│   ├── merkle.js        (131)  — Merkle tree, proof generation
│   ├── chain.js         (186)  — Chain manager
│   └── witness.js       (377)  — Witness hierarchy, OTS
├── store/
│   └── store.js         (133)  — JSON persistence (~/.forge/)
├── scanner/
│   └── index.js         (437)  — Trust assumption scanner
├── cli/
│   └── index.js         (547)  — CLI (10 commands)
├── mcp/
│   └── server.js        (534)  — MCP server (9 tools)
└── test.js              (266)  — 27 tests

Total: ~2,800 lines, minimal dependencies
```

---

## Data Storage

All data stored in `~/.forge/`:

```
~/.forge/
├── chain.json      # Atoms and blocks
├── witnesses/      # Bilateral witness receipts
└── ots/            # OpenTimestamps proofs
```

---

## Tests

```bash
node src/test.js
# 27 passed, 0 failed
```

---

## Rust Implementation

A high-performance Rust implementation is in development (private repository).

### Why Rust?

| Aspect | JavaScript | Rust |
|--------|------------|------|
| **Speed** | Interpreted | Native binary |
| **Memory** | GC managed | Zero-cost abstractions |
| **Safety** | Runtime errors | Compile-time guarantees |
| **Deployment** | Requires Node.js | Single binary |

### Implementation Status

| Module | JS | Rust | Status |
|--------|:--:|:----:|--------|
| TrustPixel (hash + witness) | ✅ | ✅ | Cross-validated |
| TrustAtom (state transitions) | ✅ | ✅ | Cross-validated |
| Merkle Tree | ✅ | 🚧 | In progress |
| Chain Manager | ✅ | 🚧 | In progress |
| Store (persistence) | ✅ | ⏳ | Planned |
| Witness (OTS) | ✅ | ⏳ | Planned |
| CLI | ✅ | ⏳ | Planned |
| Scanner | ✅ | ⏳ | Planned |

### Cross-Validation

Rust and JavaScript produce identical outputs:

```
hash("hello") → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

Both implementations pass 20+ cross-validation tests.

---

## Roadmap

- [x] Rust core implementation (Phase 1)
- [ ] Rust Merkle tree and chain (Phase 2)
- [ ] Rust persistence and OTS (Phase 3)
- [ ] Rust CLI (Phase 4)
- [ ] Web dashboard for chain visualization
- [ ] Team/organization support
- [ ] Webhook notifications
- [ ] S3/cloud backup integration
- [ ] Hardware security module (HSM) support

---

## License

MIT

---

## Summary

```
┌────────────────────────────────────────────┐
│  forge log "did something important"       │
│  forge seal                                │
│  forge anchor                              │
│                                            │
│  → Permanent, undeniable, Bitcoin-anchored │
│    proof that it happened.                 │
└────────────────────────────────────────────┘
```
