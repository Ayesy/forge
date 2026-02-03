# FORGE — Trust Chain Protocol v0.2

> Trust = Certainty × Existence

The trust layer for cloud operations and AI agents. Every operation produces a verifiable, undeniable, cryptographically chained fact.

## What's New in v0.2

- **MCP Server** — 9 tools for AI agent integration (Claude Code, Claude Desktop)
- **Witness System** — 4-level trust hierarchy with upgrade path
- **OpenTimestamps** — Anchor Merkle roots to Bitcoin blockchain (free, no API key)
- **27 tests** passing, 2,817 lines, minimal dependencies

## Quick Start

```bash
npm install
node src/cli/index.js help

# Record operations
node src/cli/index.js log "deployed nginx"
node src/cli/index.js log "configured firewall"
node src/cli/index.js verify
node src/cli/index.js seal

# Witness hierarchy
node src/cli/index.js witness                          # Check trust level
node src/cli/index.js witness --bilateral ops@host.com # Share with counterparty
node src/cli/index.js anchor                           # Submit to Bitcoin via OTS
node src/cli/index.js anchor --upgrade                 # Check Bitcoin confirmation
```

## MCP Server (AI Agent Integration)

```bash
# Start MCP server (stdio transport)
node src/mcp/server.js
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
| `forge_scan` | Enumerate trust assumptions (ports, firewall, SSH, Docker, etc.) |
| `forge_log` | Record a TrustAtom (one verifiable state transition) |
| `forge_verify` | Verify chain integrity |
| `forge_seal` | Seal atoms into a Merkle block |
| `forge_anchor` | Submit Merkle root to OTS calendars / check Bitcoin confirmation |
| `forge_witness` | Show witness status / create bilateral witness |
| `forge_prove` | Generate Merkle proof for a specific atom |
| `forge_status` | Show chain status and recent atoms |
| `forge_export` | Export full chain as JSON |

## Witness Hierarchy

```
Level 1: Self       — Only you hold the hash (can be deleted)
Level 2: Bilateral  — Two parties hold it (one can't deny)
Level 3: Public     — OTS calendar attested (independent verification)
Level 4: Anchored   — Bitcoin blockchain (computationally undeletable)
```

The witness system answers: "What is the smallest thing that, if removed, trust collapses?" Answer: A hash that at least one independent party witnessed.

## Architecture (2,817 lines, 10 files)

```
src/core/trust-pixel.js   (81)   — Hash operations, pixel creation
src/core/trust-atom.js    (125)  — Atomic state transitions
src/core/merkle.js        (131)  — Merkle tree, proof generation
src/core/chain.js         (186)  — Chain manager, divergence detection
src/core/witness.js       (377)  — Witness hierarchy, OTS integration
src/store/store.js        (133)  — JSON persistence (~/.forge/)
src/scanner/index.js      (437)  — Trust assumption scanner
src/cli/index.js          (547)  — CLI with 10 commands
src/mcp/server.js         (534)  — MCP server with 9 tools
src/test.js               (266)  — 27 tests
```

## Theory: Trust = Certainty × Existence

Hash alone is NOT trust. Hash is only half:

- **Certainty** (mathematical): SHA-256 hash — deterministic, irreversible
- **Existence** (physical/social): Witness — independent copy that survives deletion

```
Hash without witness → can be silently deleted
Witness without hash → can be forged
Trust = Certainty × Existence
```

## Tests

```bash
node src/test.js
# 27 passed, 0 failed
```

## License

MIT
