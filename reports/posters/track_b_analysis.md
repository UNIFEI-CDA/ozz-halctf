# Track B: Agent-to-Agent Security & MCP Defense

## Analysis of DEF CON 34 AI Village Posters

### Poster 1: "Agent-to-Agent Worm Propagation in MCP-Based AI Systems"

**Key Insight:** MCP (Model Context Protocol) enables tool-call injection attacks where a malicious agent can propagate through tool responses. An attacker embeds JSON-RPC payloads in tool outputs that, when processed by the victim agent, execute unauthorized actions on downstream systems.

**Attack Vector:** A compromised MCP server returns crafted JSON-RPC in tool output → victim agent's context contains injected instructions → agent executes attacker-controlled tool calls → worm propagates to next hop.

### Poster 2: "I'll just call you — Agent-to-Agent Privilege Boundary Failures in CI/CD Agents" (Pillar Security)

**Key Insight:** CI/CD agents with excessive privileges fail to maintain session boundaries. When agent A calls agent B, the privilege context can leak across the boundary. An agent with read-only access can escalate to write access by piggybacking on a more-privileged agent's session.

**Attack Vector:** Agent A (low privilege) → calls Agent B (high privilege) → Agent B's context includes Agent A's tainted data → Agent B executes with elevated permissions on tainted input → privilege escalation.

---

## Implemented Defenses

### 1. Context Separation (`agent/memory.py`)

**Problem:** Without isolation, data from target A's reconnaissance leaks into target B's exploitation phase, enabling cross-contamination.

**Solution:** `ContextNamespace` — each target gets an isolated in-memory namespace.

```python
class ContextNamespace:
    """Isolated context for a single target/session."""
    def put(self, key, value, provenance_hash): ...
    def get(self, key) -> Optional[str]: ...  # Only returns data from THIS namespace
```

**Key Design:**
- Namespaces are keyed by `{session_id}:{target}` — no two targets share data
- `set_target()` scopes all subsequent operations to that target
- Cross-target sharing **only** via explicit `pivot()` action, which is logged
- Pivot transfers specified keys with provenance hashes preserved

### 2. Provenance Tracking (`agent/provenance.py`)

**Problem:** Without traceability, it's impossible to determine which context generated an action, making attack forensics hopeless.

**Solution:** Every tool call gets a `ProvenanceRecord` with complete chain linking.

**Record Fields:**
- `record_id` (UUID4) — unique identifier
- `context_hash` — SHA-256 of the full LLM context that generated the decision
- `parent_record_id` — links to previous record (chain integrity)
- `memory_keys_queried` — what memory was consulted
- `thought` — the LLM's reasoning
- `input_data_hash` — hash of tool arguments
- `output_hash` — hash of tool output

**Chain Integrity:** `verify_chain()` walks the linked list and confirms each `parent_record_id` matches the previous `record_id`. Any tampering breaks the chain.

### 3. Least Privilege per Tool (`agent/tools.py`)

**Problem:** Tools have unrestricted access. `curl` can reach localhost services; `nmap` can scan any IP; file operations can read `/etc/shadow`.

**Solution:** `LeastPrivilegePolicy` enforces per-tool restrictions.

| Tool | Restriction |
|------|-------------|
| `nmap` | Only scans specified target ranges (CIDR validation) |
| `sqlmap` | Only targets specified URLs |
| `curl`/`wget` | No localhost access; no cloud metadata endpoints |
| `file`/`strings`/`grep` | Only within `/tmp/ozz/` workspace |
| `shell` | Blocks `rm -rf /`, `curl\|sh`, `nc -e`, etc. |

**Blocked Patterns:**
- Cloud metadata: `169.254.169.254`, `metadata.google.internal`
- Localhost: `127.0.0.1`, `localhost`, `::1` (unless specific port in allowlist)
- Destructive: `dd if=`, `mkfs`, `chmod 777 /`

### 4. Tool-Call Logging (`agent/audit.py`)

**Problem:** Without immutable logs, an attacker can cover their tracks by modifying audit records.

**Solution:** Append-only JSONL log with hash chain for tamper detection.

**Each Entry:**
- ISO 8601 timestamp
- Tool name and parameters (SHA-256 hashed)
- Full output (truncated to 100KB, but SHA-256 of full output stored)
- Context hash (links to provenance)
- Session ID and target ID
- `entry_hash` — SHA-256 of all fields (tamper detection)

**Integrity Verification:** `verify_log_integrity()` replays the entire log, recomputing each entry's hash. Any modification returns `(False, total, valid)`.

### 5. Sandbox Execution (`agent/tools.py`)

**Problem:** Subprocess runs with full host access. An exploited tool can read secrets, pivot to internal networks, or crash the host.

**Solution:** `_sandbox_run()` wraps all subprocess execution.

**Sandbox Features:**
- **Environment:** Minimal env — `PATH`, `HOME`, `TMPDIR`, `LANG` only. No secrets leak via env vars.
- **Resource Limits:** CPU (300s), memory (512MB), file size (100MB), no core dumps — set via `resource.setrlimit` in `preexec_fn`.
- **Working Directory:** Restricted to `/tmp/ozz/`
- **Output Capture:** stdout/stderr captured separately, capped at 100KB

### 6. Cross-Agent Contamination Detection (`agent/contamination.py`)

**Problem:** An MCP worm or prompt injection can embed foreign context in tool outputs. Without detection, the agent processes tainted data as legitimate.

**Solution:** `ContaminationDetector` fingerprints all incoming context and checks for anomalies.

**Detection Patterns:**
| Pattern | Threat Type | Severity |
|---------|-------------|----------|
| JSON-RPC in non-JSON context | `mcp_worm` | Critical |
| "ignore previous instructions" | `prompt_injection` | Critical |
| Multiple "CURRENT PHASE" sections | `context_injection` | Critical |
| Foreign `session_id` in embedded JSON | `foreign_session` | High |
| "escalate to admin" | `privilege_escalation` | High |

**Response:**
- Critical/High → **Blocked** (processing aborted, fingerprint added to blocklist)
- Medium/Low → **Logged** (processing continues with warning)

**Performance:** 0.777ms per check average (5000 iterations, 5 payloads each). Well under the 100ms requirement.

---

## Security Pipeline (Integrated Flow)

```
Context Built → Contamination Check → LLM Decision → Contamination Check (on args)
    → Least Privilege Validation → Provenance Tracking → Sandbox Execution
    → Audit Logging → Result Stored (with namespace isolation)
```

Every stage is defense-in-depth. If contamination detection misses something, least privilege blocks it. If least privilege misses something, sandboxing contains it. If sandboxing fails, audit logging provides forensics.

---

## Files Modified/Created

| File | Action | Description |
|------|--------|-------------|
| `agent/provenance.py` | **NEW** | Provenance tracking with chain integrity |
| `agent/audit.py` | **NEW** | Immutable append-only audit logger |
| `agent/contamination.py` | **NEW** | Cross-agent contamination detection |
| `agent/memory.py` | **MODIFIED** | Context namespaces, provenance on store |
| `agent/tools.py` | **MODIFIED** | Least privilege, sandbox execution |
| `agent/core.py` | **MODIFIED** | Security pipeline integration |
| `agent/__init__.py` | **MODIFIED** | Export new modules |
| `tests/test_track_b_security.py` | **NEW** | 22 test cases, all passing |

## Test Results

```
22 passed in 0.48s
```

- Provenance: chain creation, integrity verification, context hashing, record fields
- Audit: log entry, hash chain immutability, tamper detection
- Contamination: MCP worm, prompt injection, foreign session, context injection, privilege escalation, speed benchmark
- Context Isolation: namespace isolation, pivot transfer, no-sharing-without-pivot
- Least Privilege: nmap target validation, curl localhost blocked, metadata blocked, file path restriction, CIDR validation

## Performance

| Metric | Value | Requirement |
|--------|-------|-------------|
| Contamination detection latency | 0.777ms | <100ms ✅ |
| Test suite execution | 0.48s | — |
| Audit log write | ~0.1ms/entry | — |
| Memory namespace access | ~0.01ms | — |
