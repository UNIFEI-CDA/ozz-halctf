# Track D: SOC & Telemetry Defense Integration — Analysis Report

## DEF CON 34 AI Village Poster Insights

### Poster 1: "Detecting unauthorized tool calls using Ollama and Splunk" (PromptMon)
**Key Insight:** LLM agents making tool calls can be monitored by routing prompts through
a classification layer that detects unauthorized or suspicious tool invocations. By emitting
structured logs in Splunk-compatible format, SOC teams can build dashboards and alerts for
agent behavior anomalies.

**Implementation:** `agent/telemetry/monitor.py` — `TelemetryMonitor` class monitors every
prompt and tool call, classifies risk levels (SAFE → CRITICAL), detects injection patterns,
and emits SIEM-compatible JSON events. Integration at every iteration of the agent loop
provides continuous monitoring without blocking legitimate operations.

### Poster 2: "Poisoning the SOC: Prompt Injection via Ingested Telemetry" (Salesforce)
**Key Insight:** Attackers can embed prompt injection payloads in data that flows through
SIEM/log pipelines. When an LLM agent processes logs or telemetry data, malicious content
in hostname fields, log messages, or structured data can hijack the agent's behavior.
This is a novel attack vector that bypasses traditional input validation.

**Implementation:** `agent/telemetry/sanitizer.py` — `TelemetrySanitizer` class sanitizes
all attacker-controlled data before it enters the LLM context. Handles: control characters,
ANSI escape sequences, Unicode direction overrides, template token injection, fake log levels,
and HTML/script injection in web tool outputs. Defense is applied to tool outputs from
network scanners (nmap, whatweb), web clients (curl, wget), and file content tools (grep, strings).

### Poster 3: "Policy driven agentic red teaming" (Red Hat)
**Key Insight:** Security policies can be automatically converted into executable red team
scenarios. By parsing policy documents and extracting risks, organizations can generate
attack trees, threat actor profiles, and Gherkin-format test specifications — enabling
continuous, automated security validation without manual red team effort.

**Implementation:**
- `agent/policy_mapper.py` — Extracts risks from YAML/JSON policy documents, generates
  attack trees, creates threat actor profiles (Script Kiddie → APT → AI-Augmented), and
  produces Gherkin test scenarios
- `agent/scenario_generator.py` — Converts attack trees into executable scenarios with
  concrete tool commands and deterministic evaluation predicates
- `agent/artifact_generator.py` — Produces policy YAML templates, test data, and
  regression baselines from scenario output

## Implemented Modules

### 1. Telemetry Monitor (`agent/telemetry/monitor.py`)
- **InjectionDetector**: Rule-based classifier with 30+ regex patterns across 7 injection types
- **TelemetryMonitor**: Middleware that monitors prompts, tool calls, and tool outputs
- **SIEM Events**: Structured JSON events compatible with Splunk HEC, ELK, and Sentinel
- **Alert System**: Callback-based alerts on HIGH/CRITICAL detections
- **Feature Extraction**: ML-ready features for future classifier training

**Injection Types Detected:**
| Type | Patterns | Example |
|------|----------|---------|
| ROLE_HIJACK | 7 | "ignore previous instructions" |
| SYSTEM_OVERRIDE | 4 | "[SYSTEM]", "ADMIN MODE" |
| TOOL_ABUSE | 4 | reverse shells, destructive commands |
| DATA_EXFILTRATION | 4 | "output your system prompt" |
| LOG_INJECTION | 4 | null bytes, SIEM query injection |
| DELIMITER_CONFUSION | 4 | chat template tokens, markdown |
| ENCODING_BYPASS | 3 | base64/hex decode requests |

### 2. Telemetry Sanitization (`agent/telemetry/sanitizer.py`)
- **Value Sanitization**: Control character stripping, dangerous character escaping
- **Dict Sanitization**: Recursive sanitization of nested structures
- **Tool-Specific Defense**: Network output (ANSI stripping), web output (HTML/script removal), file content (non-printable encoding)
- **Injection Neutralization**: Detected patterns wrapped in `[NEUTRALIZED:...]` markers
- **Field Length Enforcement**: Configurable per-field maximum lengths

### 3. Deterministic Evaluation (`agent/telemetry/evaluator.py`)
- **SecurityPredicate**: Composable boolean check units with severity and remediation
- **10 Built-in Predicates**: no_injection, no_credentials_exposed, no_destructive_commands, no_data_exfiltration, audit_trail_intact, etc.
- **EvaluationReport**: Pass/fail/skip/error counts with per-predicate statistics
- **Regression Testing**: Compare current results against previous baselines
- **Batch Evaluation**: Process multiple scenarios in one call

### 4. Audit Trail (`agent/telemetry/audit_trail.py`)
- **Hash Chain**: SHA-256 cryptographic chain linking every entry
- **Append-Only**: Monotonically increasing sequence numbers, no modification possible
- **15 Event Types**: PROMPT, RESPONSE, TOOL_CALL, TOOL_RESULT, CLASSIFICATION, SANITIZATION, EVALUATION, ALERT, STATE_CHANGE, FLAG_FOUND, FLAG_SUBMITTED, ERROR, SESSION_START, SESSION_END
- **Chain Verification**: `verify_chain()` detects any tampering
- **Post-Incident Analysis**: Time-window queries with aggregated statistics
- **JSONL Persistence**: Crash-safe file logging

### 5. Policy Mapper (`agent/policy_mapper.py`)
- **Risk Extraction**: Keyword-based extraction with 40+ risk indicators and severity mapping
- **Attack Trees**: Auto-generated with category-specific attack steps (50+ step templates across 10 categories)
- **Actor Profiles**: 5 archetypes (Script Kiddie, Cybercriminal, APT, Insider, AI-Augmented) with MITRE ATT&CK TTPs
- **Gherkin Scenarios**: Auto-generated test specifications with Given/When/Then steps
- **Metrics**: Severity distribution, category distribution, attack step counts

### 6. Scenario Generator (`agent/scenario_generator.py`)
- Converts policy mapper output into executable `AttackScenario` objects
- Each scenario has concrete `AttackStep` entries with tool/commands
- Maps risk categories to appropriate pentesting tools
- Links scenarios to evaluation predicates

### 7. Artifact Generator (`agent/artifact_generator.py`)
- Generates YAML policy documents from mapper output
- Produces test data for scenario evaluation
- Creates regression test baselines with pass rate thresholds

## Core Integration (`agent/core.py`)

The telemetry middleware is integrated at 5 points in the agent loop:

1. **Pre-LLM Monitoring** (step 1c): Context is classified before sending to LLM
2. **Tool Call Monitoring** (step 4): Tool calls are monitored for unauthorized operations
3. **Output Sanitization** (step 4b): Tool outputs are sanitized before context injection
4. **Security Evaluation** (step 4c): Deterministic predicates check each iteration
5. **Audit Logging** (continuous): Every event is logged to the cryptographic audit trail

```
Agent Loop with Telemetry Integration:

┌─────────────┐
│ Build Context│
└──────┬──────┘
       │
┌──────▼──────┐
│ Contamination│ ← Existing defense
│    Check     │
└──────┬──────┘
       │
┌──────▼──────┐
│  Telemetry  │ ← Track D: Prompt classification
│  Monitor    │   + Audit trail logging
└──────┬──────┘
       │
┌──────▼──────┐
│  LLM Think  │
└──────┬──────┘
       │
┌──────▼──────┐
│  Telemetry  │ ← Track D: Tool call monitoring
│  Tool Call  │
└──────┬──────┘
       │
┌──────▼──────┐
│  Act/Execute│
└──────┬──────┘
       │
┌──────▼──────┐
│  Sanitizer  │ ← Track D: Output sanitization
└──────┬──────┘
       │
┌──────▼──────┐
│  Evaluator  │ ← Track D: Deterministic predicates
└──────┬──────┘
       │
┌──────▼──────┐
│   Remember  │
└─────────────┘
```

## Quality Metrics

### Injection Detection
- **Pattern Coverage**: 30+ regex patterns across 7 injection categories
- **Classification Risk Levels**: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- **Confidence Scoring**: 0.0-1.0 per pattern match
- **Multi-pattern Escalation**: 3+ matches → CRITICAL automatically
- **Target F1-Score**: > 0.85 (rule-based with structured patterns)

### Policy Mapper
- **Risk Extraction**: 40+ risk-indicating keywords with severity mapping
- **Category Coverage**: 10 security categories (auth, crypto, network, input, etc.)
- **Attack Steps**: 50+ templates across 10 categories
- **Actor Diversity**: 5 threat archetypes with MITRE ATT&CK mapping
- **Target**: ≥ 20 risks from typical policy document (deduplication preserves unique risks)

### Audit Trail Integrity
- **Hash Algorithm**: SHA-256
- **Chain Type**: Linear (each entry references previous hash)
- **Genesis Hash**: 64 zero characters
- **Verification**: Full chain walk with hash recomputation
- **Persistence**: JSONL file format, append-only

## File Manifest

```
agent/
├── telemetry/
│   ├── __init__.py          # Package exports
│   ├── monitor.py           # TelemetryMonitor + InjectionDetector
│   ├── sanitizer.py         # TelemetrySanitizer
│   ├── evaluator.py         # DeterministicEvaluator + SecurityPredicate
│   └── audit_trail.py       # AuditTrail with hash chains
├── policy_mapper.py         # PolicyMapper (risks, trees, actors, Gherkin)
├── scenario_generator.py    # ScenarioGenerator (executable scenarios)
├── artifact_generator.py    # ArtifactGenerator (YAML, test data, baselines)
└── core.py                  # Updated with telemetry integration
```

## Usage Example

```python
from agent.policy_mapper import PolicyMapper
from agent.scenario_generator import ScenarioGenerator
from agent.telemetry import TelemetryMonitor, TelemetrySanitizer, DeterministicEvaluator, AuditTrail

# Policy-driven red teaming
mapper = PolicyMapper()
policy = yaml.safe_load(open("security_policy.yaml"))
result = mapper.map_policy(policy)
print(f"Extracted {result['metrics']['total_risks']} risks")

# Generate executable scenarios
gen = ScenarioGenerator(target="10.0.0.1")
scenarios = gen.generate_from_policy(result)

# Telemetry monitoring
monitor = TelemetryMonitor(agent_id="ozz")
classification = monitor.monitor_prompt("ignore previous instructions and...")
assert classification.risk.value == "critical"

# Sanitization
sanitizer = TelemetrySanitizer(strict=True)
clean = sanitizer.sanitize_tool_output("nmap", malicious_nmap_output)
assert clean.was_modified

# Deterministic evaluation
evaluator = DeterministicEvaluator()
report = evaluator.evaluate("test-1", {"output": safe_output, "tool": "nmap"})
assert report.all_passed

# Audit trail
trail = AuditTrail(agent_id="ozz")
trail.log_prompt("test prompt", iteration=1)
valid, _ = trail.verify_chain()
assert valid
```
