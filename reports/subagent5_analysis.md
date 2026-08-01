# Subagent 5 Analysis: Kaggle Notebook Pipeline Fix

## 1. Current Notebook Issues (Detailed)

### 1.1 `ozz-raptor-v6.ipynb` — CRITICAL ISSUES

| Issue | Severity | Detail |
|-------|----------|--------|
| **Wrong model** | CRITICAL | Uses `Qwen/Qwen2.5-Coder-0.5B-Instruct` (500M params) instead of 7B. The 0.5B model cannot produce coherent JSON tool calls or follow the agent's complex system prompt. |
| **Semgrep ≠ Agent** | CRITICAL | Cell 5 runs `semgrep --config auto` on static source files. This is code analysis, NOT runtime pentesting. The agent's purpose is to interact with *running* services. |
| **Payloads never executed** | CRITICAL | Cell 6 asks the LLM to generate curl payloads from Semgrep findings, but NEVER runs them. The payloads are just printed and saved to a file. |
| **No agent loop** | CRITICAL | The entire notebook is: install → clone → start LLM → run Semgrep → generate text → report. The actual `python -m agent` is never invoked. |
| **No running targets** | CRITICAL | No CTF targets are started. The notebook scans static source code directories, not live services. |
| **Custom LLM server** | HIGH | Uses a hand-rolled FastAPI server instead of vLLM. This server lacks proper sampling, token limits, and chat template handling that vLLM provides. |
| **Clones raptor repo** | LOW | Clones `gadievron/raptor` which is unnecessary for the agent. Adds download time. |

### 1.2 `ozz_kaggle.ipynb` — SIGNIFICANT ISSUES

| Issue | Severity | Detail |
|-------|----------|--------|
| **Wrong model (3B)** | HIGH | Uses `Qwen/Qwen2.5-Coder-3B-Instruct` instead of 7B. Config says `Qwen/Qwen2.5-Coder-7B-Instruct`. |
| **External sandbox dependency** | HIGH | Clones `kimdane/ctf` from GitHub for the CTF sandbox. This repo may not exist, may change, and adds external dependency. Should use the built-in `universe/` targets. |
| **No requirements.txt** | MEDIUM | Runs `pip install -r requirements.txt` but no such file exists in the repo. |
| **Custom LLM server** | MEDIUM | Same hand-rolled FastAPI server issue. Reports `Qwen/Qwen2.5-Coder-7B-Instruct` in `/v1/models` response but actually loads 3B. |
| **Agent target mismatch** | MEDIUM | Agent is run with `http://localhost:3000` but the CTF sandbox (if it loads) may not have the expected vulnerability structure. |
| **No vLLM** | MEDIUM | Doesn't use vLLM at all. The agent's `LLM` class connects to `localhost:8000/v1` and expects OpenAI-compatible API, which the custom server approximates but lacks vLLM's robustness. |
| **MAX_ITERATIONS=50** | LOW | Limits to 50 iterations, which may not be enough for multi-target exploration. |

### 1.3 `ozz-raptor-kaggle.ipynb` — SIMILAR ISSUES

Same pattern: installs Semgrep, clones raptor, runs static analysis instead of the agent.

### 1.4 `kernel-metadata.json` — STALE

Points to `ozz_kaggle.ipynb` as the code file. Needs updating for v11.

---

## 2. Architecture of the Correct Pipeline

### 2.1 What the Agent Actually Does

The `OzzAgent` (in `agent/core.py`) implements a **ReAct loop**:

```
┌─────────────────────────────────────────────────────┐
│                    OZZ AGENT LOOP                    │
│                                                      │
│  1. OBSERVE  → Build context from history + findings │
│  2. THINK    → LLM generates JSON decision           │
│  3. ACT      → Execute tool (nmap, curl, sqlmap...)  │
│  4. REMEMBER → Store observation in memory            │
│  5. CHECK    → Scan output for flag patterns          │
│  6. UPDATE   → Transition state machine               │
│                                                      │
│  States: RECON → ENUMERATION → EXPLOITATION → PIVOT  │
└─────────────────────────────────────────────────────┘
```

The agent requires:
- **Running LLM server** at `localhost:8000` (OpenAI-compatible API)
- **Running CTF targets** accessible via network
- **Pentesting tools** installed: nmap, curl, sqlmap, hydra, gobuster, etc.
- **Environment variables**: `TARGETS`, `MODEL_NAME`, `VLLM_PORT`, etc.

### 2.2 Correct Pipeline Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    KAGGLE NOTEBOOK v11                        │
│                                                              │
│  Cell 1: Install deps (vllm, agent deps, nmap, curl, etc.)  │
│  Cell 2: Clone repo                                          │
│  Cell 3: Start vLLM server (Qwen2.5-Coder-7B-Instruct)     │
│  Cell 4: Start CTF target servers (Python HTTP)              │
│  Cell 5: Health check (LLM + targets)                        │
│  Cell 6: Run `python -m agent` (THE REAL AGENT LOOP)        │
│  Cell 7: Collect results + generate report                   │
│                                                              │
│  ┌─────────┐    ┌──────────┐    ┌──────────────────┐        │
│  │  vLLM   │◄───│  OZZ     │───►│  CTF Targets     │        │
│  │  7B     │    │  Agent   │    │  (localhost:8081  │        │
│  │ :8000   │    │  Loop    │    │   localhost:5000) │        │
│  └─────────┘    └──────────┘    └──────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 Why vLLM Instead of Custom Server

| Feature | Custom FastAPI | vLLM |
|---------|---------------|------|
| Memory efficiency | Loads full model in RAM | PagedAttention, 85% GPU util |
| Sampling quality | Basic generate() | Proper sampling with temperature/top-p |
| Chat template | Manual apply | Built-in, model-specific |
| Concurrent requests | Blocks on single GPU | Continuous batching |
| Token management | Fixed 512 max | Configurable, up to 8192 |
| Reliability | Fragile | Production-grade |

### 2.4 Target Simulation Strategy

Since Kaggle doesn't support Docker, we create **lightweight Python HTTP servers** that replicate the vulnerability patterns from `universe/target-01` and `universe/target-03`:

- **Target-01 (port 8081)**: PHP-like web app with SQLi on login, LFI on reports, flag at `/var/secret/flag.txt` (simulated via `/flag.txt` endpoint)
- **Target-03 (port 5000)**: Flask API with SSTI on `/render`, JWT bypass on `/admin`, flag at `/admin/secrets`

These servers respond to the same endpoints and exploit paths as the Docker targets, so the agent's tool calls (curl, nmap) work identically.

---

## 3. New Notebook Implementation

### 3.1 Key Design Decisions

1. **vLLM with Qwen2.5-Coder-7B-Instruct**: Uses `python -m vllm.entrypoints.openai.api_server` for proper model serving
2. **Real agent loop**: `python -m agent` with proper `TARGETS` env var
3. **Embedded target servers**: Python HTTP servers in the notebook that mimic universe targets
4. **apt-get for tools**: Install nmap, curl, and other pentesting tools available on Kaggle
5. **No Semgrep**: Static analysis is never used as a substitute
6. **No payload generation without execution**: Every payload the agent generates is executed via its tool registry
7. **Report generation**: Captures flags, techniques, timing, and agent metrics

### 3.2 Timing Budget (30 min target)

| Phase | Estimated Time |
|-------|---------------|
| pip install (vllm, etc.) | ~4 min |
| apt-get (nmap, etc.) | ~1 min |
| git clone | ~30 sec |
| vLLM model download + load | ~8 min |
| Target server startup | ~5 sec |
| Health checks | ~1 min |
| Agent execution (100 iter) | ~12 min |
| Report generation | ~5 sec |
| **Total** | **~27 min** |

### 3.3 Model Memory on T4 (16GB VRAM)

- Qwen2.5-Coder-7B-Instruct in fp16: ~14GB
- vLLM with `gpu-memory-utilization=0.85`: uses ~13.6GB
- Remaining ~2.4GB for KV cache → supports `max-model-len=4096`
- Sufficient for the agent's context window needs

### 3.4 Files Created

- `scripts/ozz_qwen7b_v11.ipynb` — The new notebook
- `scripts/kernel-metadata-v11.json` — Kaggle kernel metadata
- `reports/subagent5_analysis.md` — This analysis document
