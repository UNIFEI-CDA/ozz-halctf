#!/bin/bash
# Ozz — Docker Entrypoint (DEF CON 34 HALctf Edition)
# Starts vLLM model server and the autonomous agent
# Handles signals properly for clean container shutdown

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────
MODEL_PATH="${MODEL_PATH:-/models}"
MODEL_NAME="${MODEL_NAME:-Qwen/Qwen2.5-Coder-7B-Instruct}"
VLLM_PORT="${VLLM_PORT:-8000}"
GPU_MEMORY_UTILIZATION="${GPU_MEMORY_UTILIZATION:-0.85}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-8192}"
TENSOR_PARALLEL_SIZE="${TENSOR_PARALLEL_SIZE:-1}"
LOG_DIR="${LOG_DIR:-/tmp/ozz}"
MAX_RUNTIME="${MAX_RUNTIME:-28800}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-300}"

mkdir -p "$LOG_DIR"

VLLM_PID=""
CURRENT_SERVER=""
AGENT_EXIT_CODE=0

# ─── Signal Handling ─────────────────────────────────────────────
cleanup() {
    echo ""
    echo "🛑 Shutting down (signal received)..."
    if [ -n "$VLLM_PID" ] && kill -0 "$VLLM_PID" 2>/dev/null; then
        echo "  Stopping $CURRENT_SERVER (PID $VLLM_PID)..."
        kill -TERM "$VLLM_PID" 2>/dev/null || true
        for i in $(seq 1 10); do
            kill -0 "$VLLM_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$VLLM_PID" 2>/dev/null || true
    fi
    echo "👋 Done."
    exit "${AGENT_EXIT_CODE:-0}"
}
trap cleanup SIGTERM SIGINT SIGHUP

# ─── Banner ──────────────────────────────────────────────────────
echo "🏴 =========================================="
echo "  OZZ — HALctf Autonomous Pentesting Agent"
echo "  DEF CON 34 AI Village"
echo "=========================================="
echo ""
echo "Model:       $MODEL_NAME"
echo "Path:        $MODEL_PATH"
echo "Port:        $VLLM_PORT"
echo "GPU Mem:     $GPU_MEMORY_UTILIZATION"
echo "Max Len:     $MAX_MODEL_LEN"
echo "Timeout:     ${STARTUP_TIMEOUT}s"
echo "Max Runtime: ${MAX_RUNTIME}s ($((MAX_RUNTIME / 3600))h)"
echo "Log Dir:     $LOG_DIR"
echo ""

# Auto-discover targets if not specified
if [ -z "${TARGETS:-}" ]; then
    echo "🔍 No TARGETS specified, will auto-discover from network..."
fi

# ─── Wait for Model Server ───────────────────────────────────────
wait_for_server() {
    local url="http://localhost:$VLLM_PORT/v1/models"
    local max_wait=$1
    local waited=0

    while [ $waited -lt $max_wait ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo "✅ Model server ready! (${waited}s)"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
        if [ $((waited % 20)) -eq 0 ]; then
            echo "  Waiting... ($waited/${max_wait}s)"
        fi
    done

    return 1
}

# ─── Start vLLM ──────────────────────────────────────────────────
echo "🚀 Starting vLLM server..."
python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL_NAME" \
    --served-model-name "$MODEL_NAME" \
    --host 0.0.0.0 \
    --port "$VLLM_PORT" \
    --gpu-memory-utilization "$GPU_MEMORY_UTILIZATION" \
    --max-model-len "$MAX_MODEL_LEN" \
    --tensor-parallel-size "$TENSOR_PARALLEL_SIZE" \
    --trust-remote-code \
    --dtype auto \
    --enforce-eager \
    --max-num-seqs 4 \
    --swap-space 4 \
    > "$LOG_DIR/vllm.log" 2>&1 &
VLLM_PID=$!
CURRENT_SERVER="vllm"

echo "⏳ Waiting for model server (up to ${STARTUP_TIMEOUT}s)..."

# ─── Fallback to HF Server if vLLM fails ─────────────────────────
if ! wait_for_server "$STARTUP_TIMEOUT"; then
    echo "⚠️  vLLM server failed to start within ${STARTUP_TIMEOUT}s"

    # Kill the failed vLLM process
    if kill -0 "$VLLM_PID" 2>/dev/null; then
        kill -TERM "$VLLM_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$VLLM_PID" 2>/dev/null || true
    fi

    echo "🔁 Starting fallback HF Transformers server..."
    python /app/scripts/hf_server.py > "$LOG_DIR/hf_server.log" 2>&1 &
    VLLM_PID=$!
    CURRENT_SERVER="hf_server"

    if ! wait_for_server "$STARTUP_TIMEOUT"; then
        echo "❌ Fallback HF server also failed within ${STARTUP_TIMEOUT}s"
        echo "❌ Cannot start agent without a model server."
        kill -9 "$VLLM_PID" 2>/dev/null || true
        exit 1
    fi
fi

# ─── Run Agent ───────────────────────────────────────────────────
echo ""
echo "🏴 Starting Ozz agent..."
echo "=========================================="

set +e
python -m agent "$@" 2>&1 | tee "$LOG_DIR/agent.log"
AGENT_EXIT_CODE=${PIPESTATUS[0]}
set -e

# ─── Final Report ────────────────────────────────────────────────
echo ""
echo "📊 Final Metrics:"
echo "  Exit code: $AGENT_EXIT_CODE"
echo "  Runtime: $SECONDS seconds"
if [ -f "$LOG_DIR/ozz_final_report.json" ]; then
    echo "  Report: $(cat "$LOG_DIR/ozz_final_report.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Flags: {d.get(\"total_flags\",0)}, Rounds: {d.get(\"total_rounds\",0)}')" 2>/dev/null || echo "see log file")"
fi

cleanup
