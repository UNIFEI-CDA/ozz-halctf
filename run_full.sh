#!/bin/bash
# ============================================
# 🏴 OZZ — Full Stack (Universe + Agent + LLM)
# Isolated CTF environment — no internet access
# ============================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  🏴 OZZ — FULL STACK LAUNCHER            ║"
echo "  ║  Universe + Agent + LLM                  ║"
echo "  ║  Isolated CTF Network                    ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check GPU
echo -e "${CYAN}Checking GPU...${NC}"
if nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null)
    echo -e "${GREEN}  ✅ GPU found: ${GPU_INFO}${NC}"
    HAS_GPU=true
else
    echo -e "${YELLOW}  ⚠️  No GPU detected. Agent will run with HF Transformers (CPU).${NC}"
    HAS_GPU=false
fi

# Start universe (targets + scoreboard)
echo ""
echo -e "${CYAN}Starting universe (targets + scoreboard)...${NC}"
cd "$SCRIPT_DIR"
docker compose up -d --build target-01 target-02 target-03 target-04 scoreboard 2>&1 | tail -5
sleep 5

# Wait for services
echo -e "${CYAN}Waiting for services...${NC}"
for i in $(seq 1 30); do
    SCOREBOARD_OK=false
    if curl -sf http://localhost:9090/api/score > /dev/null 2>&1; then
        SCOREBOARD_OK=true
    fi
    echo "  [$i/30] Scoreboard=$SCOREBOARD_OK"
    if $SCOREBOARD_OK; then
        break
    fi
    sleep 2
done

echo -e "${GREEN}  ✅ Universe running${NC}"
echo -e "  📊 Scoreboard: http://localhost:9090"
echo -e "  🎯 Targets: 10.0.0.10 (Web) | 10.0.0.20 (SSH/SMB) | 10.0.0.30 (API) | 10.0.0.40 (MySQL)"

# Run agent
echo ""
if [ "$HAS_GPU" = true ]; then
    echo -e "${CYAN}Starting agent with GPU (vLLM)...${NC}"
    cd "$SCRIPT_DIR"
    docker compose --profile agent up --build ozz 2>&1
else
    echo -e "${CYAN}Starting agent (CPU mode — HF Transformers)...${NC}"
    cd "$SCRIPT_DIR"
    docker compose --profile agent up --build ozz 2>&1
fi

echo ""
echo -e "${GREEN}🏴 Done! Check scoreboard: http://localhost:9090${NC}"
echo -e "${CYAN}Final score:${NC}"
curl -s http://localhost:9090/api/score | python3 -m json.tool 2>/dev/null || echo "(scoreboard unavailable)"
