# Ozz — HALctf Autonomous Pentesting Agent
# Docker image for DEF CON 34 AI Village HALctf
#
# Build:
#   docker build -t ozz:latest .
#
# Run:
#   docker run --gpus all -e TARGETS="10.0.0.1" ozz:latest

FROM nvidia/cuda:12.4.0-runtime-ubuntu24.04

LABEL maintainer="Ozz <halctf@ozz>"
LABEL description="Ozz — Autonomous Pentesting Agent for HALctf"
LABEL version="0.2.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# System dependencies — COMPLETE pentest arsenal
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    # Pentesting tools — Network scanning
    nmap \
    netcat-openbsd \
    curl \
    wget \
    # Pentesting tools — Web
    nikto \
    whatweb \
    gobuster \
    dirb \
    sqlmap \
    # Pentesting tools — Brute force / Password cracking
    hydra \
    john \
    # Pentesting tools — Forensics / Steganography
    binwalk \
    steghide \
    libimage-exiftool-perl \
    # Pentesting tools — SMB / Windows
    smbclient \
    # Pentesting tools — Crypto
    openssl \
    # Utilities
    jq \
    net-tools \
    dnsutils \
    whois \
    file \
    strings \
    tmux \
    procps \
    iproute2 \
    unzip \
    # Build deps for Python packages
    build-essential \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Remove EXTERNALLY-MANAGED marker
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED

# Python dependencies — PyTorch, vLLM, Transformers, pentest libs
RUN pip3 install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cu124 \
    transformers \
    accelerate \
    vllm \
    fastapi \
    uvicorn \
    pydantic \
    requests \
    pwntools \
    beautifulsoup4 \
    lxml \
    paramiko \
    impacket \
    pyjwt

# Create working directories
RUN mkdir -p /models /app /config /tmp/ozz /tmp/hf_cache

# Copy agent code and scripts
COPY agent/ /app/agent/
COPY scripts/ /app/scripts/
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/scripts/*.sh 2>/dev/null || true

# Bundled wordlists — no network download needed (works in isolated CTF)
RUN mkdir -p /usr/share/wordlists/dirb
COPY wordlists/ /usr/share/wordlists/custom/
RUN if [ -f /usr/share/wordlists/custom/web-common.txt ]; then \
        cp /usr/share/wordlists/custom/web-common.txt /usr/share/wordlists/dirb/common.txt; \
    fi

# Default configuration
ENV MODEL_PATH=/models
ENV MODEL_NAME="Qwen/Qwen2.5-Coder-7B-Instruct"
ENV HF_HOME="/tmp/hf_cache"
ENV VLLM_PORT=8000
ENV GPU_MEMORY_UTILIZATION=0.85
ENV MAX_MODEL_LEN=8192
ENV TENSOR_PARALLEL_SIZE=1
ENV MAX_TOKENS=4096
ENV TEMPERATURE=0.3
ENV TARGETS=""
ENV SCOREBOARD_URL="http://10.0.0.200:9090"

WORKDIR /app

# Healthcheck — works with both vLLM and HF fallback server
HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=5 \
    CMD curl -sf http://localhost:${VLLM_PORT:-8000}/v1/models > /dev/null || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
