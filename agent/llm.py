"""
Ozz — LLM Interface
Connects to local vLLM server or llama.cpp server.
"""

import logging
import json
import os
import time
import requests
from typing import Optional

logger = logging.getLogger("ozz.llm")

# Default model - Qwen 2.5 Coder 7B
DEFAULT_MODEL = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-Coder-7B-Instruct")


class LLM:
    """Local LLM interface using vLLM OpenAI-compatible API."""

    # Task-adaptive temperature profiles
    TEMP_REASONING = 0.2    # Focused decisions: tool selection, phase transitions
    TEMP_EXPLOIT = 0.7      # Creative: payload generation, novel attack vectors
    TEMP_DEFAULT = 0.3      # General purpose fallback

    def __init__(self, model_path: str = "/models", port: int = 8000):
        self.model_path = model_path
        self.port = port
        self.api_url = f"http://localhost:{port}/v1"
        self.fallback_api_url = os.environ.get("FALLBACK_API_URL")
        self.model_name = os.environ.get("MODEL_NAME", DEFAULT_MODEL)
        self.max_tokens = int(os.environ.get("MAX_TOKENS", "4096"))
        self.temperature = float(os.environ.get("TEMPERATURE", "0.3"))
        self.max_retries = int(os.environ.get("LLM_MAX_RETRIES", "3"))
        self.retry_backoff = float(os.environ.get("LLM_RETRY_BACKOFF", "2"))
        self.fallback_count = 0
        self.last_request_was_fallback = False
        self._verify_connection()

    def _verify_connection(self):
        """Verify the LLM server is running."""
        try:
            resp = requests.get(f"{self.api_url}/models", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("data", [])
                if models:
                    self.model_name = models[0].get("id", self.model_name)
                    logger.info(f"✅ LLM server connected. Model: {self.model_name}")
                else:
                    logger.warning("LLM server running but no models loaded")
            else:
                logger.warning(f"LLM server returned status {resp.status_code}")
        except requests.ConnectionError:
            logger.warning(f"❌ Cannot connect to LLM server at {self.api_url}. Will continue and retry on demand.")
            logger.info("Make sure vLLM is running: python -m vllm.entrypoints.openai.api_server")

    def generate(self, prompt: str, system: Optional[str] = None, temperature: Optional[float] = None) -> str:
        """Generate a response from the LLM.

        Args:
            prompt: User prompt
            system: Optional system prompt
            temperature: Override temperature. None uses self.temperature.
                        Use TEMP_REASONING (0.2) for decisions, TEMP_EXPLOIT (0.7) for payloads.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        temp = temperature if temperature is not None else self.temperature

        def request_completion(api_url: str) -> str:
            for attempt in range(1, self.max_retries + 1):
                try:
                    resp = requests.post(
                        f"{api_url}/chat/completions",
                        json={
                            "model": self.model_name,
                            "messages": messages,
                            "max_tokens": self.max_tokens,
                            "temperature": temp,
                            "stop": ["---"],
                        },
                        timeout=120,
                    )
                    if resp.status_code >= 500:
                        raise requests.HTTPError(f"Server error {resp.status_code}: {resp.text}")
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return content.strip()
                except requests.RequestException as e:
                    logger.error(f"LLM generation error on {api_url} (attempt {attempt}/{self.max_retries}): {e}")
                    if attempt == self.max_retries:
                        break
                    time.sleep(self.retry_backoff)
                except (ValueError, KeyError) as e:
                    logger.error(f"LLM response parse error: {e}")
                    return ""
            return ""

        response = request_completion(self.api_url)
        if not response and self.fallback_api_url:
            logger.warning(f"Primary LLM endpoint failed, trying fallback at {self.fallback_api_url}")
            response = request_completion(self.fallback_api_url)
            if response:
                self.last_request_was_fallback = True
                self.fallback_count += 1

        return response

    def generate_json(self, prompt: str, system: Optional[str] = None, temperature: Optional[float] = None) -> Optional[dict]:
        """Generate and parse JSON response with robust extractions for Qwen 2.5 Coder."""
        response = self.generate(prompt, system, temperature=temperature)
        if not response:
            return None
            
        try:
            # 1. Tentar parse direto do texto limpo
            cleaned = response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # 2. Extração via Regex buscando o bloco JSON delimitado por chaves {}
            import re
            match = re.search(r"\{.*\}", response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
            logger.warning(f"Failed to parse JSON from LLM response: {response[:200]}")
            return None
