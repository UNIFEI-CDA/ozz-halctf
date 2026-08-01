import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from agent.llm import LLM

class TestLLMFallbackMetrics(unittest.TestCase):
    def test_llm_fallback_count_updates_on_fallback(self):
        llm = LLM(model_path="/models")
        llm.api_url = "http://localhost:9999"
        llm.fallback_api_url = "http://localhost:9998"
        llm.max_retries = 1
        llm.retry_backoff = 0

        # Force the request_completion method to simulate fallback success and primary failure.
        def fake_post(url, json, timeout):
            class FakeResponse:
                def __init__(self, status_code, content):
                    self.status_code = status_code
                    self._content = content
                def raise_for_status(self):
                    if self.status_code >= 400:
                        raise requests.HTTPError(f"HTTP {self.status_code}")
                def json(self):
                    return {"choices": [{"message": {"content": "{\"action\": \"shell\", \"action_input\": \"echo hi\"}"}}]}
            if url.startswith("http://localhost:9999"):
                raise requests.ConnectionError("Connection refused")
            return FakeResponse(200, "OK")

        original_post = requests.post
        try:
            requests.post = fake_post
            response = llm.generate("prompt")
        finally:
            requests.post = original_post

        self.assertTrue(llm.last_request_was_fallback)
        self.assertEqual(llm.fallback_count, 1)
        self.assertIn("echo hi", response)

if __name__ == "__main__":
    unittest.main()
