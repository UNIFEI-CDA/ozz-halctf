"""
Tests for LLM JSON parsing, edge cases, and fallback behavior.
"""
import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.llm import LLM


class TestLLMGenerateJson(unittest.TestCase):
    """Tests for LLM.generate_json() robust JSON extraction."""

    def _make_llm(self):
        """Create an LLM instance with mocked connection."""
        with patch.object(LLM, '_verify_connection'):
            llm = LLM.__new__(LLM)
            llm.model_path = "/models"
            llm.port = 8000
            llm.api_url = "http://localhost:8000/v1"
            llm.fallback_api_url = None
            llm.model_name = "test-model"
            llm.max_tokens = 4096
            llm.temperature = 0.3
            llm.max_retries = 1
            llm.retry_backoff = 0
            llm.fallback_count = 0
            llm.last_request_was_fallback = False
            return llm

    def test_parse_clean_json(self):
        """Should parse clean JSON response."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='{"action": "nmap", "action_input": "10.0.0.1"}'):
            result = llm.generate_json("test prompt")
        self.assertEqual(result["action"], "nmap")
        self.assertEqual(result["action_input"], "10.0.0.1")

    def test_parse_json_with_markdown_wrapper(self):
        """Should strip ```json ... ``` wrappers."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='```json\n{"action": "curl", "action_input": "http://target"}\n```'):
            result = llm.generate_json("test prompt")
        self.assertEqual(result["action"], "curl")

    def test_parse_json_with_plain_markdown_wrapper(self):
        """Should strip ``` ... ``` wrappers (no json tag)."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='```\n{"action": "shell", "action_input": "whoami"}\n```'):
            result = llm.generate_json("test prompt")
        self.assertEqual(result["action"], "shell")

    def test_parse_json_embedded_in_text(self):
        """Should extract JSON from surrounding text via regex."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='Here is my decision:\n{"action": "grep", "action_input": "flag /tmp"}\nDone.'):
            result = llm.generate_json("test prompt")
        self.assertEqual(result["action"], "grep")

    def test_returns_none_on_empty_response(self):
        """Should return None for empty LLM response."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value=''):
            result = llm.generate_json("test prompt")
        self.assertIsNone(result)

    def test_returns_none_on_non_json_response(self):
        """Should return None when response has no parseable JSON."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='I am sorry, I cannot help with that.'):
            result = llm.generate_json("test prompt")
        self.assertIsNone(result)

    def test_returns_none_on_malformed_json(self):
        """Should return None for malformed JSON."""
        llm = self._make_llm()
        with patch.object(llm, 'generate', return_value='{action: broken, missing: quotes}'):
            result = llm.generate_json("test prompt")
        self.assertIsNone(result)

    def test_parse_json_with_thought_and_plan_update(self):
        """Should parse full agent decision JSON with all fields."""
        llm = self._make_llm()
        decision = {
            "thought": "I should scan the target",
            "action": "nmap",
            "action_input": "-sV 10.0.0.1",
            "plan_update": "Starting recon"
        }
        with patch.object(llm, 'generate', return_value=json.dumps(decision)):
            result = llm.generate_json("test prompt")
        self.assertEqual(result["thought"], "I should scan the target")
        self.assertEqual(result["action"], "nmap")
        self.assertEqual(result["plan_update"], "Starting recon")


class TestLLMFallback(unittest.TestCase):
    """Tests for LLM fallback mechanism."""

    def _make_llm(self):
        with patch.object(LLM, '_verify_connection'):
            llm = LLM.__new__(LLM)
            llm.model_path = "/models"
            llm.port = 8000
            llm.api_url = "http://localhost:9999"
            llm.fallback_api_url = "http://localhost:9998"
            llm.model_name = "test-model"
            llm.max_tokens = 4096
            llm.temperature = 0.3
            llm.max_retries = 1
            llm.retry_backoff = 0
            llm.fallback_count = 0
            llm.last_request_was_fallback = False
            return llm

    def test_fallback_used_when_primary_fails(self):
        """Should use fallback URL when primary is unreachable."""
        import requests as req_module

        llm = self._make_llm()

        def fake_post(url, json, timeout):
            class FakeResp:
                status_code = 200
                def raise_for_status(self):
                    pass
                def json(self):
                    return {"choices": [{"message": {"content": '{"action": "test"}'}}]}
            if "9999" in url:
                raise req_module.ConnectionError("refused")
            return FakeResp()

        with patch.object(req_module, 'post', side_effect=fake_post):
            result = llm.generate("test")

        self.assertTrue(llm.last_request_was_fallback)
        self.assertEqual(llm.fallback_count, 1)
        self.assertIn("test", result)

    def test_fallback_count_accumulates(self):
        """Fallback count should accumulate across calls."""
        import requests as req_module

        llm = self._make_llm()

        def fake_post(url, json, timeout):
            class FakeResp:
                status_code = 200
                def raise_for_status(self):
                    pass
                def json(self):
                    return {"choices": [{"message": {"content": '{"a":1}'}}]}
            if "9999" in url:
                raise req_module.ConnectionError("refused")
            return FakeResp()

        with patch.object(req_module, 'post', side_effect=fake_post):
            llm.generate("test1")
            llm.generate("test2")

        self.assertEqual(llm.fallback_count, 2)


if __name__ == "__main__":
    unittest.main()
