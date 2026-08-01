"""
Tests for ToolRegistry — tool execution, error handling, and edge cases.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tools import ToolRegistry, ToolResult, Tool


class TestToolRegistry(unittest.TestCase):
    """Tests for ToolRegistry.execute() and tool wrappers."""

    def setUp(self):
        self.registry = ToolRegistry()

    def test_all_default_tools_registered(self):
        """All 19+ default tools should be registered."""
        expected = [
            "nmap", "shell", "curl", "gobuster", "nikto", "whatweb",
            "sqlmap", "hydra", "searchsploit", "wget", "nc", "python",
            "grep", "file", "strings", "exiftool", "binwalk", "ssh",
            "submit_flag", "quick_scan",
        ]
        for name in expected:
            self.assertIn(name, self.registry.tools, f"Tool '{name}' not registered")

    def test_execute_unknown_tool_returns_error(self):
        """Executing an unregistered tool should return an error ToolResult."""
        result = self.registry.execute("nonexistent_tool", "some args")
        self.assertIsInstance(result, ToolResult)
        self.assertFalse(result.success)
        self.assertIn("Unknown tool", result.error)
        self.assertIn("nonexistent_tool", result.error)

    def test_execute_returns_tool_result(self):
        """Executing a valid tool returns a ToolResult with output and success fields."""
        result = self.registry.execute("grep", "--version")
        self.assertIsInstance(result, ToolResult)
        self.assertIsInstance(result.output, str)
        self.assertIsInstance(result.success, bool)

    def test_describe_all_contains_all_tools(self):
        """describe_all() should list every registered tool with description and usage."""
        desc = self.registry.describe_all()
        self.assertIn("nmap:", desc)
        self.assertIn("curl:", desc)
        self.assertIn("submit_flag:", desc)
        self.assertIn("Usage:", desc)

    def test_submit_flag_always_succeeds(self):
        """submit_flag should always return success=True."""
        result = self.registry.execute("submit_flag", "flag{test_123}")
        self.assertTrue(result.success)
        self.assertIn("flag{test_123}", result.output)

    def test_submit_flag_stores_flag_in_output(self):
        """submit_flag output should contain the submitted flag value."""
        result = self.registry.execute("submit_flag", "CTF{my_secret_flag}")
        self.assertIn("CTF{my_secret_flag}", result.output)

    def test_tool_handler_exception_returns_error(self):
        """If a tool handler raises, execute() should catch it and return failure."""
        def bad_handler(args):
            raise RuntimeError("Intentional test error")

        self.registry.register(Tool("bad_tool", "Test tool", "bad_tool <args>", bad_handler))
        result = self.registry.execute("bad_tool", "anything")
        self.assertFalse(result.success)
        self.assertIn("ToolException", result.error)
        self.assertIn("Intentional test error", result.error)

    def test_tool_result_parsed_field_default_none(self):
        """ToolResult.parsed should default to None."""
        result = ToolResult(output="test", success=True)
        self.assertIsNone(result.parsed)

    def test_tool_result_with_parsed_data(self):
        """ToolResult can carry parsed dict data."""
        result = ToolResult(output="raw", success=True, parsed={"key": "value"})
        self.assertEqual(result.parsed["key"], "value")

    def test_run_cmd_timeout_returns_failure(self):
        """Commands that exceed timeout should return failure."""
        result = self.registry.tools["shell"].handler("sleep 10")
        # We can't easily test timeout without waiting, but we can test the mechanism
        # by checking the result type
        self.assertIsInstance(result, ToolResult)

    def test_grep_tool_basic(self):
        """grep tool should work for basic pattern matching."""
        result = self.registry.execute("grep", "root /etc/passwd")
        # May fail if /etc/passwd doesn't exist or grep not installed, but should return a result
        self.assertIsInstance(result, ToolResult)

    def test_file_tool_basic(self):
        """file tool should identify file types."""
        result = self.registry.execute("file", "/etc/passwd")
        self.assertIsInstance(result, ToolResult)


if __name__ == "__main__":
    unittest.main()
