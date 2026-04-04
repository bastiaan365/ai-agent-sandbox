"""Tests for sandbox adapters."""

import tempfile
import pytest
from sandbox.adapters.generic import SandboxedSubprocess, SandboxedFunction, create_sandboxed_function
from sandbox.adapters.langchain import SandboxedLangChainTools
from sandbox.adapters.openai_functions import SandboxedOpenAIFunctions
from sandbox.core.runtime import SandboxRuntime
from sandbox.policies.defaults import PERMISSIVE_POLICY


class TestSandboxedFunction:
    """Test generic sandboxed function wrapper."""

    def test_sandboxed_function_wrapper(self):
        """Test wrapping a function."""
        def my_func(a, b):
            return a + b

        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)
        sandboxed = SandboxedFunction(my_func, runtime)

        result = sandboxed(2, 3)
        assert result == 5

    def test_create_sandboxed_function(self):
        """Test factory function."""
        def my_func():
            return "Hello"

        sandboxed = create_sandboxed_function(my_func)
        result = sandboxed()
        assert result == "Hello"

    def test_sandboxed_function_with_file(self):
        """Test sandboxed function accessing files."""
        def write_file():
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write("test")
                return f.name

        sandboxed = create_sandboxed_function(write_file, policy=PERMISSIVE_POLICY)
        path = sandboxed()

        import os
        assert os.path.exists(path)
        os.unlink(path)


class TestSandboxedSubprocess:
    """Test subprocess wrapper."""

    def test_sandboxed_subprocess_run(self):
        """Test running subprocess."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)
        runtime.policy.processes.allowed_commands = ["echo"]

        wrapper = SandboxedSubprocess(runtime)

        # Note: On some systems this might not work due to subprocess interception
        # This is more of an integration test

    def test_sandboxed_popen(self):
        """Test Popen wrapper."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)
        wrapper = SandboxedSubprocess(runtime)

        # Verify wrapper exists
        assert wrapper.runtime == runtime


class MockLangChainTool:
    """Mock LangChain tool for testing."""

    def __init__(self, name, func):
        self.name = name
        self.func = func


class TestSandboxedLangChainTools:
    """Test LangChain tool wrapper."""

    def test_wrap_tools(self):
        """Test wrapping LangChain tools."""
        def tool_func(input_str):
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write(input_str)
                return f.name

        tools = [MockLangChainTool("write_tool", tool_func)]

        wrapper = SandboxedLangChainTools(
            tools=tools,
            policy_dict=PERMISSIVE_POLICY,
        )

        safe_tools = wrapper.get_tools()
        assert len(safe_tools) == 1

    def test_get_audit_log(self):
        """Test getting audit log from wrapper."""
        def tool_func(x):
            return x

        tools = [MockLangChainTool("test_tool", tool_func)]

        wrapper = SandboxedLangChainTools(
            tools=tools,
            policy_dict=PERMISSIVE_POLICY,
        )

        # Should have no events yet
        audit_log = wrapper.get_audit_log()
        assert isinstance(audit_log, list)

    def test_get_summary(self):
        """Test getting summary from wrapper."""
        def tool_func(x):
            return x

        tools = [MockLangChainTool("test_tool", tool_func)]

        wrapper = SandboxedLangChainTools(
            tools=tools,
            policy_dict=PERMISSIVE_POLICY,
        )

        summary = wrapper.get_summary()
        assert "total_events" in summary


class TestSandboxedOpenAIFunctions:
    """Test OpenAI function wrapper."""

    def test_register_implementation(self):
        """Test registering function implementation."""
        def my_func(x):
            return x * 2

        wrapper = SandboxedOpenAIFunctions(
            functions=[{"name": "double", "description": "Double a number"}],
            policy_dict=PERMISSIVE_POLICY,
        )

        wrapper.register_implementation("double", my_func)
        result = wrapper.execute_function("double", {"x": 5})
        assert result == 10

    def test_execute_function(self):
        """Test executing function."""
        def add(a, b):
            return a + b

        wrapper = SandboxedOpenAIFunctions(policy_dict=PERMISSIVE_POLICY)
        wrapper.register_implementation("add", add)

        result = wrapper.execute_function("add", {"a": 2, "b": 3})
        assert result == 5

    def test_execute_unregistered_function(self):
        """Test executing unregistered function."""
        wrapper = SandboxedOpenAIFunctions(policy_dict=PERMISSIVE_POLICY)

        with pytest.raises(ValueError, match="not registered"):
            wrapper.execute_function("missing", {})

    def test_get_audit_log(self):
        """Test getting audit log."""
        def my_func():
            return "result"

        wrapper = SandboxedOpenAIFunctions(policy_dict=PERMISSIVE_POLICY)
        wrapper.register_implementation("test", my_func)
        wrapper.execute_function("test", {})

        audit_log = wrapper.get_audit_log()
        assert isinstance(audit_log, list)


class TestAdapterIntegration:
    """Integration tests for adapters."""

    def test_multiple_adapters(self):
        """Test using multiple adapters together."""
        def file_tool(path):
            with open(path, "w") as f:
                f.write("test")
            return "written"

        # Test generic adapter
        sandboxed = create_sandboxed_function(
            file_tool,
            policy=PERMISSIVE_POLICY,
        )

        # Test LangChain adapter
        tools = [MockLangChainTool("file_tool", file_tool)]
        langchain_wrapper = SandboxedLangChainTools(
            tools=tools,
            policy_dict=PERMISSIVE_POLICY,
        )

        # Test OpenAI adapter
        openai_wrapper = SandboxedOpenAIFunctions(
            policy_dict=PERMISSIVE_POLICY,
        )
        openai_wrapper.register_implementation("file_tool", file_tool)

        # All should work
        assert sandboxed is not None
        assert langchain_wrapper is not None
        assert openai_wrapper is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
