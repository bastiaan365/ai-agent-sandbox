"""Tests for sandbox runtime."""

import tempfile
import pytest
from sandbox.core.runtime import SandboxRuntime, TimeoutException
from sandbox.policies.defaults import RESTRICTIVE_POLICY, PERMISSIVE_POLICY


class TestSandboxRuntime:
    """Test sandbox runtime."""

    def test_runtime_initialization(self):
        """Test creating a runtime."""
        runtime = SandboxRuntime(policy_dict=RESTRICTIVE_POLICY)
        assert runtime.agent_id
        assert runtime.policy
        assert runtime.monitor

    def test_sandboxed_decorator(self):
        """Test sandboxed decorator."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def simple_func():
            return "Hello"

        result = simple_func()
        assert result == "Hello"

    def test_sandboxed_with_args(self):
        """Test sandboxed function with arguments."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def add(a, b):
            return a + b

        result = add(2, 3)
        assert result == 5

    def test_sandboxed_with_file_access(self):
        """Test sandboxed function with file access."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def write_and_read():
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write("test data")
                path = f.name

            with open(path, "r") as f:
                content = f.read()

            import os
            os.unlink(path)

            return content

        result = write_and_read()
        assert result == "test data"

    def test_sandboxed_exception_propagation(self):
        """Test that exceptions propagate from sandboxed function."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def error_func():
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            error_func()

    def test_timeout_exception(self):
        """Test timeout handling."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=1)
        def slow_func():
            import time
            time.sleep(2)
            return "Done"

        with pytest.raises(TimeoutException):
            slow_func()

    def test_context_manager(self):
        """Test sandbox context manager."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        with runtime.sandbox_context(timeout=10):
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write("context test")
                path = f.name

        import os
        os.unlink(path)

    def test_get_audit_log(self):
        """Test getting audit log."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task():
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write("test")
                path = f.name
            import os
            os.unlink(path)

        task()

        audit_log = runtime.get_audit_log()
        assert len(audit_log) > 0

    def test_get_violations(self):
        """Test getting violations."""
        from sandbox.interceptors.filesystem import FileAccessDenied
        runtime = SandboxRuntime(policy_dict=RESTRICTIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task():
            try:
                open("/etc/passwd", "r")
            except FileAccessDenied:
                pass

        task()

        violations = runtime.get_violations()
        assert len(violations) > 0

    def test_get_summary(self):
        """Test getting execution summary."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task():
            return "Done"

        task()

        summary = runtime.get_summary()
        assert "total_events" in summary
        assert "allowed_count" in summary
        assert "denied_count" in summary

    def test_reset(self):
        """Test resetting runtime state."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task():
            return "Done"

        task()
        summary1 = runtime.get_summary()
        assert summary1["total_events"] > 0

        runtime.reset()
        summary2 = runtime.get_summary()
        assert summary2["total_events"] == 0

    def test_export_audit_log(self):
        """Test exporting audit log."""
        import os
        import json

        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task():
            return "Done"

        task()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            export_path = f.name

        try:
            runtime.export_audit_log(export_path)
            assert os.path.exists(export_path)

            with open(export_path, "r") as f:
                data = json.load(f)
                assert "events" in data
                assert len(data["events"]) > 0
        finally:
            os.unlink(export_path)

    def test_multiple_tasks(self):
        """Test running multiple tasks in same runtime."""
        runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

        @runtime.sandboxed(timeout=10)
        def task1():
            return "Task 1"

        @runtime.sandboxed(timeout=10)
        def task2():
            return "Task 2"

        result1 = task1()
        result2 = task2()

        assert result1 == "Task 1"
        assert result2 == "Task 2"

        summary = runtime.get_summary()
        assert summary["total_events"] > 0


class TestSandboxRuntimeWithAuditFile:
    """Test runtime with audit file persistence."""

    def test_audit_file_created(self):
        """Test that audit file is created."""
        import os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as f:
            audit_path = f.name

        try:
            runtime = SandboxRuntime(
                policy_dict=PERMISSIVE_POLICY,
                audit_file=audit_path,
            )

            @runtime.sandboxed(timeout=10)
            def task():
                return "Done"

            task()

            assert os.path.exists(audit_path)
            assert os.path.getsize(audit_path) > 0
        finally:
            if os.path.exists(audit_path):
                os.unlink(audit_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
