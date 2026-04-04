"""Tests for sandbox interceptors."""

import os
import tempfile
import pytest
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor
from sandbox.interceptors.filesystem import FileSystemInterceptor, FileAccessDenied
from sandbox.interceptors.network import NetworkInterceptor, NetworkAccessDenied
from sandbox.interceptors.process import ProcessInterceptor, ProcessExecutionDenied
from sandbox.interceptors.secrets import SecretsInterceptor


class TestFileSystemInterceptor:
    """Test file system interceptor."""

    def test_file_open_allowed(self):
        """Test opening allowed file."""
        policy = PolicyEngine({
            "filesystem": {"allowed_paths": ["/tmp/**"]}
        })
        monitor = EventMonitor()

        with FileSystemInterceptor(policy, monitor):
            # Should succeed
            with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
                f.write("test")
                temp_path = f.name

        # Cleanup
        try:
            os.unlink(temp_path)
        except:
            pass

    def test_file_open_denied(self):
        """Test opening denied file."""
        policy = PolicyEngine({
            "filesystem": {"allowed_paths": ["/tmp/**"], "denied_paths": ["/etc/**"]}
        })
        monitor = EventMonitor()

        with FileSystemInterceptor(policy, monitor):
            with pytest.raises(FileAccessDenied):
                open("/etc/passwd", "r")

    def test_check_path_allowed(self):
        """Test path checking."""
        policy = PolicyEngine({
            "filesystem": {"allowed_paths": ["/tmp/**"]}
        })
        monitor = EventMonitor()

        interceptor = FileSystemInterceptor(policy, monitor)
        assert interceptor.check_path_allowed("/tmp/test.txt")
        assert not interceptor.check_path_allowed("/etc/passwd")


class TestNetworkInterceptor:
    """Test network interceptor."""

    def test_check_host_allowed(self):
        """Test host checking."""
        policy = PolicyEngine({
            "network": {
                "allowed_hosts": ["*.example.com"],
                "allowed_ports": [80, 443],
            }
        })
        monitor = EventMonitor()

        interceptor = NetworkInterceptor(policy, monitor)
        assert interceptor.check_host_allowed("api.example.com", 443)
        assert not interceptor.check_host_allowed("evil.com", 443)

    def test_get_allowed_hosts(self):
        """Test getting allowed hosts."""
        policy = PolicyEngine({
            "network": {
                "allowed_hosts": ["*.example.com"],
            }
        })
        monitor = EventMonitor()

        interceptor = NetworkInterceptor(policy, monitor)
        assert "*.example.com" in interceptor.get_allowed_hosts()


class TestProcessInterceptor:
    """Test process interceptor."""

    def test_check_command_allowed(self):
        """Test command checking."""
        policy = PolicyEngine({
            "processes": {"allowed_commands": ["python*"]}
        })
        monitor = EventMonitor()

        interceptor = ProcessInterceptor(policy, monitor)
        assert interceptor.check_command_allowed("python script.py")
        assert not interceptor.check_command_allowed("rm -rf /")

    def test_get_denied_commands(self):
        """Test getting denied commands."""
        policy = PolicyEngine({
            "processes": {"denied_commands": ["rm", "dd"]}
        })
        monitor = EventMonitor()

        interceptor = ProcessInterceptor(policy, monitor)
        assert "rm" in interceptor.get_denied_commands()
        assert "dd" in interceptor.get_denied_commands()


class TestSecretsInterceptor:
    """Test secrets interceptor."""

    def test_check_var_protected(self):
        """Test checking protected variables."""
        policy = PolicyEngine({
            "secrets": {"protected_vars": ["*API*", "*KEY*"]}
        })
        monitor = EventMonitor()

        interceptor = SecretsInterceptor(policy, monitor)
        assert interceptor.check_var_protected("MY_API_KEY")
        assert not interceptor.check_var_protected("USER")

    def test_filter_dict(self):
        """Test filtering dictionary."""
        policy = PolicyEngine({
            "secrets": {"protected_vars": ["*API*"]}
        })
        monitor = EventMonitor()

        interceptor = SecretsInterceptor(policy, monitor)
        test_dict = {"USER": "john", "API_KEY": "secret", "PASSWORD": "pwd"}
        filtered = interceptor.filter_dict(test_dict)

        assert "USER" in filtered
        assert "API_KEY" not in filtered
        assert "PASSWORD" in filtered


class TestInterceptorIntegration:
    """Integration tests for interceptors."""

    def test_multiple_interceptors(self):
        """Test using multiple interceptors together."""
        policy = PolicyEngine({
            "filesystem": {"allowed_paths": ["/tmp/**"]},
            "network": {"allowed_hosts": ["example.com"]},
            "processes": {"allowed_commands": ["curl"]},
            "secrets": {"protected_vars": ["*API*"]},
        })
        monitor = EventMonitor()

        fs = FileSystemInterceptor(policy, monitor)
        net = NetworkInterceptor(policy, monitor)
        proc = ProcessInterceptor(policy, monitor)
        sec = SecretsInterceptor(policy, monitor)

        # All should be active
        with fs, net, proc, sec:
            assert fs.check_path_allowed("/tmp/test.txt")
            assert net.check_host_allowed("example.com", 80)
            assert proc.check_command_allowed("curl example.com")
            assert sec.check_var_protected("API_KEY")

    def test_monitoring_integration(self):
        """Test that monitor logs events properly."""
        policy = PolicyEngine({
            "filesystem": {"allowed_paths": ["/tmp/**"]}
        })
        monitor = EventMonitor()

        with FileSystemInterceptor(policy, monitor):
            with pytest.raises(FileAccessDenied):
                open("/etc/passwd", "r")

        # Check that event was logged
        violations = monitor.get_violations()
        assert len(violations) > 0
        assert not violations[0].allowed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
