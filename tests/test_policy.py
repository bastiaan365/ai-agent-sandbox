"""Tests for policy engine."""

import pytest
from sandbox.core.policy import PolicyEngine, FileSystemPolicy, NetworkPolicy, ProcessPolicy


class TestFileSystemPolicy:
    """Test file system access policy."""

    def test_path_allowed_explicit(self):
        """Test explicit allowed path."""
        policy = FileSystemPolicy(allowed_paths=["/tmp/**"])
        assert policy.is_path_allowed("/tmp/test.txt")
        assert policy.is_path_allowed("/tmp/dir/file.txt")

    def test_path_denied(self):
        """Test denied path takes precedence."""
        policy = FileSystemPolicy(
            allowed_paths=["/tmp/**", "/etc/**"],
            denied_paths=["/etc/passwd"],
        )
        assert policy.is_path_allowed("/tmp/test.txt")
        assert not policy.is_path_allowed("/etc/passwd")
        assert policy.is_path_allowed("/etc/other")

    def test_path_not_in_allowed(self):
        """Test path not in allowed list."""
        policy = FileSystemPolicy(allowed_paths=["/tmp/**"])
        assert not policy.is_path_allowed("/home/user/file.txt")

    def test_empty_allowed_paths_allows_all(self):
        """Test empty allowed paths allows everything."""
        policy = FileSystemPolicy(allowed_paths=[])
        assert policy.is_path_allowed("/any/path/here.txt")
        assert policy.is_path_allowed("/etc/passwd")


class TestNetworkPolicy:
    """Test network access policy."""

    def test_host_allowed(self):
        """Test allowed host."""
        policy = NetworkPolicy(allowed_hosts=["*.example.com"])
        assert policy.is_host_allowed("api.example.com", 443)

    def test_host_denied(self):
        """Test denied host."""
        policy = NetworkPolicy(
            allowed_hosts=["*.example.com"],
            denied_hosts=["internal.example.com"],
        )
        assert not policy.is_host_allowed("internal.example.com", 443)

    def test_port_not_allowed(self):
        """Test port not in allowed list."""
        policy = NetworkPolicy(
            allowed_hosts=["example.com"],
            allowed_ports=[80, 443],
        )
        assert policy.is_host_allowed("example.com", 443)
        assert not policy.is_host_allowed("example.com", 8080)

    def test_empty_allowed_hosts_denies_all(self):
        """Test empty allowed hosts denies everything."""
        policy = NetworkPolicy(allowed_hosts=[])
        assert not policy.is_host_allowed("example.com", 443)
        assert not policy.is_host_allowed("localhost", 80)


class TestProcessPolicy:
    """Test process execution policy."""

    def test_command_allowed(self):
        """Test allowed command."""
        policy = ProcessPolicy(allowed_commands=["python*", "curl"])
        assert policy.is_command_allowed("python script.py")
        assert policy.is_command_allowed("python3 test.py")

    def test_command_denied(self):
        """Test denied command."""
        policy = ProcessPolicy(denied_commands=["rm", "dd"])
        assert not policy.is_command_allowed("rm -rf /")
        assert not policy.is_command_allowed("dd if=/dev/sda")

    def test_empty_allowed_commands_denies_all(self):
        """Test empty allowed commands denies everything."""
        policy = ProcessPolicy(allowed_commands=[])
        assert not policy.is_command_allowed("python test.py")
        assert not policy.is_command_allowed("curl example.com")


class TestPolicyEngine:
    """Test complete policy engine."""

    def test_load_policy_dict(self):
        """Test loading policy from dict."""
        policy_dict = {
            "metadata": {"name": "test", "version": "1.0"},
            "filesystem": {"max_file_size": 1024},
            "network": {"allowed_hosts": ["example.com"]},
        }
        engine = PolicyEngine(policy_dict)
        assert engine.name == "test"
        assert engine.version == "1.0"

    def test_validate_policy(self):
        """Test policy validation."""
        policy_dict = {
            "metadata": {"name": "test"},
            "filesystem": {"allowed_paths": []},
            "network": {"allowed_hosts": []},
        }
        engine = PolicyEngine(policy_dict)
        errors = engine.validate()
        # Should have warnings about empty allowed lists
        assert len(errors) > 0

    def test_to_dict(self):
        """Test exporting policy to dict."""
        policy_dict = {
            "metadata": {"name": "test"},
            "filesystem": {"allowed_paths": ["/tmp/**"]},
        }
        engine = PolicyEngine(policy_dict)
        exported = engine.to_dict()
        assert exported["metadata"]["name"] == "test"
        assert "/tmp/**" in exported["filesystem"]["allowed_paths"]

    def test_default_values(self):
        """Test default policy values."""
        engine = PolicyEngine({})
        assert engine.filesystem.max_file_size == 10 * 1024 * 1024
        assert engine.resources.max_timeout_seconds == 60


class TestPolicyFromYAML:
    """Test loading policy from YAML (integration test)."""

    def test_from_yaml_file(self, tmp_path):
        """Test loading from YAML file."""
        import yaml

        yaml_file = tmp_path / "policy.yaml"
        policy_dict = {
            "metadata": {"name": "test_yaml"},
            "filesystem": {"allowed_paths": ["/tmp/**"]},
        }

        with open(yaml_file, "w") as f:
            yaml.dump(policy_dict, f)

        engine = PolicyEngine.from_yaml(str(yaml_file))
        assert engine.name == "test_yaml"
        assert engine.filesystem.allowed_paths == ["/tmp/**"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
