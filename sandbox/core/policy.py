"""Policy engine for sandbox access control."""

import fnmatch
import yaml
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from pydantic import BaseModel, validator


@dataclass
class FileSystemPolicy:
    """File system access policy."""
    max_file_size: int = 10 * 1024 * 1024  # 10MB default
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)

    def is_path_allowed(self, path: str) -> bool:
        """Check if path is allowed."""
        # Check denied first (deny takes precedence)
        for pattern in self.denied_paths:
            if self._matches_pattern(path, pattern):
                return False

        # If allowed_paths is empty, allow by default (unless denied)
        if not self.allowed_paths:
            return True

        # Check allowed patterns
        for pattern in self.allowed_paths:
            if self._matches_pattern(path, pattern):
                return True

        return False

    @staticmethod
    def _matches_pattern(path: str, pattern: str) -> bool:
        """Match path against glob pattern."""
        return fnmatch.fnmatch(path, pattern)


@dataclass
class NetworkPolicy:
    """Network access policy."""
    allowed_hosts: List[str] = field(default_factory=list)
    denied_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    denied_ports: List[int] = field(default_factory=list)

    def is_host_allowed(self, host: str, port: int = 80) -> bool:
        """Check if host:port is allowed."""
        # Check denied first
        for pattern in self.denied_hosts:
            if self._matches_pattern(host, pattern):
                return False

        # Check denied ports
        if port in self.denied_ports:
            return False

        # If allowed_hosts is empty, deny by default
        if not self.allowed_hosts:
            return False

        # Check allowed patterns
        for pattern in self.allowed_hosts:
            if self._matches_pattern(host, pattern):
                # Check allowed ports
                if not self.allowed_ports or port in self.allowed_ports:
                    return True

        return False

    @staticmethod
    def _matches_pattern(host: str, pattern: str) -> bool:
        """Match host against glob pattern."""
        return fnmatch.fnmatch(host, pattern)


@dataclass
class ProcessPolicy:
    """Process execution policy."""
    allowed_commands: List[str] = field(default_factory=list)
    denied_commands: List[str] = field(default_factory=list)

    def is_command_allowed(self, command: str) -> bool:
        """Check if command is allowed."""
        # Extract base command
        base_cmd = command.split()[0] if command else ""

        # Check denied first
        for pattern in self.denied_commands:
            if self._matches_pattern(base_cmd, pattern):
                return False

        # If allowed_commands is empty, deny by default
        if not self.allowed_commands:
            return False

        # Check allowed patterns
        for pattern in self.allowed_commands:
            if self._matches_pattern(base_cmd, pattern):
                return True

        return False

    @staticmethod
    def _matches_pattern(cmd: str, pattern: str) -> bool:
        """Match command against pattern."""
        return fnmatch.fnmatch(cmd, pattern)


@dataclass
class ResourcePolicy:
    """Resource limit policy."""
    max_memory_mb: int = 512
    max_timeout_seconds: int = 60
    max_file_ops: int = 1000
    max_network_requests: int = 100


@dataclass
class SecretsPolicy:
    """Secrets access policy."""
    protected_vars: List[str] = field(default_factory=list)

    def is_var_protected(self, var_name: str) -> bool:
        """Check if variable is protected."""
        return any(fnmatch.fnmatch(var_name, pattern) for pattern in self.protected_vars)


class PolicyEngine:
    """YAML-based policy engine for sandbox access control."""

    def __init__(self, policy_dict: Optional[Dict[str, Any]] = None):
        """Initialize policy engine with policy dict or defaults."""
        if policy_dict is None:
            policy_dict = {}

        self._parse_policy(policy_dict)

    def _parse_policy(self, policy_dict: Dict[str, Any]) -> None:
        """Parse policy dictionary."""
        # Metadata
        meta = policy_dict.get("metadata", {})
        self.name: str = meta.get("name", "default")
        self.version: str = meta.get("version", "1.0")
        self.description: str = meta.get("description", "")

        # File system policy
        fs_config = policy_dict.get("filesystem", {})
        self.filesystem = FileSystemPolicy(
            max_file_size=fs_config.get("max_file_size", 10 * 1024 * 1024),
            allowed_paths=fs_config.get("allowed_paths", []),
            denied_paths=fs_config.get("denied_paths", []),
        )

        # Network policy
        net_config = policy_dict.get("network", {})
        self.network = NetworkPolicy(
            allowed_hosts=net_config.get("allowed_hosts", []),
            denied_hosts=net_config.get("denied_hosts", []),
            allowed_ports=net_config.get("allowed_ports", [80, 443]),
            denied_ports=net_config.get("denied_ports", []),
        )

        # Process policy
        proc_config = policy_dict.get("processes", {})
        self.processes = ProcessPolicy(
            allowed_commands=proc_config.get("allowed_commands", []),
            denied_commands=proc_config.get("denied_commands", []),
        )

        # Secrets policy
        sec_config = policy_dict.get("secrets", {})
        self.secrets = SecretsPolicy(
            protected_vars=sec_config.get("protected_vars", []),
        )

        # Resource policy
        res_config = policy_dict.get("resources", {})
        self.resources = ResourcePolicy(
            max_memory_mb=res_config.get("max_memory_mb", 512),
            max_timeout_seconds=res_config.get("max_timeout_seconds", 60),
            max_file_ops=res_config.get("max_file_ops", 1000),
            max_network_requests=res_config.get("max_network_requests", 100),
        )

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "PolicyEngine":
        """Load policy from YAML file."""
        with open(yaml_path, "r") as f:
            policy_dict = yaml.safe_load(f)
        return cls(policy_dict)

    def validate(self) -> List[str]:
        """Validate policy, return list of errors."""
        errors = []

        # Check for empty allowed lists (deny-by-default)
        if (
            not self.filesystem.allowed_paths
            and self.filesystem.denied_paths
        ):
            errors.append(
                "Warning: No allowed_paths defined in filesystem policy. "
                "All paths will be denied (except denied_paths)."
            )

        if (
            not self.network.allowed_hosts
            and not self.network.denied_hosts
        ):
            errors.append(
                "Warning: No allowed_hosts defined in network policy. "
                "All network access will be denied."
            )

        if (
            not self.processes.allowed_commands
            and self.processes.denied_commands
        ):
            errors.append(
                "Warning: No allowed_commands defined in process policy. "
                "All process execution will be denied."
            )

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Export policy as dictionary."""
        return {
            "metadata": {
                "name": self.name,
                "version": self.version,
                "description": self.description,
            },
            "filesystem": {
                "max_file_size": self.filesystem.max_file_size,
                "allowed_paths": self.filesystem.allowed_paths,
                "denied_paths": self.filesystem.denied_paths,
            },
            "network": {
                "allowed_hosts": self.network.allowed_hosts,
                "denied_hosts": self.network.denied_hosts,
                "allowed_ports": self.network.allowed_ports,
                "denied_ports": self.network.denied_ports,
            },
            "processes": {
                "allowed_commands": self.processes.allowed_commands,
                "denied_commands": self.processes.denied_commands,
            },
            "secrets": {
                "protected_vars": self.secrets.protected_vars,
            },
            "resources": {
                "max_memory_mb": self.resources.max_memory_mb,
                "max_timeout_seconds": self.resources.max_timeout_seconds,
                "max_file_ops": self.resources.max_file_ops,
                "max_network_requests": self.resources.max_network_requests,
            },
        }
