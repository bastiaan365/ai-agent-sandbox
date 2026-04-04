"""Helper utilities for sandbox."""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def load_policy_file(filepath: str) -> Dict[str, Any]:
    """Load policy from YAML file.

    Args:
        filepath: Path to policy file

    Returns:
        Policy dictionary
    """
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def save_policy_file(policy: Dict[str, Any], filepath: str) -> None:
    """Save policy to YAML file.

    Args:
        policy: Policy dictionary
        filepath: Path to save to
    """
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        yaml.dump(policy, f, default_flow_style=False)


def load_audit_log(filepath: str) -> list:
    """Load audit log from JSON lines file.

    Args:
        filepath: Path to audit log file

    Returns:
        List of audit events
    """
    events = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    except FileNotFoundError:
        pass
    return events


def format_audit_event(event: Dict[str, Any]) -> str:
    """Format audit event for display.

    Args:
        event: Audit event dictionary

    Returns:
        Formatted string
    """
    timestamp = event.get("timestamp", "unknown")
    event_type = event.get("event_type", "unknown")
    message = event.get("message", "")
    allowed = event.get("allowed", True)
    severity = event.get("severity", "info")

    status = "ALLOWED" if allowed else "DENIED"
    return f"[{timestamp}] {status} {event_type.upper()} ({severity}): {message}"


def export_audit_to_json(events: list, filepath: str) -> None:
    """Export audit events to JSON file.

    Args:
        events: List of audit events
        filepath: Path to export to
    """
    with open(filepath, "w") as f:
        json.dump(events, f, indent=2)


def print_policy_summary(policy: Dict[str, Any]) -> None:
    """Print a summary of policy configuration.

    Args:
        policy: Policy dictionary
    """
    meta = policy.get("metadata", {})
    print(f"Policy: {meta.get('name', 'unknown')}")
    print(f"Version: {meta.get('version', 'unknown')}")
    print(f"Description: {meta.get('description', '')}")
    print()

    fs = policy.get("filesystem", {})
    print(f"File System:")
    print(f"  Max size: {fs.get('max_file_size', 0)} bytes")
    print(f"  Allowed paths: {len(fs.get('allowed_paths', []))} patterns")
    print(f"  Denied paths: {len(fs.get('denied_paths', []))} patterns")
    print()

    net = policy.get("network", {})
    print(f"Network:")
    print(f"  Allowed hosts: {len(net.get('allowed_hosts', []))} patterns")
    print(f"  Denied hosts: {len(net.get('denied_hosts', []))} patterns")
    print(f"  Allowed ports: {net.get('allowed_ports', [])}")
    print()

    proc = policy.get("processes", {})
    print(f"Processes:")
    print(f"  Allowed commands: {len(proc.get('allowed_commands', []))} patterns")
    print(f"  Denied commands: {len(proc.get('denied_commands', []))} patterns")
    print()

    res = policy.get("resources", {})
    print(f"Resources:")
    print(f"  Max memory: {res.get('max_memory_mb', 0)} MB")
    print(f"  Max timeout: {res.get('max_timeout_seconds', 0)} seconds")
    print(f"  Max file ops: {res.get('max_file_ops', 0)}")
    print(f"  Max network requests: {res.get('max_network_requests', 0)}")
