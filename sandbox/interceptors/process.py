"""Process execution interceptor."""

import subprocess
from typing import Any, Optional, List, Union
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor, EventType, EventSeverity


class ProcessExecutionDenied(Exception):
    """Raised when process execution is denied by policy."""
    pass


class ProcessInterceptor:
    """Intercepts process execution and enforces policy."""

    def __init__(self, policy: PolicyEngine, monitor: EventMonitor):
        """Initialize process interceptor.

        Args:
            policy: Policy engine
            monitor: Event monitor
        """
        self.policy = policy
        self.monitor = monitor
        self._active = False
        self._original_popen = subprocess.Popen
        self._original_run = subprocess.run
        self._original_call = subprocess.call
        self._original_check_call = subprocess.check_call
        self._original_check_output = subprocess.check_output

    def __enter__(self):
        """Enter context and install interceptor."""
        self._active = True
        subprocess.Popen = self._sandboxed_popen
        subprocess.run = self._sandboxed_run
        subprocess.call = self._sandboxed_call
        subprocess.check_call = self._sandboxed_check_call
        subprocess.check_output = self._sandboxed_check_output
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original functions."""
        self._active = False
        subprocess.Popen = self._original_popen
        subprocess.run = self._original_run
        subprocess.call = self._original_call
        subprocess.check_call = self._original_check_call
        subprocess.check_output = self._original_check_output
        return False

    def _check_command(self, args: Union[str, List[str]]) -> None:
        """Check if command is allowed.

        Args:
            args: Command arguments

        Raises:
            ProcessExecutionDenied: If command is not allowed
        """
        # Extract command string
        if isinstance(args, str):
            command = args
        elif isinstance(args, (list, tuple)):
            command = " ".join(str(arg) for arg in args) if args else ""
        else:
            command = str(args)

        # Check policy
        if not self.policy.processes.is_command_allowed(command):
            self.monitor.log_event(
                event_type=EventType.PROCESS_EXEC,
                message=f"Process execution denied: {command}",
                severity=EventSeverity.ERROR,
                allowed=False,
                details={
                    "command": command,
                },
            )
            raise ProcessExecutionDenied(f"Command not allowed: {command}")

        # Log the operation
        self.monitor.log_event(
            event_type=EventType.PROCESS_EXEC,
            message=f"Process execution: {command}",
            allowed=True,
            details={
                "command": command,
            },
        )

    def _sandboxed_popen(self, args: Union[str, List[str]], **kwargs):
        """Sandboxed Popen."""
        if not self._active:
            return self._original_popen(args, **kwargs)

        self._check_command(args)
        return self._original_popen(args, **kwargs)

    def _sandboxed_run(self, args: Union[str, List[str]], **kwargs):
        """Sandboxed subprocess.run."""
        if not self._active:
            return self._original_run(args, **kwargs)

        self._check_command(args)
        return self._original_run(args, **kwargs)

    def _sandboxed_call(self, args: Union[str, List[str]], **kwargs):
        """Sandboxed subprocess.call."""
        if not self._active:
            return self._original_call(args, **kwargs)

        self._check_command(args)
        return self._original_call(args, **kwargs)

    def _sandboxed_check_call(self, args: Union[str, List[str]], **kwargs):
        """Sandboxed subprocess.check_call."""
        if not self._active:
            return self._original_check_call(args, **kwargs)

        self._check_command(args)
        return self._original_check_call(args, **kwargs)

    def _sandboxed_check_output(self, args: Union[str, List[str]], **kwargs):
        """Sandboxed subprocess.check_output."""
        if not self._active:
            return self._original_check_output(args, **kwargs)

        self._check_command(args)
        return self._original_check_output(args, **kwargs)

    def check_command_allowed(self, command: str) -> bool:
        """Check if command is allowed.

        Args:
            command: Command to check

        Returns:
            True if allowed, False otherwise
        """
        return self.policy.processes.is_command_allowed(command)

    def get_allowed_commands(self) -> list:
        """Get list of allowed command patterns.

        Returns:
            List of allowed patterns
        """
        return self.policy.processes.allowed_commands.copy()

    def get_denied_commands(self) -> list:
        """Get list of denied command patterns.

        Returns:
            List of denied patterns
        """
        return self.policy.processes.denied_commands.copy()
