"""File system access interceptor."""

import builtins
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor, EventType, EventSeverity


class FileAccessDenied(Exception):
    """Raised when file access is denied by policy."""
    pass


class FileSystemInterceptor:
    """Intercepts file system operations and enforces policy."""

    def __init__(self, policy: PolicyEngine, monitor: EventMonitor):
        """Initialize file system interceptor.

        Args:
            policy: Policy engine
            monitor: Event monitor
        """
        self.policy = policy
        self.monitor = monitor
        self._original_open = builtins.open
        self._original_unlink = Path.unlink
        self._original_rmdir = Path.rmdir
        self._active = False

    def __enter__(self):
        """Enter context and install interceptor."""
        self._active = True
        builtins.open = self._sandboxed_open
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original functions."""
        self._active = False
        builtins.open = self._original_open
        return False

    def _sandboxed_open(
        self,
        file: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ):
        """Sandboxed file open function."""
        if not self._active:
            return self._original_open(
                file, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline
            )

        # Resolve path
        abs_path = str(Path(file).resolve())

        # Determine operation type
        write_modes = {"w", "a", "x", "w+", "a+", "x+"}
        is_write = any(m in mode for m in write_modes)
        is_read = any(m in mode for m in {"r", "+", "w+", "a+", "x+"})

        operation = "write" if is_write else "read"

        # Check policy
        if not self.policy.filesystem.is_path_allowed(abs_path):
            self.monitor.log_event(
                event_type=EventType.FILE_WRITE if is_write else EventType.FILE_READ,
                message=f"File {operation} denied: {abs_path}",
                severity=EventSeverity.ERROR,
                allowed=False,
                details={
                    "path": abs_path,
                    "mode": mode,
                    "operation": operation,
                },
            )
            raise FileAccessDenied(f"Access denied: {abs_path}")

        # Check file size (before write)
        try:
            if os.path.exists(abs_path):
                size = os.path.getsize(abs_path)
                if size > self.policy.filesystem.max_file_size:
                    self.monitor.log_event(
                        event_type=EventType.FILE_READ if is_read else EventType.FILE_WRITE,
                        message=f"File size exceeds limit: {abs_path} ({size} bytes)",
                        severity=EventSeverity.ERROR,
                        allowed=False,
                        details={
                            "path": abs_path,
                            "size": size,
                            "max_allowed": self.policy.filesystem.max_file_size,
                        },
                    )
                    raise FileAccessDenied(f"File size exceeds limit: {abs_path}")
        except OSError:
            pass

        # Log the operation
        self.monitor.log_event(
            event_type=EventType.FILE_WRITE if is_write else EventType.FILE_READ,
            message=f"File {operation}: {abs_path}",
            allowed=True,
            details={
                "path": abs_path,
                "mode": mode,
                "operation": operation,
            },
        )

        # Call original open
        return self._original_open(
            file, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline
        )

    def check_path_allowed(self, path: str) -> bool:
        """Check if path is allowed.

        Args:
            path: File path to check

        Returns:
            True if allowed, False otherwise
        """
        abs_path = str(Path(path).resolve())
        return self.policy.filesystem.is_path_allowed(abs_path)

    def get_allowed_paths(self) -> list:
        """Get list of allowed path patterns.

        Returns:
            List of allowed patterns
        """
        return self.policy.filesystem.allowed_paths.copy()

    def get_denied_paths(self) -> list:
        """Get list of denied path patterns.

        Returns:
            List of denied patterns
        """
        return self.policy.filesystem.denied_paths.copy()
