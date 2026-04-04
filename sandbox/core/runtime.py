"""Main sandbox runtime for executing agents with policy enforcement."""

import functools
import signal
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional, TypeVar
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor, EventType, EventSeverity
from sandbox.interceptors.filesystem import FileSystemInterceptor
from sandbox.interceptors.network import NetworkInterceptor
from sandbox.interceptors.process import ProcessInterceptor
from sandbox.interceptors.secrets import SecretsInterceptor

T = TypeVar("T")


class TimeoutException(Exception):
    """Raised when sandbox execution times out."""
    pass


class SandboxRuntime:
    """Main sandbox runtime that applies policies to agent execution."""

    def __init__(
        self,
        policy_dict: Optional[Dict[str, Any]] = None,
        audit_file: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        """Initialize sandbox runtime.

        Args:
            policy_dict: Policy configuration as dictionary
            audit_file: Path to audit log file
            agent_id: Optional agent identifier
        """
        self.agent_id = agent_id or str(uuid.uuid4())[:8]
        self.policy = PolicyEngine(policy_dict or {})
        self.monitor = EventMonitor(audit_file=audit_file, agent_id=self.agent_id)

        # Initialize interceptors
        self.fs_interceptor = FileSystemInterceptor(
            policy=self.policy,
            monitor=self.monitor,
        )
        self.net_interceptor = NetworkInterceptor(
            policy=self.policy,
            monitor=self.monitor,
        )
        self.proc_interceptor = ProcessInterceptor(
            policy=self.policy,
            monitor=self.monitor,
        )
        self.secrets_interceptor = SecretsInterceptor(
            policy=self.policy,
            monitor=self.monitor,
        )

        # Validate policy
        errors = self.policy.validate()
        for error in errors:
            self.monitor.log_event(
                event_type=EventType.EXECUTION_START,
                message=error,
                severity=EventSeverity.WARNING,
            )

    def sandboxed(
        self,
        timeout: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator to sandbox a function.

        Args:
            timeout: Optional timeout in seconds
            request_id: Optional request ID

        Returns:
            Decorated function
        """
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                rid = request_id or str(uuid.uuid4())[:8]
                return self._execute_sandboxed(
                    func=func,
                    args=args,
                    kwargs=kwargs,
                    timeout=timeout,
                    request_id=rid,
                )
            return wrapper
        return decorator

    def _execute_sandboxed(
        self,
        func: Callable[..., T],
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> T:
        """Execute function in sandbox with all interceptors active.

        Args:
            func: Function to execute
            args: Function arguments
            kwargs: Function keyword arguments
            timeout: Optional timeout in seconds
            request_id: Optional request ID

        Returns:
            Function return value

        Raises:
            TimeoutException: If timeout exceeded
        """
        kwargs = kwargs or {}
        rid = request_id or str(uuid.uuid4())[:8]
        timeout = timeout or self.policy.resources.max_timeout_seconds

        self.monitor.log_event(
            event_type=EventType.EXECUTION_START,
            message=f"Starting execution of {func.__name__}",
            request_id=rid,
        )

        result = None
        exception = None

        def run():
            nonlocal result, exception
            try:
                with self.fs_interceptor, self.net_interceptor, self.proc_interceptor, self.secrets_interceptor:
                    result = func(*args, **kwargs)
            except Exception as e:
                exception = e

        # Execute with timeout
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            self.monitor.log_event(
                event_type=EventType.VIOLATION,
                message=f"Execution timeout exceeded ({timeout}s)",
                severity=EventSeverity.ERROR,
                allowed=False,
                request_id=rid,
            )
            raise TimeoutException(f"Execution timed out after {timeout} seconds")

        if exception:
            self.monitor.log_event(
                event_type=EventType.EXECUTION_END,
                message=f"Execution failed: {str(exception)}",
                severity=EventSeverity.ERROR,
                request_id=rid,
            )
            raise exception

        self.monitor.log_event(
            event_type=EventType.EXECUTION_END,
            message=f"Execution completed successfully",
            request_id=rid,
        )

        return result

    @contextmanager
    def sandbox_context(self, timeout: Optional[int] = None):
        """Context manager for sandboxed execution.

        Example:
            with runtime.sandbox_context(timeout=30):
                # Code here is sandboxed
                pass
        """
        timeout = timeout or self.policy.resources.max_timeout_seconds

        self.monitor.log_event(
            event_type=EventType.EXECUTION_START,
            message="Entering sandbox context",
        )

        try:
            with self.fs_interceptor, self.net_interceptor, self.proc_interceptor, self.secrets_interceptor:
                yield
        except Exception as e:
            self.monitor.log_event(
                event_type=EventType.VIOLATION,
                message=f"Exception in sandbox context: {str(e)}",
                severity=EventSeverity.ERROR,
                allowed=False,
            )
            raise
        finally:
            self.monitor.log_event(
                event_type=EventType.EXECUTION_END,
                message="Exiting sandbox context",
            )

    def get_audit_log(self, limit: Optional[int] = None) -> list:
        """Get audit log events.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of audit events
        """
        return [e.to_dict() for e in self.monitor.get_events(limit=limit)]

    def get_violations(self, limit: Optional[int] = None) -> list:
        """Get policy violations.

        Args:
            limit: Maximum number of violations to return

        Returns:
            List of violation events
        """
        return [e.to_dict() for e in self.monitor.get_violations(limit=limit)]

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary.

        Returns:
            Dictionary with execution statistics
        """
        return self.monitor.get_summary()

    def export_audit_log(self, filepath: str) -> None:
        """Export audit log to JSON file.

        Args:
            filepath: Path to output file
        """
        self.monitor.export_json(filepath)

    def reset(self) -> None:
        """Reset monitor and clear all events."""
        self.monitor.clear()
