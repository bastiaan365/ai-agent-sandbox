"""Generic subprocess adapter for sandboxing commands."""

import subprocess
from typing import Callable, List, Optional, Dict, Any
from sandbox.core.runtime import SandboxRuntime
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor


class SandboxedSubprocess:
    """Wraps subprocess calls with sandbox policy enforcement."""

    def __init__(self, runtime: SandboxRuntime):
        """Initialize sandboxed subprocess wrapper.

        Args:
            runtime: Sandbox runtime instance
        """
        self.runtime = runtime
        self.policy = runtime.policy
        self.monitor = runtime.monitor

    def run(
        self,
        args: List[str],
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Run subprocess in sandbox.

        Args:
            args: Command arguments
            **kwargs: Additional subprocess.run arguments

        Returns:
            CompletedProcess result
        """
        with self.runtime.sandbox_context():
            return subprocess.run(args, **kwargs)

    def check_output(
        self,
        args: List[str],
        **kwargs,
    ) -> bytes:
        """Run subprocess and get output in sandbox.

        Args:
            args: Command arguments
            **kwargs: Additional subprocess.check_output arguments

        Returns:
            Captured output
        """
        with self.runtime.sandbox_context():
            return subprocess.check_output(args, **kwargs)

    def popen(
        self,
        args: List[str],
        **kwargs,
    ) -> subprocess.Popen:
        """Create Popen instance in sandbox.

        Args:
            args: Command arguments
            **kwargs: Additional Popen arguments

        Returns:
            Popen instance
        """
        # Note: Popen will be sandboxed by interceptor
        return subprocess.Popen(args, **kwargs)


class SandboxedFunction:
    """Wraps a Python function with sandbox execution."""

    def __init__(self, func: Callable, runtime: SandboxRuntime):
        """Initialize sandboxed function wrapper.

        Args:
            func: Function to wrap
            runtime: Sandbox runtime instance
        """
        self.func = func
        self.runtime = runtime
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __call__(self, *args, **kwargs) -> Any:
        """Call function in sandbox.

        Args:
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function return value
        """
        return self.runtime._execute_sandboxed(
            func=self.func,
            args=args,
            kwargs=kwargs,
        )


def create_sandboxed_function(
    func: Callable,
    policy: Optional[Dict[str, Any]] = None,
) -> SandboxedFunction:
    """Create a sandboxed version of a function.

    Args:
        func: Function to sandbox
        policy: Optional policy configuration

    Returns:
        Sandboxed function wrapper
    """
    runtime = SandboxRuntime(policy_dict=policy)
    return SandboxedFunction(func, runtime)
