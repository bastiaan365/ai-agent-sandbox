"""LangChain integration adapter for sandboxed tools."""

from typing import Any, Callable, Dict, List, Optional
from sandbox.core.runtime import SandboxRuntime
from sandbox.core.policy import PolicyEngine


class SandboxedLangChainTools:
    """Wraps LangChain tools with sandbox policy enforcement."""

    def __init__(
        self,
        tools: Optional[List[Any]] = None,
        policy_dict: Optional[Dict[str, Any]] = None,
        policy_file: Optional[str] = None,
    ):
        """Initialize sandboxed LangChain tools wrapper.

        Args:
            tools: List of LangChain Tool objects
            policy_dict: Policy configuration as dictionary
            policy_file: Path to YAML policy file
        """
        self.tools = tools or []

        # Create sandbox runtime
        if policy_file:
            self.runtime = SandboxRuntime()
            self.runtime.policy = PolicyEngine.from_yaml(policy_file)
        else:
            self.runtime = SandboxRuntime(policy_dict=policy_dict)

    def get_tools(self) -> List[Any]:
        """Get sandboxed tools.

        Returns:
            List of sandboxed Tool objects
        """
        sandboxed = []

        for tool in self.tools:
            # Create sandboxed version of tool function
            original_func = tool.func if hasattr(tool, "func") else tool.callback

            # Wrap with sandbox
            @self.runtime.sandboxed(timeout=30)
            def sandboxed_func(tool_input: str, _original=original_func):
                return _original(tool_input)

            # Create new tool with sandboxed function
            if hasattr(tool, "func"):
                tool.func = sandboxed_func
            else:
                tool.callback = sandboxed_func

            sandboxed.append(tool)

        return sandboxed

    def get_audit_log(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get audit log from sandbox runtime.

        Args:
            limit: Maximum number of events

        Returns:
            List of audit events
        """
        return self.runtime.get_audit_log(limit=limit)

    def get_violations(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get policy violations.

        Args:
            limit: Maximum number of violations

        Returns:
            List of violation events
        """
        return self.runtime.get_violations(limit=limit)

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary.

        Returns:
            Summary statistics
        """
        return self.runtime.get_summary()


def sandbox_tool(
    tool: Any,
    policy_dict: Optional[Dict[str, Any]] = None,
) -> Any:
    """Wrap a single LangChain tool with sandbox.

    Args:
        tool: LangChain Tool to wrap
        policy_dict: Optional policy configuration

    Returns:
        Sandboxed tool
    """
    wrapper = SandboxedLangChainTools(
        tools=[tool],
        policy_dict=policy_dict,
    )
    return wrapper.get_tools()[0]
