"""OpenAI function calling wrapper with sandbox integration."""

from typing import Any, Callable, Dict, List, Optional
from sandbox.core.runtime import SandboxRuntime


class SandboxedOpenAIFunctions:
    """Wraps OpenAI function specifications with sandbox enforcement."""

    def __init__(
        self,
        functions: Optional[List[Dict[str, Any]]] = None,
        policy_dict: Optional[Dict[str, Any]] = None,
        implementations: Optional[Dict[str, Callable]] = None,
    ):
        """Initialize sandboxed OpenAI functions wrapper.

        Args:
            functions: List of OpenAI function definitions
            policy_dict: Policy configuration
            implementations: Mapping of function names to implementations
        """
        self.functions = functions or []
        self.implementations = implementations or {}
        self.runtime = SandboxRuntime(policy_dict=policy_dict)

    def register_implementation(self, name: str, func: Callable) -> None:
        """Register function implementation.

        Args:
            name: Function name
            func: Implementation function
        """
        self.implementations[name] = func

    def execute_function(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Execute function in sandbox.

        Args:
            name: Function name
            arguments: Function arguments

        Returns:
            Function result
        """
        if name not in self.implementations:
            raise ValueError(f"Function {name} not registered")

        func = self.implementations[name]

        @self.runtime.sandboxed(timeout=30)
        def wrapped():
            return func(**arguments)

        return wrapped()

    def execute_from_completion(self, completion: Dict[str, Any]) -> Any:
        """Execute function from OpenAI completion response.

        Args:
            completion: OpenAI completion with function_call

        Returns:
            Function result
        """
        if "function_call" not in completion:
            raise ValueError("No function_call in completion")

        function_call = completion["function_call"]
        name = function_call["name"]

        # Parse arguments
        import json
        try:
            arguments = json.loads(function_call["arguments"])
        except json.JSONDecodeError:
            arguments = {}

        return self.execute_function(name, arguments)

    def get_audit_log(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get audit log.

        Args:
            limit: Maximum events

        Returns:
            Audit events
        """
        return self.runtime.get_audit_log(limit=limit)

    def get_violations(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get policy violations.

        Args:
            limit: Maximum violations

        Returns:
            Violation events
        """
        return self.runtime.get_violations(limit=limit)
