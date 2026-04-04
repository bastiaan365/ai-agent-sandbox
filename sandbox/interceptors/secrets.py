"""Secrets/environment variable access interceptor."""

import os
from typing import Optional, Dict, Any
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor, EventType, EventSeverity


class SecretAccessDenied(Exception):
    """Raised when secret/credential access is denied by policy."""
    pass


class SecretsInterceptor:
    """Intercepts environment variable access and enforces policy."""

    def __init__(self, policy: PolicyEngine, monitor: EventMonitor):
        """Initialize secrets interceptor.

        Args:
            policy: Policy engine
            monitor: Event monitor
        """
        self.policy = policy
        self.monitor = monitor
        self._active = False
        self._original_getenv = os.getenv
        self._original_environ = None

    def __enter__(self):
        """Enter context and install interceptor."""
        self._active = True
        os.getenv = self._sandboxed_getenv
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original functions."""
        self._active = False
        os.getenv = self._original_getenv
        return False

    def _sandboxed_getenv(
        self,
        key: str,
        default: Optional[str] = None,
    ) -> Optional[str]:
        """Sandboxed getenv function."""
        if not self._active:
            return self._original_getenv(key, default)

        # Check if variable is protected
        if self.policy.secrets.is_var_protected(key):
            self.monitor.log_event(
                event_type=EventType.SECRET_ACCESS,
                message=f"Protected environment variable access denied: {key}",
                severity=EventSeverity.WARNING,
                allowed=False,
                details={
                    "variable": key,
                },
            )
            # Return default instead of raising
            return default

        # Log access to sensitive-looking variables
        if any(term in key.upper() for term in ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API"]):
            self.monitor.log_event(
                event_type=EventType.SECRET_ACCESS,
                message=f"Potentially sensitive variable access: {key}",
                severity=EventSeverity.INFO,
                allowed=True,
                details={
                    "variable": key,
                },
            )

        return self._original_getenv(key, default)

    def check_var_protected(self, var_name: str) -> bool:
        """Check if variable is protected.

        Args:
            var_name: Variable name

        Returns:
            True if protected, False otherwise
        """
        return self.policy.secrets.is_var_protected(var_name)

    def get_protected_vars(self) -> list:
        """Get list of protected variable patterns.

        Returns:
            List of protected patterns
        """
        return self.policy.secrets.protected_vars.copy()

    def filter_dict(self, env_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Filter dictionary to remove protected variables.

        Args:
            env_dict: Dictionary to filter

        Returns:
            Filtered dictionary
        """
        return {
            k: v for k, v in env_dict.items()
            if not self.policy.secrets.is_var_protected(k)
        }
