"""Network access interceptor."""

try:
    import urllib.request
    import urllib.error
    import http.client
except ImportError:
    pass

from typing import Any, Optional, Dict
from sandbox.core.policy import PolicyEngine
from sandbox.core.monitor import EventMonitor, EventType, EventSeverity


class NetworkAccessDenied(Exception):
    """Raised when network access is denied by policy."""
    pass


class NetworkInterceptor:
    """Intercepts network operations and enforces policy."""

    def __init__(self, policy: PolicyEngine, monitor: EventMonitor):
        """Initialize network interceptor.

        Args:
            policy: Policy engine
            monitor: Event monitor
        """
        self.policy = policy
        self.monitor = monitor
        self._active = False
        self._original_urlopen = None
        self._original_http_connect = None

    def __enter__(self):
        """Enter context and install interceptor."""
        self._active = True
        try:
            import urllib.request
            self._original_urlopen = urllib.request.urlopen
            urllib.request.urlopen = self._sandboxed_urlopen
        except (ImportError, AttributeError):
            pass

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original functions."""
        self._active = False
        try:
            import urllib.request
            if self._original_urlopen:
                urllib.request.urlopen = self._original_urlopen
        except (ImportError, AttributeError):
            pass
        return False

    def _sandboxed_urlopen(self, url: str, *args, **kwargs):
        """Sandboxed URL open function."""
        if not self._active:
            return self._original_urlopen(url, *args, **kwargs)

        # Parse URL
        if isinstance(url, str):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or "unknown"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except Exception as e:
                self.monitor.log_event(
                    event_type=EventType.NETWORK_REQUEST,
                    message=f"Failed to parse URL: {url}",
                    severity=EventSeverity.WARNING,
                    allowed=False,
                    details={"url": url, "error": str(e)},
                )
                raise NetworkAccessDenied(f"Invalid URL: {url}")
        else:
            self.monitor.log_event(
                event_type=EventType.NETWORK_REQUEST,
                message="Network access with non-string URL",
                severity=EventSeverity.WARNING,
                allowed=False,
            )
            raise NetworkAccessDenied("Only string URLs are allowed")

        # Check policy
        if not self.policy.network.is_host_allowed(host, port):
            self.monitor.log_event(
                event_type=EventType.NETWORK_REQUEST,
                message=f"Network access denied: {host}:{port}",
                severity=EventSeverity.ERROR,
                allowed=False,
                details={
                    "host": host,
                    "port": port,
                    "url": url,
                },
            )
            raise NetworkAccessDenied(f"Access denied: {host}:{port}")

        # Log the operation
        self.monitor.log_event(
            event_type=EventType.NETWORK_REQUEST,
            message=f"Network request: {host}:{port}",
            allowed=True,
            details={
                "host": host,
                "port": port,
                "url": url,
            },
        )

        # Call original urlopen
        return self._original_urlopen(url, *args, **kwargs)

    def check_host_allowed(self, host: str, port: int = 80) -> bool:
        """Check if host:port is allowed.

        Args:
            host: Hostname
            port: Port number

        Returns:
            True if allowed, False otherwise
        """
        return self.policy.network.is_host_allowed(host, port)

    def get_allowed_hosts(self) -> list:
        """Get list of allowed host patterns.

        Returns:
            List of allowed patterns
        """
        return self.policy.network.allowed_hosts.copy()

    def get_denied_hosts(self) -> list:
        """Get list of denied host patterns.

        Returns:
            List of denied patterns
        """
        return self.policy.network.denied_hosts.copy()
