"""Real-time event monitoring and audit logging."""

import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pathlib import Path


class EventType(str, Enum):
    """Types of sandbox events."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_REQUEST = "network_request"
    PROCESS_EXEC = "process_exec"
    SECRET_ACCESS = "secret_access"
    VIOLATION = "violation"
    EXECUTION_START = "execution_start"
    EXECUTION_END = "execution_end"


class EventSeverity(str, Enum):
    """Event severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class SandboxEvent:
    """A sandbox event for audit trail."""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    event_type: EventType = EventType.EXECUTION_START
    severity: EventSeverity = EventSeverity.INFO
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    allowed: bool = True
    agent_id: Optional[str] = None
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result["event_type"] = self.event_type.value
        result["severity"] = self.severity.value
        return result


class EventMonitor:
    """Monitors and logs sandbox events."""

    def __init__(self, audit_file: Optional[str] = None, agent_id: Optional[str] = None):
        """Initialize event monitor.

        Args:
            audit_file: Path to audit log file (JSON lines format)
            agent_id: Optional agent identifier
        """
        self.agent_id = agent_id
        self.audit_file = audit_file
        self.events: List[SandboxEvent] = []
        self.lock = threading.Lock()

        # Setup file logging if specified
        if audit_file:
            self.audit_path = Path(audit_file)
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)

        # Setup Python logging
        self.logger = logging.getLogger(f"sandbox.{agent_id or 'default'}")
        self.logger.setLevel(logging.DEBUG)

    def log_event(
        self,
        event_type: EventType,
        message: str,
        severity: EventSeverity = EventSeverity.INFO,
        details: Optional[Dict[str, Any]] = None,
        allowed: bool = True,
        request_id: Optional[str] = None,
    ) -> SandboxEvent:
        """Log an event.

        Args:
            event_type: Type of event
            message: Event message
            severity: Severity level
            details: Additional details
            allowed: Whether action was allowed
            request_id: Optional request ID

        Returns:
            The created event
        """
        event = SandboxEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            allowed=allowed,
            agent_id=self.agent_id,
            request_id=request_id,
        )

        with self.lock:
            self.events.append(event)

            # Log to file if configured
            if self.audit_file:
                self._write_event_to_file(event)

            # Log to Python logger
            level = {
                EventSeverity.INFO: logging.INFO,
                EventSeverity.WARNING: logging.WARNING,
                EventSeverity.ERROR: logging.ERROR,
            }.get(severity, logging.INFO)

            self.logger.log(level, f"[{event_type.value}] {message}")

        return event

    def _write_event_to_file(self, event: SandboxEvent) -> None:
        """Write event to audit file (JSON lines)."""
        try:
            with open(self.audit_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write audit event: {e}")

    def get_events(
        self,
        event_type: Optional[EventType] = None,
        severity: Optional[EventSeverity] = None,
        allowed: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> List[SandboxEvent]:
        """Get events with optional filtering.

        Args:
            event_type: Filter by event type
            severity: Filter by severity
            allowed: Filter by allowed/denied
            limit: Maximum results

        Returns:
            List of matching events
        """
        with self.lock:
            filtered = self.events

            if event_type:
                filtered = [e for e in filtered if e.event_type == event_type]
            if severity:
                filtered = [e for e in filtered if e.severity == severity]
            if allowed is not None:
                filtered = [e for e in filtered if e.allowed == allowed]

            if limit:
                filtered = filtered[-limit:]

            return filtered

    def get_violations(self, limit: Optional[int] = None) -> List[SandboxEvent]:
        """Get denied/violation events.

        Args:
            limit: Maximum results

        Returns:
            List of violation events
        """
        with self.lock:
            violations = [e for e in self.events if not e.allowed or e.event_type == EventType.VIOLATION]
            if limit:
                violations = violations[-limit:]
            return violations

    def clear(self) -> None:
        """Clear all events from memory."""
        with self.lock:
            self.events.clear()

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        with self.lock:
            total = len(self.events)
            allowed = sum(1 for e in self.events if e.allowed)
            denied = sum(1 for e in self.events if not e.allowed)

            events_by_type = {}
            for event in self.events:
                key = event.event_type.value
                events_by_type[key] = events_by_type.get(key, 0) + 1

            return {
                "total_events": total,
                "allowed_count": allowed,
                "denied_count": denied,
                "events_by_type": events_by_type,
                "agent_id": self.agent_id,
            }

    def export_json(self, filepath: str) -> None:
        """Export all events as JSON."""
        with self.lock:
            events_data = [e.to_dict() for e in self.events]

        with open(filepath, "w") as f:
            json.dump(
                {
                    "agent_id": self.agent_id,
                    "total_events": len(events_data),
                    "events": events_data,
                },
                f,
                indent=2,
            )
