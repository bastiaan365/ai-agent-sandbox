#!/usr/bin/env python3
"""Basic sandbox example - demonstrating file and network operations."""

from sandbox.core.runtime import SandboxRuntime
from sandbox.policies.defaults import RESTRICTIVE_POLICY, PERMISSIVE_POLICY


def example_restrictive():
    """Demonstrate restrictive policy."""
    print("=" * 60)
    print("Example 1: Restrictive Policy (No file/network access)")
    print("=" * 60)

    runtime = SandboxRuntime(policy_dict=RESTRICTIVE_POLICY)

    # Try to read a file (will be denied)
    @runtime.sandboxed(timeout=10)
    def read_file():
        try:
            with open("/etc/passwd", "r") as f:
                return f.read()
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"

    result = read_file()
    print(f"Result: {result}")

    # Try to write to temp (will be allowed)
    @runtime.sandboxed(timeout=10)
    def write_file():
        try:
            with open("/tmp/test.txt", "w") as f:
                f.write("Hello, Sandbox!")
            return "File written successfully"
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"

    result = write_file()
    print(f"Result: {result}")

    # Print audit log
    print("\nAudit Log:")
    for event in runtime.get_audit_log(limit=5):
        status = "ALLOWED" if event["allowed"] else "DENIED"
        print(f"  [{status}] {event['event_type']}: {event['message']}")

    # Print summary
    summary = runtime.get_summary()
    print(f"\nSummary: {summary['total_events']} events, {summary['denied_count']} denied")


def example_permissive():
    """Demonstrate permissive policy."""
    print("\n" + "=" * 60)
    print("Example 2: Permissive Policy (Allowed operations)")
    print("=" * 60)

    runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

    # Try to write to home directory (will be allowed)
    @runtime.sandboxed(timeout=10)
    def write_home():
        import os
        try:
            path = os.path.expanduser("~/sandbox_test.txt")
            with open(path, "w") as f:
                f.write("Test file in home directory")
            return f"File written to {path}"
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"

    result = write_home()
    print(f"Result: {result}")

    # Try to check environment (some vars protected)
    @runtime.sandboxed(timeout=10)
    def check_env():
        import os
        results = []
        results.append(f"PATH: {os.getenv('PATH', 'not found')[:50]}...")
        results.append(f"AWS_KEY: {os.getenv('AWS_KEY', 'not found')}")
        return "\n".join(results)

    result = check_env()
    print(f"\nEnvironment Check:\n{result}")

    # Print violations
    violations = runtime.get_violations()
    if violations:
        print(f"\nViolations ({len(violations)}):")
        for event in violations[:3]:
            print(f"  - {event['message']}")
    else:
        print("\nNo violations!")


def example_decorator():
    """Demonstrate decorator usage."""
    print("\n" + "=" * 60)
    print("Example 3: Using Decorator Syntax")
    print("=" * 60)

    runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

    # Define a function with decorator
    @runtime.sandboxed(timeout=10)
    def my_agent_task():
        """Sample agent task."""
        result = []
        result.append("Starting agent task...")

        # Write to temp
        with open("/tmp/agent_output.txt", "w") as f:
            f.write("Agent output here")
        result.append("Wrote to /tmp/agent_output.txt")

        # Read it back
        with open("/tmp/agent_output.txt", "r") as f:
            content = f.read()
        result.append(f"Read back: {content}")

        result.append("Agent task completed!")
        return "\n".join(result)

    output = my_agent_task()
    print(f"Output:\n{output}")

    # Check statistics
    summary = runtime.get_summary()
    print(f"\nStatistics:")
    print(f"  Total events: {summary['total_events']}")
    print(f"  Allowed: {summary['allowed_count']}")
    print(f"  Denied: {summary['denied_count']}")
    print(f"  By type: {summary['events_by_type']}")


def example_context_manager():
    """Demonstrate context manager usage."""
    print("\n" + "=" * 60)
    print("Example 4: Using Context Manager")
    print("=" * 60)

    runtime = SandboxRuntime(policy_dict=PERMISSIVE_POLICY)

    try:
        with runtime.sandbox_context(timeout=10):
            print("Inside sandbox context...")

            # These operations are sandboxed
            with open("/tmp/context_test.txt", "w") as f:
                f.write("Test from context manager")

            print("File written successfully!")

            with open("/tmp/context_test.txt", "r") as f:
                content = f.read()
                print(f"File contents: {content}")

    except Exception as e:
        print(f"Error: {e}")

    summary = runtime.get_summary()
    print(f"\nEvents in context: {summary['total_events']}")


if __name__ == "__main__":
    example_restrictive()
    example_permissive()
    example_decorator()
    example_context_manager()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)
