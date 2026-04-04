#!/usr/bin/env python3
"""LangChain integration example."""

from sandbox.core.runtime import SandboxRuntime
from sandbox.adapters.langchain import SandboxedLangChainTools
from sandbox.policies.defaults import WEB_AGENT_POLICY


class MockTool:
    """Mock LangChain Tool for demonstration."""

    def __init__(self, name, description, func):
        self.name = name
        self.description = description
        self.func = func

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


def read_file_tool(file_path: str) -> str:
    """Tool to read a file."""
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"


def write_file_tool(file_path: str, content: str) -> str:
    """Tool to write a file."""
    try:
        with open(file_path, "w") as f:
            f.write(content)
        return f"File written successfully: {file_path}"
    except Exception as e:
        return f"Error writing file: {e}"


def example_sandboxed_tools():
    """Demonstrate sandboxed LangChain tools."""
    print("=" * 60)
    print("LangChain Integration Example")
    print("=" * 60)

    # Create mock tools
    tools = [
        MockTool("read_file", "Read contents of a file", read_file_tool),
        MockTool("write_file", "Write content to a file", write_file_tool),
    ]

    # Wrap with sandbox
    sandboxed_tools = SandboxedLangChainTools(
        tools=tools,
        policy_dict=WEB_AGENT_POLICY,
    )

    # Get sandboxed versions
    safe_tools = sandboxed_tools.get_tools()

    print(f"Created {len(safe_tools)} sandboxed tools")

    # Try to use tools
    print("\nTest 1: Writing to allowed path (/tmp)")
    result = safe_tools[1].func("/tmp/langchain_test.txt", "Hello from LangChain!")
    print(f"Result: {result}")

    print("\nTest 2: Reading from allowed path (/tmp)")
    result = safe_tools[0].func("/tmp/langchain_test.txt")
    print(f"Result: {result}")

    print("\nTest 3: Trying to read from denied path (/etc/passwd)")
    result = safe_tools[0].func("/etc/passwd")
    print(f"Result: {result}")

    # Check audit log
    audit_log = sandboxed_tools.get_audit_log(limit=5)
    print(f"\nAudit Log ({len(audit_log)} events):")
    for event in audit_log:
        status = "ALLOWED" if event["allowed"] else "DENIED"
        print(f"  [{status}] {event['event_type']}: {event['message']}")

    # Check violations
    violations = sandboxed_tools.get_violations()
    if violations:
        print(f"\nViolations ({len(violations)}):")
        for v in violations[:3]:
            print(f"  - {v['message']}")

    # Summary
    summary = sandboxed_tools.get_summary()
    print(f"\nSummary:")
    print(f"  Total events: {summary['total_events']}")
    print(f"  Allowed: {summary['allowed_count']}")
    print(f"  Denied: {summary['denied_count']}")


def example_agent_simulation():
    """Simulate an AI agent using sandboxed tools."""
    print("\n" + "=" * 60)
    print("Agent Simulation Example")
    print("=" * 60)

    runtime = SandboxRuntime(policy_dict=WEB_AGENT_POLICY)

    # Simulate an agent that performs multiple operations
    @runtime.sandboxed(timeout=30)
    def agent_workflow():
        """Simulate an agent workflow."""
        steps = []

        # Step 1: Create a file
        try:
            with open("/tmp/agent_task.txt", "w") as f:
                f.write("Agent Task Log\n")
                f.write("===============\n\n")
            steps.append("✓ Created task log file")
        except Exception as e:
            steps.append(f"✗ Failed to create file: {e}")

        # Step 2: Write results
        try:
            with open("/tmp/agent_task.txt", "a") as f:
                f.write("Step 1: Task started\n")
                f.write("Step 2: Processed data\n")
                f.write("Step 3: Generated results\n")
            steps.append("✓ Wrote task results")
        except Exception as e:
            steps.append(f"✗ Failed to write results: {e}")

        # Step 3: Read results
        try:
            with open("/tmp/agent_task.txt", "r") as f:
                content = f.read()
            steps.append(f"✓ Read task results ({len(content)} bytes)")
        except Exception as e:
            steps.append(f"✗ Failed to read results: {e}")

        # Step 4: Try to access protected area (will fail)
        try:
            with open("/etc/shadow", "r") as f:
                f.read()
            steps.append("✗ Unexpectedly read /etc/shadow!")
        except Exception as e:
            steps.append(f"✓ Blocked access to /etc/shadow (as expected)")

        return "\n".join(steps)

    # Run agent
    output = agent_workflow()
    print(f"Agent Output:\n{output}")

    # Check audit trail
    print(f"\nAudit Trail:")
    events = runtime.get_audit_log(limit=10)
    for event in events:
        status = "✓" if event["allowed"] else "✗"
        print(f"  {status} {event['event_type']}: {event['message']}")

    # Export audit
    runtime.export_audit_log("/tmp/agent_audit.json")
    print(f"\nAudit log exported to /tmp/agent_audit.json")


if __name__ == "__main__":
    example_sandboxed_tools()
    example_agent_simulation()
    print("\n" + "=" * 60)
    print("LangChain examples completed!")
    print("=" * 60)
