"""Command-line interface for sandbox."""

import json
import sys
import click
from pathlib import Path
from sandbox.core.runtime import SandboxRuntime
from sandbox.core.policy import PolicyEngine
from sandbox.utils.helpers import (
    load_policy_file,
    load_audit_log,
    format_audit_event,
    print_policy_summary,
)
from sandbox.policies.defaults import RESTRICTIVE_POLICY, PERMISSIVE_POLICY, WEB_AGENT_POLICY


@click.group()
def main():
    """AI Agent Sandbox - Security sandbox for AI agents."""
    pass


@main.command()
@click.option("--policy", type=click.Path(exists=True), help="Path to policy YAML file")
@click.option("--policy-type", type=click.Choice(["restrictive", "permissive", "web-agent"]), help="Use built-in policy")
def validate(policy, policy_type):
    """Validate a sandbox policy file."""
    if policy and policy_type:
        click.echo("Error: Specify either --policy or --policy-type, not both")
        sys.exit(1)

    if policy_type:
        policies = {
            "restrictive": RESTRICTIVE_POLICY,
            "permissive": PERMISSIVE_POLICY,
            "web-agent": WEB_AGENT_POLICY,
        }
        policy_dict = policies[policy_type]
        click.echo(f"Validating built-in policy: {policy_type}")
    elif policy:
        try:
            policy_dict = load_policy_file(policy)
            click.echo(f"Validating policy: {policy}")
        except Exception as e:
            click.echo(f"Error loading policy: {e}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: Specify --policy or --policy-type")
        sys.exit(1)

    # Validate
    engine = PolicyEngine(policy_dict)
    errors = engine.validate()

    if errors:
        click.echo("Validation warnings:")
        for error in errors:
            click.echo(f"  - {error}")
    else:
        click.echo("Policy is valid!")

    # Print summary
    print_policy_summary(policy_dict)


@main.command()
@click.argument("script", type=click.Path(exists=True))
@click.option("--policy", type=click.Path(exists=True), help="Path to policy YAML file")
@click.option("--policy-type", type=click.Choice(["restrictive", "permissive", "web-agent"]), default="restrictive", help="Use built-in policy")
@click.option("--timeout", type=int, default=60, help="Timeout in seconds")
@click.option("--audit", type=click.Path(), help="Path to audit log file")
def run(script, policy, policy_type, timeout, audit):
    """Run a Python script in the sandbox."""
    # Load policy
    if policy:
        try:
            policy_dict = load_policy_file(policy)
        except Exception as e:
            click.echo(f"Error loading policy: {e}", err=True)
            sys.exit(1)
    else:
        policies = {
            "restrictive": RESTRICTIVE_POLICY,
            "permissive": PERMISSIVE_POLICY,
            "web-agent": WEB_AGENT_POLICY,
        }
        policy_dict = policies[policy_type]

    # Create runtime
    runtime = SandboxRuntime(policy_dict=policy_dict, audit_file=audit)

    # Load and execute script
    try:
        with open(script, "r") as f:
            code = f.read()

        # Execute in sandbox
        @runtime.sandboxed(timeout=timeout)
        def run_script():
            exec(code, {"__name__": "__main__"})

        run_script()
        click.echo("Script execution completed successfully")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Print summary
    summary = runtime.get_summary()
    click.echo("\nExecution Summary:")
    click.echo(f"  Total events: {summary['total_events']}")
    click.echo(f"  Allowed: {summary['allowed_count']}")
    click.echo(f"  Denied: {summary['denied_count']}")

    if audit:
        click.echo(f"\nAudit log written to: {audit}")


@main.command()
@click.option("--port", type=int, default=5000, help="Port for dashboard")
@click.option("--audit", type=click.Path(exists=True), help="Path to audit log file")
def monitor(port, audit):
    """Start real-time monitoring dashboard."""
    try:
        from flask import Flask, render_template_string, jsonify
    except ImportError:
        click.echo("Error: Flask is required for monitoring. Install with: pip install flask")
        sys.exit(1)

    app = Flask(__name__)

    # Load audit log if provided
    audit_events = []
    if audit:
        audit_events = load_audit_log(audit)

    @app.route("/")
    def dashboard():
        """Serve dashboard HTML."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sandbox Monitor</title>
            <style>
                body { font-family: Arial; margin: 20px; background: #f5f5f5; }
                h1 { color: #333; }
                .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }
                .stat { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
                .stat-label { color: #666; font-size: 14px; }
                table { width: 100%; background: white; border-collapse: collapse; margin: 20px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                th { background: #007bff; color: white; padding: 10px; text-align: left; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
                tr:hover { background: #f9f9f9; }
                .allowed { background: #d4edda; }
                .denied { background: #f8d7da; }
                .warning { background: #fff3cd; }
            </style>
            <script>
                function refreshStats() {
                    fetch('/api/stats')
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('total').textContent = data.total_events;
                            document.getElementById('allowed').textContent = data.allowed_count;
                            document.getElementById('denied').textContent = data.denied_count;
                        });
                }
                setInterval(refreshStats, 2000);
            </script>
        </head>
        <body>
            <h1>Sandbox Monitor</h1>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="total">0</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="allowed">0</div>
                    <div class="stat-label">Allowed</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="denied">0</div>
                    <div class="stat-label">Denied</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Status</div>
                    <div style="color: #28a745; font-weight: bold;">Running</div>
                </div>
            </div>
            <h2>Recent Events</h2>
            <table id="events">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Message</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </body>
        </html>
        """
        return render_template_string(html)

    @app.route("/api/stats")
    def api_stats():
        """Get statistics."""
        return jsonify({
            "total_events": len(audit_events),
            "allowed_count": sum(1 for e in audit_events if e.get("allowed", True)),
            "denied_count": sum(1 for e in audit_events if not e.get("allowed", True)),
        })

    @app.route("/api/events")
    def api_events():
        """Get recent events."""
        return jsonify(audit_events[-50:])

    click.echo(f"Starting dashboard on http://localhost:{port}")
    click.echo("Press Ctrl+C to stop")
    app.run(host="0.0.0.0", port=port, debug=False)


@main.command()
@click.option("--audit", type=click.Path(exists=True), help="Path to audit log file")
@click.option("--limit", type=int, default=50, help="Maximum events to show")
@click.option("--filter", type=click.Choice(["allowed", "denied", "violation", "file", "network", "process"]), help="Filter by type")
@click.option("--output", type=click.Path(), help="Export to JSON file")
def audit(audit, limit, filter, output):
    """View audit trail."""
    if not audit:
        audit = "audit.log"

    try:
        events = load_audit_log(audit)
    except Exception as e:
        click.echo(f"Error loading audit log: {e}", err=True)
        sys.exit(1)

    # Filter events
    if filter == "allowed":
        events = [e for e in events if e.get("allowed", True)]
    elif filter == "denied":
        events = [e for e in events if not e.get("allowed", True)]
    elif filter == "violation":
        events = [e for e in events if e.get("event_type") == "violation"]
    elif filter:
        events = [e for e in events if filter in e.get("event_type", "")]

    # Limit results
    events = events[-limit:]

    # Export to file if requested
    if output:
        with open(output, "w") as f:
            json.dump(events, f, indent=2)
        click.echo(f"Exported {len(events)} events to {output}")
    else:
        # Display events
        if not events:
            click.echo("No events found")
        else:
            for event in events:
                formatted = format_audit_event(event)
                if not event.get("allowed", True):
                    click.secho(formatted, fg="red")
                elif event.get("severity") == "warning":
                    click.secho(formatted, fg="yellow")
                else:
                    click.echo(formatted)

    # Summary
    click.echo()
    click.echo(f"Total events: {len(events)}")
    click.echo(f"Allowed: {sum(1 for e in events if e.get('allowed', True))}")
    click.echo(f"Denied: {sum(1 for e in events if not e.get('allowed', True))}")


if __name__ == "__main__":
    main()
