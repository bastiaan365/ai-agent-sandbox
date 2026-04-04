# AI Agent Sandbox

Runtime security sandbox for AI agents. Intercepts file access, network calls, process execution, and secret usage through YAML-based policies. Think of it as a firewall for what your AI agents can do on a system.

Built this after watching too many LangChain demos where the agent had unrestricted filesystem access. Cool demo, terrible idea in production. This wraps any Python-based agent with policy enforcement so you can actually control what it touches.

## How it works

Your agent code runs inside a sandbox runtime that checks every operation against a YAML policy:

```
Agent code
  └── Sandbox runtime (decorator or context manager)
        ├── File interceptor      (read/write/delete)
        ├── Network interceptor   (HTTP, DNS)
        ├── Process interceptor   (subprocess calls)
        ├── Secrets interceptor   (env vars, tokens)
        └── Resource limiter      (memory, timeout, ops count)
              └── Audit logger (JSON)
```

Everything gets logged. Violations get blocked and flagged.

## Install

```bash
git clone https://github.com/bastiaan365/ai-agent-sandbox.git
cd ai-agent-sandbox
pip install -e .
```

## Quick start

### As a decorator

```python
from sandbox.core.runtime import SandboxRuntime
from sandbox.policies.defaults import RESTRICTIVE_POLICY

runtime = SandboxRuntime(policy_dict=RESTRICTIVE_POLICY)

@runtime.sandboxed(timeout=30)
def my_agent():
    with open('/tmp/output.txt', 'w') as f:
        f.write('this is allowed')
    # trying to read /etc/shadow would get blocked
    return "done"
```

### CLI

```bash
# validate a policy
sandbox validate policies/restrictive.yaml

# run a script under policy
sandbox run --policy policies/restrictive.yaml agent_script.py

# start monitoring dashboard
sandbox monitor --port 5000

# view audit trail
sandbox audit --limit 50
```

### LangChain integration

```python
from sandbox.adapters.langchain import SandboxedLangChainTools

sandboxed = SandboxedLangChainTools(
    tools=my_langchain_tools,
    policy_file="policies/web_agent.yaml"
)
agent.tools = sandboxed.get_tools()
```

Drop-in replacement — your existing tools work the same, just with policy enforcement around them.

## Policy format

Policies are YAML files that define what's allowed:

```yaml
metadata:
  name: "web_agent"
  version: "1.0"

filesystem:
  max_file_size: 10485760
  allowed_paths:
    - "/tmp/**"
    - "/home/user/downloads/**"
  denied_paths:
    - "/etc/**"
    - "/root/**"

network:
  allowed_hosts:
    - "api.openai.com"
    - "*.github.com"
  denied_hosts:
    - "*.internal.corp"

processes:
  allowed_commands: ["curl", "python"]
  denied_commands: ["rm", "dd", "mkfs"]

secrets:
  protected_vars: ["API_KEY", "PASSWORD", "TOKEN"]

resources:
  max_memory_mb: 512
  max_timeout_seconds: 60
```

Three built-in templates: **restrictive** (default, very locked down), **permissive** (more room for general tasks), and **web_agent** (tuned for browsing/API agents).

## Monitoring

The Flask dashboard at `localhost:5000` shows live agent activity — execution status, policy violations, file access, network requests, and resource usage.

Audit logs are structured JSON, filterable by event type:

```bash
sandbox audit --filter violation
sandbox audit --output audit.json
```

## Project layout

```
sandbox/
├── core/
│   ├── runtime.py      # Main sandbox entry point
│   ├── policy.py       # YAML policy parsing + matching
│   └── interceptors/   # File, network, process, secrets
├── adapters/
│   └── langchain.py    # LangChain tool wrapper
├── dashboard/          # Flask monitoring UI
├── policies/           # Built-in templates
└── audit/              # JSON logging
tests/
examples/
```

## Limitations

This is **application-level** policy enforcement, not OS-level sandboxing. It intercepts Python calls — native C extensions could bypass it. For high-risk agents, use this alongside containers or VMs as part of a defense-in-depth setup.

Resource limits are approximate. Timing attacks and side channels are not addressed.

## Tests

```bash
pytest tests/ -v
pytest tests/test_interceptors.py -v
```

## Related

- [LLM Red Team Toolkit](https://github.com/bastiaan365/llm-red-team-toolkit) — offensive testing for LLM apps
- [MCP IT Ops](https://github.com/bastiaan365/mcp-it-ops) — MCP server where this kind of sandboxing would be useful

## License

MIT
