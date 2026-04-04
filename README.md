# AI Agent Sandbox

A comprehensive security sandbox and runtime environment for AI agents. Monitor and control system interactions (file access, network calls, process execution, secrets) through YAML-based policies.

## Features

- **Policy Engine**: YAML-based policies defining allowed/denied operations
- **Real-time Monitoring**: Track all agent activities with structured logging
- **Multiple Interceptors**: File, network, process, and secret access control
- **Audit Trail**: Complete JSON audit log of all sandbox events
- **Web Dashboard**: Flask-based real-time monitoring interface
- **LangChain Integration**: Drop-in wrapper for LangChain tools
- **Built-in Policy Templates**: Restrictive, permissive, and web-agent policies
- **CLI Interface**: Easy-to-use command-line tools

## Architecture

```
┌─────────────────────────────┐
│   AI Agent Code             │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│  Sandbox Runtime            │
│  (Decorator/Context Mgr)    │
└──────────────┬──────────────┘
               │
       ┌───────┼────────┬────────────┬─────────────┐
       │       │        │            │             │
   ┌───▼─┐ ┌──▼──┐ ┌───▼───┐ ┌─────▼────┐ ┌─────▼────┐
   │File │ │Net  │ │Process│ │Secrets   │ │Resource  │
   │     │ │     │ │       │ │Mgr       │ │Limits    │
   └─────┘ └─────┘ └───────┘ └──────────┘ └──────────┘
       │       │        │            │             │
       └───────┼────────┴────────────┴─────────────┘
               │
       ┌───────▼──────────┐
       │  Audit Logger    │
       │  (JSON format)   │
       └──────────────────┘
```

## Installation

```bash
# Clone and install
git clone <repo>
cd ai-agent-sandbox
pip install -e .
```

Or via pip:
```bash
pip install ai-agent-sandbox
```

## Quick Start

### 1. Run Agent in Sandbox

```python
from sandbox.core.runtime import SandboxRuntime
from sandbox.policies.defaults import RESTRICTIVE_POLICY

runtime = SandboxRuntime(policy_dict=RESTRICTIVE_POLICY)

# Wrap your agent function
@runtime.sandboxed(timeout=30)
def my_agent():
    # Your agent code
    with open('/tmp/allowed.txt', 'w') as f:
        f.write('Hello')
    return "Done"

result = my_agent()
```

### 2. Use CLI

```bash
# Validate a policy file
sandbox validate policies/restrictive.yaml

# Run agent with policy
sandbox run --policy policies/restrictive.yaml my_script.py

# Start monitoring dashboard
sandbox monitor --port 5000

# View audit trail
sandbox audit --limit 50
```

### 3. LangChain Integration

```python
from sandbox.adapters.langchain import SandboxedLangChainTools
from langchain.agents import Tool

tools = [
    Tool(name="read_file", func=read_file_func, description="Read file"),
]

sandboxed_tools = SandboxedLangChainTools(
    tools=tools,
    policy_file="policies/web_agent.yaml"
)

# Now tools are sandboxed!
agent.tools = sandboxed_tools.get_tools()
```

## Policy Format

Policies are YAML files defining what agents can do:

```yaml
metadata:
  name: "web_agent"
  version: "1.0"
  description: "Policy for web browsing agents"

filesystem:
  max_file_size: 10485760  # 10MB
  allowed_paths:
    - "/tmp/**"
    - "/home/user/downloads/**"
  denied_paths:
    - "/etc/**"
    - "/root/**"

network:
  allowed_hosts:
    - "api.example.com"
    - "*.github.com"
  denied_hosts:
    - "*.internal.corp"
  allowed_ports: [80, 443]

processes:
  allowed_commands:
    - "curl"
    - "python"
  denied_commands:
    - "rm"
    - "dd"
    - "mkfs"

secrets:
  protected_vars:
    - "API_KEY"
    - "PASSWORD"
    - "TOKEN"

resources:
  max_memory_mb: 512
  max_timeout_seconds: 60
  max_file_ops: 1000
```

## Policy Templates

### Restrictive (Default)
- Only read-only file access to whitelisted paths
- No network access
- No subprocess execution
- No secret access
- 30-second timeout

### Permissive
- Read/write to `/tmp` and user home
- Limited network (common APIs)
- Subprocess execution for safe commands
- Some environment variable access
- 5-minute timeout

### Web Agent
- Read/write to temp/downloads
- Network access to common APIs (GitHub, OpenAI, etc.)
- curl/wget for HTTP
- No filesystem deletion
- 2-minute timeout

## Monitoring & Audit

### Real-time Dashboard
```bash
sandbox monitor --port 5000
# Visit http://localhost:5000
```

Shows:
- Agent execution status
- Policy violations in real-time
- Network requests
- File access patterns
- Resource usage

### Audit Log
```bash
# View last 50 events
sandbox audit --limit 50

# View violations only
sandbox audit --filter violation

# Export to file
sandbox audit --output audit.json
```

## Examples

See `/examples/` directory:
- `basic_sandbox.py`: Simple file/network operations
- `langchain_example.py`: Integration with LangChain agents

Run examples:
```bash
python examples/basic_sandbox.py
```

## Testing

```bash
pytest tests/
pytest tests/test_policy.py -v
pytest tests/test_interceptors.py -v
```

## Architecture Details

### Runtime
- Entry point for sandboxing
- Applies policy to execution context
- Manages interceptor lifecycle
- Handles timeout and resource limits

### Policy Engine
- Parses YAML policies
- Glob pattern matching for paths
- Validates requests against rules
- Caches compiled rules

### Interceptors
- **FileSystem**: `open()`, path traversal, size limits
- **Network**: HTTP/DNS requests, host/port filtering
- **Process**: `subprocess`, dangerous commands
- **Secrets**: Environment variable filtering

### Audit Logger
- Structured JSON logging
- Timestamps and request IDs
- Violation flagging
- Searchable event database

## Security Considerations

1. **Not a Container**: This is NOT a full OS-level sandbox. It's for policy enforcement at the application level.
2. **Python-Only**: Interception works for Python code. Native C extensions may bypass.
3. **Defense in Depth**: Use alongside OS-level controls (containers, VMs) for high-risk agents.
4. **Policy Validation**: Always validate policies before deployment.

## Limitations

- Does not prevent all side channels
- No protection against timing attacks
- Resource limits are approximate
- Cannot prevent all subprocess escapes

## Contributing

Contributions welcome! Please:
1. Add tests for new features
2. Update documentation
3. Follow black/isort formatting

## License

MIT License - see LICENSE file

## Support

Issues and questions: GitHub Issues
