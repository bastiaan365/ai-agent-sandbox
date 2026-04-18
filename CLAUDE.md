# ai-agent-sandbox

Runtime security sandbox for AI agents. Wraps Python-based agents with policy enforcement that intercepts file access, network calls, process execution, and secret usage. Maintained by Bastiaan ([@bastiaan365](https://github.com/bastiaan365)).

This file scopes Claude's behaviour for this repo. The global `~/.claude/CLAUDE.md` covers personal conventions; everything below is repo-specific.

## What this repo is

- A **defensive runtime library**: wrap an agent (LangChain / OpenAI Functions / generic Python) with `Sandbox`, define a YAML policy, and the sandbox enforces it on every operation. Violations get blocked + audit-logged.
- The companion to [`llm-red-team-toolkit`](https://github.com/bastiaan365/llm-red-team-toolkit): one breaks, this one defends.
- **Public security/AI-tooling project** — directly relevant to the security-engineer-with-AI-skills job market.

## Repo conventions

### Structure

```
sandbox/
├── cli.py
├── core/
│   ├── runtime.py      Sandbox context manager + decorator entry points
│   ├── policy.py       YAML policy loader + validator
│   └── monitor.py      audit logger
├── adapters/
│   ├── langchain.py
│   ├── openai_functions.py
│   └── generic.py
├── interceptors/       (referenced in runtime; file/network/process/secrets handlers)
└── utils/
examples/
├── basic_sandbox.py
└── langchain_example.py
tests/
IMPLEMENTATION_NOTES.md
```

### What this project must NEVER do

- **Be a sandbox-bypass tool.** This is defensive code. Adding "convenience" features that let agents punch through the policy defeats the entire purpose.
- **Trust agent-supplied paths or network targets.** All policy checks happen BEFORE the operation runs. Never log a "would have blocked" warning and then run the operation anyway — block means block.
- **Leak the policy contents to the agent under test.** The agent should not be able to read its own policy file via the sandboxed file interceptor; that's information that helps it craft bypasses.

### Python style

- Python 3.10+ target.
- `sandbox/` package; tests in `tests/`.
- Type hints on the public Sandbox API (`runtime.py` entry points), policy loader, all interceptors.
- Use `from __future__ import annotations` at top of every module that uses forward refs.
- Context-manager + decorator dual entry points — both must be tested.

### Examples directory

- `examples/` is committed and meant to be runnable AS-IS. Each example must work with `pip install -e .` and a default policy.
- Examples should NOT include real API keys, real customer data, or real credentials. Use placeholder values + comments noting where to set env vars.
- An example that's broken is worse than no example. Run them as part of pre-release checks.

### Testing

- pytest. Coverage focus areas:
  - Policy loader: YAML parsing, schema validation, error messages on bad input
  - Each interceptor: blocks-when-disallowed, allows-when-allowed, audit-logs-both
  - Adapters: LangChain / OpenAI Functions wrap correctly without leaking unsandboxed access
- Integration test with a tiny synthetic agent that tries (and is denied) a forbidden file read.

### Validation gates

Before any commit:

- `python -m py_compile sandbox/**/*.py`
- `pytest tests/ -v`
- **Examples actually run:**
  ```bash
  for ex in examples/*.py; do python -c "import ast; ast.parse(open('$ex').read())" && echo "$ex syntax OK"; done
  ```
  All should pass syntax check; ideally also run the tiny ones (`basic_sandbox.py`).
- **Policy-leak self-check:** confirm the policy file path is in the sandbox's default deny list for file reads (otherwise an agent could read its own policy).
  ```bash
  grep -A 5 "default_policy\|policy_path" sandbox/core/policy.py | head -20
  ```

## Workflow expectations for Claude

When I ask you to **add a new interceptor** (e.g., DNS, GPU access, clipboard):

1. Propose the interceptor's interface first as plain text — what does it intercept, what's the policy schema entry?
2. Add to `sandbox/interceptors/<name>.py` following the existing interceptor pattern (block-by-default, audit on every call).
3. Wire into `runtime.py` so it's part of the default sandbox stack.
4. Add tests in `tests/test_interceptors.py`: blocked-when-disallowed, allowed-when-allowed, audit-trail-emitted.
5. Update IMPLEMENTATION_NOTES.md and the README architecture diagram.

When I ask you to **add a new adapter** (e.g., LlamaIndex, AutoGen, custom framework):

1. Look at existing adapters (`langchain.py`, `openai_functions.py`) for the pattern.
2. Implement in `sandbox/adapters/<name>.py`.
3. Add an example in `examples/<name>_example.py` that's runnable with default policy.
4. Add tests in `tests/test_adapters.py` confirming the adapter wraps without leaking.

When I ask you to **modify the policy schema**:

1. **Treat as a breaking change** — existing user policies may stop validating. Show the migration path explicitly.
2. Bump a `schema_version` field in policies that don't have one yet.
3. Update IMPLEMENTATION_NOTES.md with the schema change.
4. Update tests + at least one example.

## Things to avoid

- Adding "trusted" or "bypass" categories to the policy schema. The whole point is no bypass.
- Logging at INFO level the contents of files the agent tried to read. Block silently or audit-only-the-attempt; never echo content.
- `subprocess.run(..., shell=True)` anywhere — defeats the process interceptor's purpose.
- Async-only adapters that can't work with sync agents. The library has to support both.
- `gh release` from automation — defensive security library, releases happen by my hand only.

## Related repos

- [`llm-red-team-toolkit`](https://github.com/bastiaan365/llm-red-team-toolkit) — the offensive counterpart; together they're a red+blue pair
- [`mcp-it-ops`](https://github.com/bastiaan365/mcp-it-ops) — same Python conventions
- [`iot-threat-detector`](https://github.com/bastiaan365/iot-threat-detector) — adjacent in spirit (runtime monitoring for security)

## Drift from target structure

_Claude maintains this section. List anything in the repo that doesn't match the conventions above, with why it's still there and what would need to happen to fix it._

- _(empty until first audit pass — fill on next session that actually edits code)_
