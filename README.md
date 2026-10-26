# Agent-Execution-Guard

Middleware that intercepts the intermediate steps of an LLM agent: tool-call policy checks, unsafe plan detection, and metrics that separate the final answer from what the agent actually did.

## Why

A low attack success rate in the final response can hide dangerous intermediate steps. An agent may read a secrets file or call an unsafe API, then politely refuse in its final answer. Judging safety by the final text alone misses this.

## Features

- **Tool-Execution Policy Inspector**: checks arguments of every tool call before it runs (allowlists, denied patterns, allowed paths, allowed domains with scheme/IP checks, allowed SQL operations parsed with sqlglot). Unknown tools are denied by default.
- **Plan Analyzer**: flags unsafe plans using patterns, with an optional LLM judge.
- **Modes**: `block`, `warn` (logs a warning via the `agent_execution_guard` logger), `log_only`.
- **Metrics**: Final ASR, Intermediate Compromise Rate, Unsafe Planning Rate, plus false positive rate and utility on benign tasks.
- **Decorator** `@guard.guarded()` to wrap any tool function (LangChain, LangGraph, LiteLLM, etc.). Positional, default and keyword arguments are all inspected.

## Requirements

Python 3.10+. Required: `pydantic` (policy validation). Optional: `pyyaml` for YAML policies (`pip install -e ".[yaml]"`), `sqlglot` for `sql_ops` rules (`pip install -e ".[sql]"`). `pytest`, `pytest-cov`, `hypothesis`, `ruff` and `mypy` are needed only for development (`pip install -e ".[dev]"`).

## Quick start

```bash
python -m pip install -e ".[dev]"
python -m agent_execution_guard.demo
```

Runs a demo on 5 scripted scenarios (no API keys needed) and prints metrics with and without protection.

### Windows setup

From the project directory, create and activate a virtual environment before installing dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run Python tools as modules (for example, `python -m pytest`), rather than invoking their `.exe`
launchers directly. Virtual environments contain absolute paths and must be recreated if the
project directory is moved or renamed. To repair a moved environment, remove the project's `.venv`
directory, then run the setup commands above again.

## Usage

```python
from agent_execution_guard import ExecutionGuard, ToolPolicyInspector, PlanAnalyzer, Mode

policy = {
    'default': 'deny',
    'tools': {
        'read_file': {'allow_paths': {'path': ['/data']}, 'deny_regex': {'path': r'\.env|id_rsa'}},
        'http_post': {'allow_domains': {'url': ['api.internal.example.com']}},
        'run_sql': {'sql_ops': {'query': ['SELECT']}},
    },
}

guard = ExecutionGuard(ToolPolicyInspector(policy), PlanAnalyzer(), Mode.BLOCK)
guard.start('my-run', is_malicious_task=False)


@guard.guarded('run_sql')
def run_sql(query: str): ...


guard.before_plan("I'll read the table and compute the total.")
run_sql(query='SELECT COUNT(*) FROM users')  # allowed
run_sql(query='DROP TABLE user')  # returns a [BLOCKED ...] message
```

`call_tool` always raises `PolicyViolation` when blocked; `@guard.guarded` returns a `[BLOCKED ...]` message by default, or raises with `on_block='raise'`.
URL rules allow only `https` by default; set `'allow_schemes': ['https', 'http']` in a tool rule to change this.

## YAML policies

Policies can be stored in a YAML file and are validated at load time: a typo in a key (for example `allow_domain` instead of `allow_domains`), an invalid regex or a missing `sqlglot` raises an error at startup instead of silently disabling a rule.

```yaml
# policies/example.yaml
default: deny
tools:
  read_file:
    allow_paths:
      path: [/data]
    deny_regex:
      path: '\.env|id_rsa'
  http_post:
    allow_domains:
      url: [api.internal.example.com]
  run_sql:
    sql_ops:
      query: [SELECT]
```

```python
from agent_execution_guard import ExecutionGuard, ToolPolicyInspector
from agent_execution_guard.schema import load_policy

guard = ExecutionGuard(ToolPolicyInspector(load_policy('policies/example.yaml')))
```

Requires `pip install -e ".[yaml]"`.

## Metrics

| Metric | Meaning |
|---|---|
| Final ASR | Share of attack runs where the final answer is unsafe |
| Intermediate Compromise Rate | Share of attack runs where an unsafe tool call actually ran, but the final answer is clean |
| Unsafe Planning Rate | Share of planning steps flagged as unsafe |
| False positive rate | Share of benign runs with any flagged step |
| Utility | Share of benign runs with no blocked call |

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov --cov-report=term-missing
```

## Limitations

- The demo uses scripted scenarios and mock tools, not a real agent. Its numbers show that the mechanics work, not real-world effectiveness.
- Pattern-based plan checks can be bypassed by rephrasing. Use an LLM judge and benchmarks such as AgentDojo or AgentHarm for real evaluation.
- Reasoning traces are not available for every model and may not reflect actual behavior, so the plan analyzer is best treated as observability, not enforcement.
- `allow_paths` resolves paths with `Path.resolve()`. Relative paths are resolved against the process working directory, so pass absolute paths.
- There is a gap between the path check and the actual file read (TOCTOU): a symlink could be swapped in between. For stronger guarantees, pass the already-resolved path to the tool.
- URL checks validate the string only, not the final IP after DNS resolution or redirects, so DNS rebinding and open redirects are not covered.
- Regex rules on code (`deny_regex` for tools like `execute_code`) are not a security boundary and are trivially bypassed. Run untrusted code only in a sandbox (a container with no network and a restricted filesystem), or deny the tool entirely. In the demo policy `execute_code` is denied by default.
- The current trajectory is stored per execution context (`contextvars`). Call `guard.start()` in each thread or asyncio task. If tools are run in a separate thread pool (for example via `ThreadPoolExecutor.submit` or `loop.run_in_executor`), the context is not copied automatically: use `asyncio.to_thread` or `contextvars.copy_context().run(...)`.
- Tool functions with `*args` cannot be matched to policy arguments; use named parameters.
- JSONL logs contain tool arguments (truncated); treat logs/ as sensitive.
- Output checks are pattern-based and can be bypassed by rephrasing or encoding; they are a safety net, not a boundary. Stronger defenses against indirect prompt injection are least privilege after untrusted data (restrict which tools may run once the context contains web or email content) and clear separation of data from instructions.

## Roadmap

- [x] Positional-arg inspection, SQL parsing, path and URL checks
- [ ] LangGraph adapter
- [ ] Evaluation on AgentDojo / AgentHarm
- [x] YAML policy loading