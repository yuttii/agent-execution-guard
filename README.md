# Agent-Execution-Guard

Middleware that intercepts the intermediate steps of an LLM agent: tool-call policy checks, unsafe plan detection, and metrics that separate the final answer from what the agent actually did.

## Why

A low attack success rate in the final response can hide dangerous intermediate steps. An agent may read a secrets file or call an unsafe API, then politely refuse in its final answer. Judging safety by the final text alone misses this.

## Features

- **Tool-Execution Policy Inspector**: checks arguments of every tool call before it runs (allowlists, denied patterns, allowed domains, allowed SQL operations). Unknown tools are denied by default.
- **Plan Analyzer**: flags unsafe plans using patterns, with an optional LLM judge.
- **Modes**: `block`, `warn`, `log_only`.
- **Metrics**: Final ASR, Intermediate Compromise Rate, Unsafe Planning Rate, plus false positive rate and utility on benign tasks.
- **Decorator** `@guard.guarded()` to wrap any tool function (LangChain, LangGraph, LiteLLM, etc.).

## Requirements

Python 3.10+. The core has no dependencies. `pytest` is needed only for tests.

## Quick start

```bash
python guard.py
```

Runs a demo on 5 scripted scenarios (no API keys needed) and prints metrics with and without protection.

## Usage

```python
from guard import ExecutionGuard, ToolPolicyInspector, PlanAnalyzer, Mode

policy = {
    'default': 'deny',
    'tools': {
        'read_file': {'deny_regex': {'path': r'\.env|id_rsa|/etc/passwd'}},
        'http_post': {'allow_domains': {'url': ['api.internal.example.com']}},
        'run_sql':   {'sql_ops': {'query': ['SELECT']}},
    },
}

guard = ExecutionGuard(ToolPolicyInspector(policy), PlanAnalyzer(), Mode.BLOCK)
guard.start('my-run', is_malicious_task = False)

@guard.guarded('run_sql')
def run_sql(query: str):
    ...

guard.before_plan("I'll read the table and compute the total.")
run_sql(query = 'SELECT COUNT(*) FROM users')   # allowed
run_sql(query = 'DROP TABLE user')             # returns a [BLOCKED ...] message
```

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
pip install pytest
python -m pytest -v
```

## Limitations

- The demo uses scripted scenarios and mock tools, not a real agent. Its numbers show that the mechanics work, not real-world effectiveness.
- Pattern-based plan checks can be bypassed by rephrasing. Use an LLM judge and benchmarks such as AgentDojo or AgentHarm for real evaluation.
- Reasoning traces are not available for every model and may not reflect actual behavior, so the plan analyzer is best treated as observability, not enforcement.

## Roadmap

- LangGraph adapter
- Evaluation on AgentDojo / AgentHarm
- YAML policy loading