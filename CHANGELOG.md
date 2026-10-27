   # Changelog

   ## 0.2.0
   - Fixed: positional and default arguments are now inspected by `@guard.guarded`
   - Added: `on_block` option, real `warn` mode via logging
   - Added: SQL parsing with sqlglot (fail closed), `allow_paths`, stricter URL checks
   - Changed: trajectory stored per context (`contextvars`); `execute_code` denied by default in demo policy

   ## 0.2.1
   - Fixed: malformed URLs no longer crash the inspector; they are blocked (fail closed)
   - Added: regression, coverage (pytest-cov) and property-based (hypothesis) tests
   
   ## 0.3.0
   - Changed: code split into the `agent_execution_guard` package (`python -m agent_execution_guard.demo`)
   - Added: validated policies (pydantic), YAML loading, startup errors for typos and missing sqlglot
   - Added: JSONL event log, trajectory export
   - Added: `after_tool_call` hook (secret redaction, prompt-injection detection), `Tainted Tool Output Rate`