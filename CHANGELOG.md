   # Changelog

   ## 0.2.0
   - Fixed: positional and default arguments are now inspected by `@guard.guarded`
   - Added: `on_block` option, real `warn` mode via logging
   - Added: SQL parsing with sqlglot (fail closed), `allow_paths`, stricter URL checks
   - Changed: trajectory stored per context (`contextvars`); `execute_code` denied by default in demo policy