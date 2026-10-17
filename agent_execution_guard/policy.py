from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .schema import Policy


class ToolPolicyInspector:
    def __init__(self, policy: Policy | dict[str, Any]):
        self.policy = policy if isinstance(policy, Policy) else Policy.model_validate(policy)
        self.default = self.policy.default
        self.tools = self.policy.tools
        if any(r.sql_ops for r in self.tools.values()) and importlib.util.find_spec('sqlglot') is None:
            raise RuntimeError(
                'sql_ops rules need sqlglot: pip install "agent-execution-guard[sql]"'
            )

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            return list(value)
        origin = getattr(value, '__origin__', None)
        args = getattr(value, '__args__', ())
        if origin in (list, tuple, set):
            items: list[Any] = []
            for arg in args:
                if isinstance(arg, (list, tuple, set)):
                    items.extend(ToolPolicyInspector._as_list(arg))
                else:
                    items.append(arg)
            return items
        return [value]

    @staticmethod
    def _host(value: str) -> str:
        try:
            if '@' in value and '://' not in value:  # email
                return value.rsplit('@', 1)[1].lower().rstrip('.')
            return (urlparse(value).hostname or '').lower().rstrip('.')
        except ValueError:
            return ''

    @staticmethod
    def _url_problems(value: str, schemes: list[str]) -> list[str]:
        try:
            u = urlparse(value)
        except ValueError:
            return ['URL cannot be parsed']
        host = (u.hostname or '').lower().rstrip('.')
        probs: list[str] = []
        if u.scheme not in schemes:
            probs.append(f'scheme "{u.scheme}" not allowed')
        if host in {'localhost', '127.0.0.1', '::1'}:
            probs.append('localhost not allowed')
        if host:
            try:
                ipaddress.ip_address(host)
                probs.append('IP address host not allowed')
            except ValueError:
                pass
        return probs

    @staticmethod
    def _path_allowed(value: str, roots: list[str]) -> bool:
        if not value.strip() or '\x00' in value:
            return False
        try:
            p = Path(value).resolve()
            resolved_roots = [Path(r).resolve() for r in roots]
        except (OSError, RuntimeError, ValueError):
            return False
        return any(p == r or r in p.parents for r in resolved_roots)

    def _sql_violations(self, tool: str, arg: str, query: str, ops: list[str]) -> list[str]:
        import sqlglot
        from sqlglot import exp

        if not query.strip():
            return []
        allowed = {o.upper() for o in ops}
        try:
            stmts = [s for s in sqlglot.parse(query) if s is not None]
        except Exception:  # noqa: BLE001  (any parser failure must block the query: fail closed)
            return [f'{tool}.{arg} SQL cannot be parsed']

        query_types = (exp.Select, exp.Union, exp.Except, exp.Intersect)
        write_types = (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create)
        out: list[str] = []
        for s in stmts:
            op = 'SELECT' if isinstance(s, query_types) else type(s).__name__.upper()
            if op not in allowed:
                out.append(f'{tool}.{arg} SQL op "{op}" not allowed')
            for node in s.find_all(*write_types):
                nop = type(node).__name__.upper()
                if node is not s and nop not in allowed:
                    out.append(f'{tool}.{arg} nested SQL op "{nop}" not allowed')
        return out

    def check(self, tool: str, args: dict[str, Any]) -> list[str]:
        rule = self.tools.get(tool)
        if rule is None:
            return [f'tool "{tool}" not in allowlist'] if self.default == 'deny' else []

        out: list[str] = []
        for arg, pattern in rule.deny_regex.items():
            if re.search(pattern, str(args.get(arg, '')), re.IGNORECASE):
                out.append(f'{tool}.{arg} matches denied pattern /{pattern}/')

        for arg, domains in rule.allow_domains.items():
            value = str(args.get(arg, ''))
            host = self._host(value)
            allowed_domains = self._as_list(domains)
            if not any(host == d or host.endswith('.' + d) for d in allowed_domains):
                out.append(f'{tool}.{arg} host "{host}" not in allowed domains')
            if '://' in value:
                for prob in self._url_problems(value, rule.get('allow_schemes', ['https'])):
                    out.append(f'{tool}.{arg} {prob}')

        for arg, roots in rule.allow_paths.items():
            allowed_roots = self._as_list(roots)
            if not self._path_allowed(str(args.get(arg, '')), allowed_roots):
                out.append(f'{tool}.{arg} path not in allowed roots')

        for arg, ops in rule.sql_ops.items():
            out.extend(self._sql_violations(tool, arg, str(args.get(arg, '')), ops))
        return out
