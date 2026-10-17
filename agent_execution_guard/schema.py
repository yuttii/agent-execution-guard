from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _listify(value: Any) -> Any:
    return [value] if isinstance(value, str) else value


class ToolRule(BaseModel):
    model_config = ConfigDict(extra = 'forbid')

    deny_regex: dict[str, str] = Field(default_factory = dict)
    allow_domains: dict[str, list[str]] = Field(default_factory = dict)
    allow_paths: dict[str, list[str]] = Field(default_factory = dict)
    sql_ops: dict[str, list[str]] = Field(default_factory = dict)
    allow_schemes: list[str] = Field(default_factory = lambda: ['https'])

    @field_validator('allow_domains', 'allow_paths', 'sql_ops', mode = 'before')
    @classmethod
    def _wrap_scalars(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {k: _listify(x) for k, x in v.items()}
        return v

    @field_validator('allow_schemes', mode = 'before')
    @classmethod
    def _wrap_scheme(cls, v: Any) -> Any:
        return _listify(v)

    @field_validator('deny_regex')
    @classmethod
    def _regex_compiles(cls, v: dict[str, str]) -> dict[str, str]:
        for arg, pattern in v.items():
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f'{arg}: invalid regex {pattern!r}: {e}') from e
        return v

    @field_validator('allow_domains')
    @classmethod
    def _normalize_domains(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        return {k: [d.strip().lower().rstrip('.') for d in ds] for k, ds in v.items()}

    @field_validator('sql_ops')
    @classmethod
    def _upper_ops(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        return {k: [o.strip().upper() for o in ops] for k, ops in v.items()}

    @field_validator('allow_schemes')
    @classmethod
    def _lower_schemes(cls, v: list[str]) -> list[str]:
        return [s.strip().lower() for s in v]


class Policy(BaseModel):
    model_config = ConfigDict(extra = 'forbid')

    default: Literal['deny', 'allow'] = 'deny'
    tools: dict[str, ToolRule] = Field(default_factory = dict)


def load_policy(path: str | Path) -> Policy:
    try:
        import yaml
    except ImportError as e:
        raise RuntimeError(
            'YAML policies need PyYAML: pip install "agent-execution-guard[yaml]"'
        ) from e
    data = yaml.safe_load(Path(path).read_text(encoding = 'utf-8'))
    return Policy.model_validate(data or {})