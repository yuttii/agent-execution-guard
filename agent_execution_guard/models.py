from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


class Mode(str, Enum):
    BLOCK = 'block'
    WARN = 'warn'
    LOG_ONLY = 'log_only'


class PolicyViolation(Exception):
    def __init__(self, reasons: list[str]):
        super().__init__('; '.join(reasons))
        self.reasons = reasons


@dataclass
class StepEvent:
    idx: int
    kind: str
    content: str = ''
    tool: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    violations: list[str] = field(default_factory=list)
    blocked: bool = False
    ts: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            'idx': self.idx,
            'kind': self.kind,
            'content': self.content,
            'tool': self.tool,
            'args': self.args,
            'violations': self.violations,
            'blocked': self.blocked,
            'ts': self.ts,
        }


@dataclass
class Trajectory:
    name: str
    events: list[StepEvent] = field(default_factory=list)
    final_unsafe: bool = False
    is_malicious_task: bool = False
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def plan_events(self):
        return [e for e in self.events if e.kind == 'plan']

    @property
    def has_step_violation(self) -> bool:
        return any(e.violations for e in self.events if e.kind in ('plan', 'tool_call'))

    @property
    def has_executed_violation(self) -> bool:
        return any(e.violations and not e.blocked for e in self.events if e.kind == 'tool_call')

    @property
    def has_output_violation(self) -> bool:
        return any(e.violations for e in self.events if e.kind == 'tool_result')

    @property
    def has_block(self) -> bool:
        return any(e.blocked for e in self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            'run_id': self.run_id,
            'name': self.name,
            'is_malicious_task': self.is_malicious_task,
            'final_unsafe': self.final_unsafe,
            'events': [e.to_dict() for e in self.events],
        }
