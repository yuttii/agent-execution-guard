from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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


@dataclass
class Trajectory:
    name: str
    events: list[StepEvent] = field(default_factory=list)
    final_unsafe: bool = False
    is_malicious_task: bool = False

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
    def has_block(self) -> bool:
        return any(e.blocked for e in self.events)
