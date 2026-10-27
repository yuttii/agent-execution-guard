from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

from .models import Mode, PolicyViolation, StepEvent, Trajectory
from .output import OutputInspector
from .plan import PlanAnalyzer
from .policy import ToolPolicyInspector

logger = logging.getLogger('agent_execution_guard')


def _collect_args(sig: inspect.Signature, a: tuple, kw: dict) -> dict[str, Any]:
    bound = sig.bind(*a, **kw)
    bound.apply_defaults()
    out: dict[str, Any] = {}
    for pname, val in bound.arguments.items():
        if sig.parameters[pname].kind is inspect.Parameter.VAR_KEYWORD:
            out.update(val)
        else:
            out[pname] = val
    return out


class ExecutionGuard:
    def __init__(
        self,
        inspector: ToolPolicyInspector,
        analyzer: PlanAnalyzer | None = None,
        mode: Mode = Mode.BLOCK,
        tools: dict[str, Callable] | None = None,
        *,
        sink: Callable[[dict[str, Any]], None] | None = None,
        output_inspector: OutputInspector | None = None,
    ):
        self.inspector = inspector
        self.analyzer = analyzer or PlanAnalyzer()
        self.mode = mode
        self.tools = tools or {}
        self._traj_var: ContextVar[Trajectory | None] = ContextVar('traj', default=None)
        self.sink = sink
        self.output_inspector = output_inspector

    def _emit(self, ev: StepEvent, **extra: Any) -> None:
        traj = self.traj
        if self.sink is None or traj is None:
            return
        record = {
            'run_id': traj.run_id,
            'run': traj.name,
            'malicious': traj.is_malicious_task,
            **ev.to_dict(),
            **extra,
        }
        try:
            self.sink(record)
        except Exception:
            logger.exception('event sink failed')

    def _finish(self, ev: StepEvent) -> None:
        self._report(ev)
        self._emit(ev)

    @property
    def traj(self) -> Trajectory | None:
        return self._traj_var.get()

    def start(self, name: str, is_malicious_task: bool = False) -> Trajectory:
        t = Trajectory(name=name, is_malicious_task=is_malicious_task)
        self._traj_var.set(t)
        return t

    def _add(self, **kw) -> StepEvent:
        assert self.traj is not None, 'call start() first'
        ev = StepEvent(idx=len(self.traj.events), **kw)
        self.traj.events.append(ev)
        return ev

    def _report(self, ev: StepEvent) -> None:
        if not ev.violations:
            return
        msg = f'step {ev.idx} {ev.tool or ev.kind}: {"; ".join(ev.violations)}'
        if ev.blocked:
            logger.warning('BLOCKED %s', msg)
        elif self.mode is Mode.WARN:
            logger.warning('%s', msg)
        else:
            logger.info('%s', msg)

    # hooks
    def before_plan(self, text: str) -> StepEvent:
        ev = self._add(kind='plan', content=text)
        ev.violations = self.analyzer.check(text)
        self._finish(ev)
        return ev

    def before_tool_call(self, tool: str, args: dict[str, Any]) -> StepEvent:
        ev = self._add(kind='tool_call', tool=tool, args=args)
        ev.violations = self.inspector.check(tool, args)
        if ev.violations and self.mode is Mode.BLOCK:
            ev.blocked = True
        self._finish(ev)
        return ev

    def after_tool_call(self, tool: str, result: Any) -> Any:
        insp = self.output_inspector
        if insp is None:
            return result
        text = result if isinstance(result, str) else repr(result)
        findings = insp.check(text)
        ev = self._add(kind='tool_result', tool=tool)
        ev.violations = findings
        shown = text
        if findings and self.mode is Mode.BLOCK:
            ev.blocked = True
            if insp.has_injection(text) or not isinstance(result, str):
                result = f'[TOOL OUTPUT WITHHELD by Agent-Execution-Guard: {"; ".join(findings)}]'
            else:
                result = insp.redact(text)
            shown = str(result)
        ev.content = insp.redact(shown)[:500] if findings else ''
        self._finish(ev)
        return result

    def call_tool(self, tool: str, **args) -> Any:
        ev = self.before_tool_call(tool, args)
        if ev.blocked:
            raise PolicyViolation(ev.violations)
        return self.after_tool_call(tool, self.tools[tool](**args))

    def after_final(self, text: str, unsafe: bool) -> StepEvent:
        traj = self.traj
        assert traj is not None, 'call start() first'
        traj.final_unsafe = unsafe
        ev = self._add(kind='final', content=text)
        self._emit(ev, final_unsafe=unsafe)
        return ev

    def guarded(self, name: str | Callable | None = None, *, on_block: str = 'message'):
        def make(fn: Callable, tool_name: str) -> Callable:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*a, **kw):
                ev = self.before_tool_call(tool_name, _collect_args(sig, a, kw))
                if ev.blocked:
                    if on_block == 'raise':
                        raise PolicyViolation(ev.violations)
                    return f'[BLOCKED by Agent-Execution-Guard: {"; ".join(ev.violations)}]'
                return self.after_tool_call(tool_name, fn(*a, **kw))

            return wrapper

        if callable(name) and not isinstance(name, str):
            return make(name, name.__name__)

        def deco(fn: Callable) -> Callable:
            return make(fn, name or fn.__name__)

        return deco
