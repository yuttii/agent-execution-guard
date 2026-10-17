from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Trajectory

MAX_FIELD_CHARS = 2000


def _shorten(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f'...[+{len(value) - limit} chars]'
    if isinstance(value, dict):
        return {k: _shorten(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_shorten(v, limit) for v in value]
    return value


class JsonlSink:
    def __init__(self, path: str | Path, max_field_chars: int = MAX_FIELD_CHARS):
        self.path = Path(path)
        self.max_field_chars = max_field_chars
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents = True, exist_ok = True)

    def __call__(self, record: dict[str, Any]) -> None:
        line = json.dumps(_shorten(record, self.max_field_chars), ensure_ascii = False, default = repr)
        with self._lock, self.path.open('a', encoding = 'utf-8') as f:
            f.write(line + '\n')


def export_trajectories(trajs: Iterable[Trajectory], path: str | Path) -> int:
    p = Path(path)
    p.parent.mkdir(parents = True, exist_ok = True)
    n = 0
    with p.open('w', encoding='utf-8') as f:
        for t in trajs:
            f.write(json.dumps(t.to_dict(), ensure_ascii = False, default = repr) + '\n')
            n += 1
    return n


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding = 'utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]