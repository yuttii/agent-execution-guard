import json
import threading

from agent_execution_guard import ExecutionGuard, Mode, PlanAnalyzer, ToolPolicyInspector
from agent_execution_guard.demo import DEMO_POLICY, run_scenarios
from agent_execution_guard.sinks import JsonlSink, export_trajectories, load_jsonl


def _guard(tmp_path, sink=None):
    path = tmp_path / 'logs' / 'run.jsonl'
    g = ExecutionGuard(
        ToolPolicyInspector(DEMO_POLICY), PlanAnalyzer(), Mode.BLOCK, sink=sink or JsonlSink(path)
    )
    g.start('t', is_malicious_task=True)
    return g, path


def test_events_written_in_order(tmp_path):
    g, path = _guard(tmp_path)
    g.before_plan('I will compute the total')
    g.before_tool_call('run_sql', {'query': 'DROP TABLE t'})
    g.after_final('done', unsafe=False)
    rows = load_jsonl(path)
    assert [r['kind'] for r in rows] == ['plan', 'tool_call', 'final']
    assert rows[1]['blocked'] is True and rows[1]['violations']
    assert rows[2]['final_unsafe'] is False
    assert all(r['run_id'] == g.traj.run_id and r['ts'] for r in rows)


def test_non_serializable_args_do_not_crash(tmp_path):
    g, path = _guard(tmp_path)
    g.before_tool_call('run_sql', {'query': 'SELECT 1', 'obj': object()})
    assert len(load_jsonl(path)) == 1


def test_long_values_are_truncated(tmp_path):
    g, path = _guard(tmp_path)
    g.before_plan('x' * 10_000)
    assert len(load_jsonl(path)[0]['content']) < 2100


def test_broken_sink_does_not_break_guard(tmp_path):
    def bad_sink(record):
        raise OSError('disk full')

    g, _ = _guard(tmp_path, sink=bad_sink)
    ev = g.before_plan('hello')
    assert ev.kind == 'plan'


def test_threads_write_valid_lines(tmp_path):
    sink = JsonlSink(tmp_path / 'm.jsonl')

    def work(n):
        g = ExecutionGuard(ToolPolicyInspector(DEMO_POLICY), sink=sink)
        g.start(f't{n}')
        for _ in range(20):
            g.before_plan('ok')

    ts = [threading.Thread(target=work, args=(i,)) for i in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(load_jsonl(tmp_path / 'm.jsonl')) == 100


def test_export_trajectories_roundtrip(tmp_path):
    trajs = run_scenarios(Mode.BLOCK)
    n = export_trajectories(trajs, tmp_path / 'out' / 'traj.jsonl')
    rows = load_jsonl(tmp_path / 'out' / 'traj.jsonl')
    assert n == len(trajs) == len(rows)
    assert rows[0]['events'] and rows[0]['run_id']
    json.dumps(rows)
