from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_execution_guard import ToolPolicyInspector
from agent_execution_guard.schema import Policy, load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / 'policies' / 'example.yaml'


def test_typo_in_rule_key_is_rejected():
    with pytest.raises(ValidationError) as exc:
        Policy.model_validate({'tools': {'http_post': {'allow_domain': {'url': ['a.com']}}}})
    assert 'allow_domain' in str(exc.value)


def test_typo_in_top_level_key_is_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate({'defualt': 'allow'})


def test_invalid_default_is_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate({'default': 'maybe'})


def test_invalid_regex_is_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate({'tools': {'t': {'deny_regex': {'a': '('}}}})


def test_values_are_normalized():
    p = Policy.model_validate({'tools': {'t': {'allow_domains': {'url': 'Example.COM.'}}}})
    assert p.tools['t'].allow_domains['url'] == ['example.com']


def test_inspector_accepts_policy_object():
    insp = ToolPolicyInspector(Policy.model_validate({'tools': {'t': {}}}))
    assert insp.check('t', {}) == []


def test_sql_ops_without_sqlglot_fails_at_start(monkeypatch):
    monkeypatch.setattr('importlib.util.find_spec', lambda name: None)
    with pytest.raises(RuntimeError, match = 'sqlglot'):
        ToolPolicyInspector({'tools': {'run_sql': {'sql_ops': {'query': ['SELECT']}}}})


def test_example_yaml_is_valid_and_works():
    pytest.importorskip('yaml')
    insp = ToolPolicyInspector(load_policy(EXAMPLE))
    assert insp.check('run_sql', {'query': 'SELECT 1'}) == []
    assert insp.check('run_sql', {'query': 'DROP TABLE t'})


def test_load_policy_rejects_typo(tmp_path):
    pytest.importorskip('yaml')
    f = tmp_path / 'p.yaml'
    f.write_text('tools:\n  t:\n    allow_domain: {url: [a.com]}\n', encoding = 'utf-8')
    with pytest.raises(ValidationError):
        load_policy(f)


def test_load_policy_empty_file_denies_all(tmp_path):
    pytest.importorskip('yaml')
    f = tmp_path / 'p.yaml'
    f.write_text('', encoding = 'utf-8')
    assert ToolPolicyInspector(load_policy(f)).check('anything', {})