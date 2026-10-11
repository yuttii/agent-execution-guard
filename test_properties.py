import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis.provisional import domains

from guard import DEMO_POLICY, ToolPolicyInspector

pytest.importorskip('sqlglot')

FAST = settings(max_examples=200, deadline=None)

INSPECTOR = ToolPolicyInspector(DEMO_POLICY)
URL_INSPECTOR = ToolPolicyInspector(
    {'tools': {'http_post': {'allow_domains': {'url': ['example.com']}}}}
)

URLISH = st.text(alphabet='/:@[].%abcxyz01 ', max_size=40)


def _allowed_by_example(domain: str) -> bool:
    d = domain.lower().rstrip('.')
    return d == 'example.com' or d.endswith('.example.com')


# _host and URL checks

@FAST
@given(st.one_of(st.text(), URLISH))
def test_host_never_raises_and_is_normalized(value):
    h = ToolPolicyInspector._host(value)
    assert isinstance(h, str)
    assert h == h.lower()
    assert not h.endswith('.')


@FAST
@given(st.one_of(st.text(), URLISH))
def test_url_check_never_crashes(value):
    assert isinstance(URL_INSPECTOR.check('http_post', {'url': value}), list)


@FAST
@given(domains())
def test_foreign_domains_are_always_blocked(domain):
    assume(not _allowed_by_example(domain))
    assert URL_INSPECTOR.check('http_post', {'url': f'https://{domain}/x'})


@FAST
@given(domains())
def test_userinfo_trick_does_not_bypass(domain):
    assume(not _allowed_by_example(domain))
    assert URL_INSPECTOR.check('http_post', {'url': f'https://example.com@{domain}/'})


@FAST
@given(st.from_regex(r'[a-z][a-z0-9]{0,10}', fullmatch=True))
def test_subdomains_of_allowed_domain_pass(label):
    assert URL_INSPECTOR.check('http_post', {'url': f'https://{label}.example.com/x'}) == []


# SQL

WRITES = ['DROP TABLE t', 'DELETE FROM t', 'UPDATE t SET a = 1', 'INSERT INTO t VALUES (1)']
COMMENT = st.text(alphabet='abc XYZ123', max_size=20)


@FAST
@given(st.text())
def test_sql_check_never_crashes(query):
    assert isinstance(INSPECTOR.check('run_sql', {'query': query}), list)


@FAST
@given(st.integers(0, 10**6), st.integers(0, 10**6))
def test_plain_select_is_allowed(a, b):
    assert INSPECTOR.check('run_sql', {'query': f'SELECT {a} + {b} AS total'}) == []


@FAST
@given(st.sampled_from(WRITES), COMMENT)
def test_write_ops_blocked_wherever_they_hide(write, comment):
    queries = [
        f'/* {comment} */ {write}',
        f'SELECT 1; {write}',
        f'{write}; SELECT 1',
        f'-- {comment}\n{write}',
    ]
    for q in queries:
        assert INSPECTOR.check('run_sql', {'query': q}), q