import pytest
from pydantic import ValidationError

from gate import CONFIG_PATH, Finding, GateConfig, decide, load_config


def finding(severity):
    return Finding(severity=severity, category="security", file="a.py", line=1,
                   title="t", explanation="e", fix="f")


def config(**overrides):
    return GateConfig(**{"model": "m", **overrides})


def test_no_findings_passes():
    assert decide([], config()) == []


def test_fail_on_severity_fails():
    reasons = decide([finding("HIGH")], config())
    assert reasons == ["1 HIGH finding(s) (fail_on)"]


def test_low_findings_pass():
    assert decide([finding("LOW"), finding("INFO")], config()) == []


def test_max_count_under_limit_passes():
    assert decide([finding("MEDIUM")] * 2, config(max_count={"MEDIUM": 2})) == []


def test_max_count_over_limit_fails():
    reasons = decide([finding("MEDIUM")] * 3, config(max_count={"MEDIUM": 2}))
    assert reasons == ["3 MEDIUM finding(s), max is 2 (max_count)"]


def test_custom_fail_on():
    assert decide([finding("CRITICAL")], config(fail_on=["MEDIUM"])) == []


def test_unknown_severity_rejected():
    with pytest.raises(ValidationError):
        config(fail_on=["SCARY"])


def test_repo_config_is_valid():
    assert load_config(CONFIG_PATH).model
