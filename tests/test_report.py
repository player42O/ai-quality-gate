import json

from gate import Finding, Review, render_report, write_reports


def review_with(*findings):
    return Review(summary="One issue found.", findings=list(findings))


def finding(severity="HIGH", title="SQL injection"):
    return Finding(severity=severity, category="security", file="app.py", line=7,
                   title=title, explanation="user input in query", fix="use parameters")


def test_fail_report_lists_reasons_and_findings():
    report = render_report("FAIL", review_with(finding()), ["1 HIGH finding(s) (fail_on)"])
    assert "❌ AI Quality Gate: FAIL" in report
    assert "- 1 HIGH finding(s) (fail_on)" in report
    assert "| HIGH | security | `app.py:7` | SQL injection |" in report


def test_pass_report_without_findings():
    report = render_report("PASS", review_with(), [])
    assert "✅ AI Quality Gate: PASS" in report
    assert "No findings." in report


def test_error_report_says_blocked():
    report = render_report("ERROR", None, ["diff too large"])
    assert "fail closed" in report
    assert "- diff too large" in report


def test_pipes_in_model_text_dont_break_the_table():
    report = render_report("FAIL", review_with(finding(title="a | b")), ["x"])
    assert "a \\| b" in report


def test_write_reports_creates_md_and_json(tmp_path):
    write_reports("FAIL", review_with(finding()), ["reason"], tmp_path)
    data = json.loads((tmp_path / "gate-report.json").read_text(encoding="utf-8"))
    assert data["status"] == "FAIL"
    assert data["review"]["findings"][0]["line"] == 7
    assert (tmp_path / "gate-report.md").exists()
