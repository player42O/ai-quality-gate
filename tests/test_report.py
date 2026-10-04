import json

from gate import Finding, Review, render_report, write_reports


def review_with(*findings):
    return Review(summary="One issue found.", findings=list(findings))


def finding(severity="HIGH", title="SQL injection", file="app.py"):
    return Finding(severity=severity, category="security", file=file, line=7,
                   title=title, explanation="user input in query", fix="use parameters")


def test_fail_report_lists_reasons_and_findings():
    report = render_report("FAIL", review_with(finding()), ["1 HIGH finding(s) (fail_on)"])
    assert "❌ AI Quality Gate: FAIL" in report
    assert "- 1 HIGH finding\\(s\\) \\(fail\\_on\\)" in report  # escaped; GitHub shows it plainly
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


def test_error_reasons_are_escaped_too():
    report = render_report("ERROR", None, ["review failed: <img src=x> @admin"])
    assert "<img" not in report
    assert "@admin" not in report


def test_file_paths_keep_underscores():
    report = render_report("FAIL", review_with(finding(file="tests/test_rules.py")), ["x"])
    assert "`tests/test_rules.py:7`" in report


def test_model_text_cannot_inject_links_html_or_mentions():
    evil = "![x](https://evil.example/t.png) <img src=x> @admin"
    report = render_report("FAIL", review_with(finding(title=evil)), ["x"])
    assert "![x](" not in report
    assert "<img" not in report
    assert "@admin" not in report


def test_write_reports_creates_md_and_json(tmp_path):
    write_reports("FAIL", review_with(finding()), ["reason"], tmp_path)
    data = json.loads((tmp_path / "gate-report.json").read_text(encoding="utf-8"))
    assert data["status"] == "FAIL"
    assert data["review"]["findings"][0]["line"] == 7
    assert (tmp_path / "gate-report.md").exists()
