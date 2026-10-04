# ai-quality-gate

An AI-powered CI/CD quality gate: no code reaches the `qa` branch unless it passes an automated security and quality audit.

## How it works (today)

1. Open a PR into `qa`.
2. GitHub Actions runs `gate.py`, which sends the PR diff to Claude for a security (OWASP Top 10) and quality review.
3. Claude returns structured JSON findings (severity, file, line, issue, fix).
4. The rules in `gate-config.yml` decide PASS or FAIL. If the gate itself errors, it also fails (fail closed).
5. Branch protection blocks the merge unless every check passes.

## Checks

| Check | Tool | Finds | How |
|---|---|---|---|
| `gate` | Claude | logic flaws, OWASP issues, quality bugs | AI review of the diff |
| `bandit` | bandit | insecure Python patterns (eval, shell=True, weak hashes…) | fixed rules (SAST) |
| `pip-audit` | pip-audit | dependencies with known CVEs | vulnerability databases (PyPI/OSV) |
| `gitleaks` | gitleaks | committed keys, tokens, passwords | regex + entropy, every PR commit |
| `tests` | pytest | broken gate logic | unit tests |

The deterministic tools are consistent and free; Claude catches what rules can't.

The gate script and its rules always come from the base branch, so a PR can't loosen its own review.

## Setup

- Repo secret `ANTHROPIC_API_KEY` (Settings → Secrets and variables → Actions). Set a spend limit on the key.

## Rules (`gate-config.yml`)

| Key | Meaning | Default |
|---|---|---|
| `model` | Claude model | (required) |
| `effort` | `low` … `max`; higher = more thorough, more tokens | `medium` |
| `fail_on` | severities that fail the gate | `[CRITICAL, HIGH]` |
| `max_count` | fail if a severity appears more than N times, e.g. `MEDIUM: 5` | none |
| `ignore_paths` | git glob patterns not sent to Claude | none |
| `max_diff_chars` | larger diffs fail with an error | `150000` |

## Development

```
pip install -r requirements-dev.txt
pytest
```

## Branches

- `main`: stable code
- `qa`: protected; only PRs that pass the gate can merge

## Roadmap

| Phase | What |
|---|---|
| 1 | Pipeline skeleton + branch protection ✅ |
| 2 | Claude review script with structured JSON findings ✅ |
| 3 | Severity rules engine (YAML config) ✅ |
| 4 | Static tools: bandit, pip-audit, gitleaks ✅ (SonarCloud optional) |
| 5 | Reports + notifications (PR comment, Slack) |
| 6 | Hardening: prompt injection, big diffs, flaky results |
| 7 | Package as a reusable workflow + full docs |
