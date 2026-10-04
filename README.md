# ai-quality-gate

An AI-powered CI/CD quality gate: no code reaches the `qa` branch unless it passes an automated security and quality audit.

## How it works (today)

1. Open a PR into `qa`.
2. GitHub Actions runs `gate.py` against the PR diff.
3. The gate prints PASS or FAIL. Branch protection blocks the merge on FAIL.

Right now the gate is a placeholder that fails on a marker string (see `gate.py`). The Claude audit replaces it in Phase 2.

## Branches

- `main`: stable code
- `qa`: protected; only PRs that pass the gate can merge

## Roadmap

| Phase | What |
|---|---|
| 1 | Pipeline skeleton + branch protection ✅ |
| 2 | Claude review script with structured JSON findings |
| 3 | Severity rules engine (YAML config) |
| 4 | Static tools: bandit, gitleaks, SonarCloud |
| 5 | Reports + notifications (PR comment, Slack) |
| 6 | Hardening: prompt injection, big diffs, flaky results |
| 7 | Package as a reusable workflow + full docs |
