# ai-quality-gate

An AI-powered CI/CD quality gate: no code reaches the `qa` branch unless it passes an automated security and quality audit.

## How it works (today)

1. Open a PR into `qa`.
2. GitHub Actions runs `gate.py`, which sends the PR diff to Claude for a security (OWASP Top 10) and quality review.
3. Claude returns structured JSON findings (severity, file, line, issue, fix).
4. Any CRITICAL or HIGH finding means FAIL. If the gate itself errors, it also fails (fail closed).
5. Branch protection blocks the merge unless the gate passes.

## Setup

- Repo secret `ANTHROPIC_API_KEY` (Settings → Secrets and variables → Actions). Set a spend limit on the key.
- Optional env vars: `GATE_MODEL` (default `claude-opus-5-5`), `GATE_EFFORT` (default `medium`).

## Branches

- `main`: stable code
- `qa`: protected; only PRs that pass the gate can merge

## Roadmap

| Phase | What |
|---|---|
| 1 | Pipeline skeleton + branch protection ✅ |
| 2 | Claude review script with structured JSON findings ✅ |
| 3 | Severity rules engine (YAML config) |
| 4 | Static tools: bandit, gitleaks, SonarCloud |
| 5 | Reports + notifications (PR comment, Slack) |
| 6 | Hardening: prompt injection, big diffs, flaky results |
| 7 | Package as a reusable workflow + full docs |
