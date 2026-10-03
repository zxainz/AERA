# Contributing to AERA

## Ground rules

AERA is dual-use-adjacent tooling: it generates proof-of-concept code for
vulnerabilities. Every contribution must keep the ethical safeguards intact:

- **Never weaken the authorization gate.** No bypasses, no default secrets,
  no "dev mode" that skips validation.
- **Never weaken sandbox isolation.** `network_mode="none"` and container
  cleanup are non-negotiable.
- **Never remove or truncate audit logging.**
- PoC output stays validation-grade: commented, minimal, localhost-only,
  no persistence, no obfuscation, no anti-analysis.

Pull requests that erode any of the above will be rejected.

## Workflow

1. Fork, branch, and keep changes focused.
2. Add or update tests in `tests/`. New modules need coverage of both the
   happy path and the fail-closed path.
3. Run the full suite: `pytest tests/ -q`, plus `bandit -r aera/ -ll`.
4. Update docs (`docs/`, `README.md`) when behavior changes.
5. Open the PR with a clear description of what changed and why.

## Code style

- Python 3.11+, type hints on public functions.
- Keep modules small and single-purpose; the pipeline in `core.py` is the
  only orchestrator.
- Fail closed on security boundaries, fail open only on advisory enrichment
  (document it when you do).
