# Bootstrap Status — 2026-10-12

Repository: `davoodsahraie-pi/global-publication-authority-lock`

Status: **PUBLIC LOCK BOOTSTRAPPED / CI VALIDATED / BRANCH PROTECTION NOT YET ACTIVE**

## Current authority anchors

- Public lock SHA-256: `f75c4fa324843b7b55e9c1557d32af884a34ca15967bce97d54687285a86a25b`
- Private execution-state SHA-256 anchor: `eb52f80fc04df349996a4df81720391a98e57d380d5643c9f8d71ae670feddc0`

## CI evidence

- Positive read-only smoke test: PR #1 / workflow `publication-authority` = **SUCCESS**
- Negative stale-state test: PR #2 / workflow `publication-authority` = **FAILURE as expected**
- This proves the gate both allows the exact current read-only action and denies a stale lock request.

## Installed enforcement components

- `authority/CURRENT.json`
- `authority/CURRENT.sha256`
- `gate/publication_gate.py`
- `gate/transition_guard.py`
- `scripts/selftest.py`
- `scripts/ci_validate_pr.py`
- `.github/workflows/publication-authority.yml`
- `.github/workflows/authorize-next-action.yml`
- `.github/CODEOWNERS`
- `policy/OFFICIALITY.md`
- `ruleset/REQUIRED_GITHUB_RULESET.md`

## Exact next action

Enable a GitHub ruleset / branch-protection policy for `main` requiring:

1. pull request before merge,
2. required status check `publication-authority`,
3. no force pushes,
4. no branch deletion,
5. no direct pushes to `main`,
6. no bot/ChatGPT/Codex bypass actor.

Until that rule is active:

`EXTERNAL ENFORCEMENT = VALIDATED BUT NOT HARD-LOCKED`

After the rule is active, verify with one real blocked direct-write/merge scenario and record activation.
