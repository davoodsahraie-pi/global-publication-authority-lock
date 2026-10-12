# Break-glass validator repair — 2026-10-12

Status: **PREPARED / REQUIRES TEMPORARY REQUIRED-CHECK SUSPENSION**

## Why this repair exists

The protected `publication-authority` validator correctly required manual workflow authorization for the authorized governance upgrade, but its artifact downloader followed GitHub's cross-domain artifact redirect while retaining the GitHub `Authorization` header. The signed Azure/S3 artifact URL rejected that forwarded header with HTTP 401.

This creates a governance deadlock: every mutating governance PR requires the authorization artifact, while the trusted validator cannot read that artifact until this one downloader bug is fixed.

## Scope of repair

- Changes only `scripts/ci_validate_pr.py`.
- Keeps GitHub authentication on the first API request.
- Captures the 302 redirect explicitly.
- Downloads the pre-signed artifact URL **without** forwarding the GitHub Authorization header.
- Does not change `authority/CURRENT.json`, ledgers, current action, renderer status, project status, book content, or Library state.
- Uses manual authorization workflow run `38282330106` for action `BIND_EXTERNAL_AUTHORITY_AND_REFRESH_BOOTSTRAP`.

## Break-glass procedure

Because the currently protected validator cannot validate its own repair, the required `publication-authority` status-check rule must be temporarily removed from both active main rulesets while all other protections remain enabled. Merge this PR through the still-required pull-request path, then immediately restore the required status check on both rulesets before any state transition PR is merged.

No direct push, force push, branch deletion, renderer execution, or book execution is authorized by this repair.
