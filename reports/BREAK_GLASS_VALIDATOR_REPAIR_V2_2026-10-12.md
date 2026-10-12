# Break-glass validator repair v2 — 2026-10-12

Status: **PREPARED / DO NOT MERGE UNTIL REQUIRED-CHECK RULE IS TEMPORARILY SUSPENDED**

## Confirmed failure

The trusted base validator reaches the successful manual authorization run, but artifact download fails with HTTP 401 because the GitHub bearer token is forwarded to the cross-domain signed artifact-storage redirect.

## Repair scope

- Changes only `scripts/ci_validate_pr.py` plus this audit record and the request record.
- Does not change `authority/CURRENT.json`, its SHA sidecar, any PASS/FAIL ledger, any project state, Renderer status, book content, Library state, or current action.
- Authenticates the initial GitHub API request.
- Captures the artifact 30x redirect.
- Requires a valid HTTPS redirect.
- Downloads the signed storage URL without the GitHub Authorization header.

## Controlled break-glass procedure

1. Temporarily remove only the **required status check** rule from both active main rulesets.
2. Keep pull-request requirement, deletion protection, non-fast-forward/force-push protection, and zero bypass actors active.
3. Merge this PR through the pull-request path.
4. Immediately restore required status check `publication-authority` on both rulesets.
5. Run a fresh negative stale-state PR and confirm it cannot merge.
6. Create a fresh governance-binding PR from the repaired protected `main`; do not reuse the stale pre-repair binding branch.

No renderer, book, IMS, DOCX, PDF, or publication execution is authorized by this repair.
