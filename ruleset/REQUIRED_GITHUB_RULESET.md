# Required rules for main

Configure a branch protection rule or ruleset for `main` with:

- Require a pull request before merging.
- Require status check: `publication-authority`.
- Require branches to be up to date before merging, if available.
- Block force pushes.
- Block branch deletion.
- Do not allow direct pushes to `main`.
- Do not add ChatGPT, Codex, bots, or apps to a bypass list.
- For this single-owner repository, do not require an approving review unless a second human reviewer is added.

The bootstrap commits made before this rule exists are the only bootstrap exception.
