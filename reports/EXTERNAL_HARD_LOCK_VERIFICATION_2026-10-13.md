# External Hard-Lock Verification — 2026-10-13

Status: **HARD LOCK VERIFIED**

This report records an end-to-end enforcement test against the live protected `main` branch.

## Authority identity

- Public lock SHA-256: `9ebf7952318991090fea04801e9636003f6cf15b36db0654c79ddee764740e52`
- Private execution-state SHA-256 anchor: `656bac3fc2c9bc370a3667427b338c3ab64b7c83f7f19829f15db442f3f7f656`
- Required status check: `publication-authority`
- Primary ruleset: `publication-authority-main-lock` / ID `24932377`
- Secondary hardening ruleset: `GLOBAL-PUBLICATION-MAIN-LOCK` / ID `24939466`
- Both rulesets: active, zero bypass actors, current user bypass = never.

## Positive path

PR #11 executed the current READ_ONLY EXACT_NEXT_ACTION and added the additive renderer gap map.

The `publication-authority` workflow completed successfully and GitHub permitted the protected merge.

Merged commit: `208a0b042215da2a03fa2ea9d2cff3d59172c17b`.

## Negative path

PR #12 was created fresh from the then-current `main` but deliberately supplied the previous public-lock SHA.

Expected result: DENY.

Observed result:

- `publication-authority` workflow run `38338087401`: **failure**.
- A direct API merge attempt was rejected by GitHub with HTTP 405 and the rule violation:
  `Required status check "publication-authority" is failing.`

Therefore a stale executor cannot make the stale request official even when it has repository write access.

## Conclusion

The enforcement path is now demonstrated at the repository boundary, not merely by prompt convention:

`STALE STATE -> GATE FAILURE -> REQUIRED CHECK FAILURE -> MERGE BLOCKED`

and:

`CURRENT VALID READ-ONLY ACTION -> GATE PASS -> PROTECTED MERGE ALLOWED`

No renderer, book, IMS, DOCX, or PDF execution was performed in this verification.
