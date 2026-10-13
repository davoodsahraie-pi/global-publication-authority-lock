# Mixed Direction v3 — Protected Governance Transition

Date: 2026-10-13

Status: **STATE-TRANSITION PROPOSAL ONLY; NOT FIXTURE REGISTRATION**

## Manual authority

- Workflow run: https://github.com/davoodsahraie-pi/global-publication-authority-lock/actions/runs/38372864672
- Action kind: `GOVERNANCE_UPGRADE`
- Exact action ID: `REGISTER_MIXED_DIRECTION_V3_ADDITIVE_FIXTURE`
- Project: `GLOBAL`
- Authorized operations: `["GOVERNANCE_UPGRADE","SET_NEXT_ACTION","AUTHORITY_UPDATE","STATE_TRANSITION"]`
- Authorization pinned to old public `5e799acb8f9919e38f6ea901d3cc1e73e3db86ae53d988247538318b43cd0295` and old private `baacdcfe5f9b76519e2b18762816e570dfdd3ee78794e707a943f36eb1469083`.

## Proposed state

- Next public lock SHA-256: `338cdcb09c91df098d1508670642330cbd108612c63d3141c452a4d13bca16bf`
- Next private State SHA-256: `ea2ea80acb8c54c40e1398ff49cea067297fb3ebd9343f5997ce09edd4f3c6db`
- Candidate private Library path: `/GLOBAL-PUBLICATION/Publication Master Control/GLOBAL_PUBLICATION_EXECUTION_STATE_v1.3_2026-10-13.json`
- User-approved exact v3 fixture SHA-256: `e0b0069933994cc82fbc50d8a3c1254e48d142ad01069757f45771047e586954`.

## Preserved immutable scope

All existing PASS and METHOD FAIL ledger hashes, frozen projects and blocked projects are unchanged. N2 and the thirteen Word-native primitives remain immutable. Renderer remains `QUALIFICATION_PENDING`; pending Word Mobile and Word-exported PDF are not promoted.

Mixed v3 is an additive four-case semantic fixture. The three LTR-label/RTL-payload technical blocks use physical left, while ordinary headings (including Test 4) remain RTL physical right. Do not generalize the technical left exception to all text.

## Next mandatory barrier

After successful protected merge and exact Library Current state alignment, run a **NEW** manual `EXECUTE` workflow bound to the new public/private SHA. This GOVERNANCE_UPGRADE run may NOT register, promote or upload the actual fixture officially. No Renderer/IMS/book build occurs in this transition.
