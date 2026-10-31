# GEN38 ENGSEQ Stage 3 — code-only prequalification, not an active Profile

This staging directory does **not** change `authority/CURRENT.json`, the private Library `CURRENT` state, any Source, Generator, Driver, Claim, producer workflow or book output.

Frozen GEN38 Authority SHA-256: `e972e0293128c7d223079603ceaf62db9d0fe96afcc2844fa947af6dc2a562ab`.

Files:
- `engseq_stage3_trust.py`: SHA-pinned **read-only** Ed25519 receipt verifier; accepts qualifying reviewer only from an independently pinned, revocation-fresh registry. **No trusted reviewer keys are currently provided.** Missing crypto dependency fails closed.
- `trust_policy.json`: candidate evidence policy for exact-scope A/B review; C/D remain held.
- `trust_anchors.json`: intentionally **unprovisioned empty** reviewer registry; cannot authorize a real review.
- `engseq_stage3_roles.py`: frozen-R17R9 role-evidence gate.
- `role_evidence.json`: proven 56 structural blocks and 363 multiword spans, with all unverified role admissions explicitly held. Caption exhaustive evidence unavailable.
- `staged_profile.json`: snapshot of frozen pins, draft code hashes, runtime pin mismatch, and inactive status. **Not a protected Authority-installed profile.**

Tested changed scope: `python -B -m unittest discover -s tests -p 'test_stage3_prequalification.py' -v`. Synthetic test signature keys are generated only in memory and are never trusted as official reviewer keys or stored.

**Next gated work:** independent owner-approved trust anchors and qualified signer identities; explicit protected pin and PPGES loader; a successful two-store GEN39 handoff; honest rendered-caption/role attestations. The stage cannot be labelled a final qualification PASS while these are missing. No blanket second-human receipt requirement is assumed for all A/B.
