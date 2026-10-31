#!/usr/bin/env python3
"""GEN38 additive ENGSEQ Identity v2 code-only seam (not a deployment).

Original R09 identity checks are reused; no Canonical text, Queue, Generator or
Driver is rebuilt.  A GEN38 profile is *not* activated by installing this file.
No LAB result can authorize Claim, Driver, rendering or publication.
"""
from engseq_identity_registry_v2 import (
    preclaim_v2_from_frozen_crosswalk,
    IdentityHold,
)

V2_PROFILE_FIELDS = frozenset((
    "gen38_engseq_identity_v2",
    "gen37_engseq_identity_v2",
    "engseq_identity_v2",
))

def code_only_preclaim_guard(public_authority: dict) -> dict:
    """Protected Broker hook: deny any v2 profile pending a later activation."""
    if not isinstance(public_authority, dict):
        return {"status": "DENY_INVALID_AUTHORITY", "producer_authorized": False}
    if any(field in public_authority for field in V2_PROFILE_FIELDS):
        return {"status": "DENY_V2_NOT_ACTIVATED", "producer_authorized": False}
    return {"status": "UNSELECTED_CODE_ONLY", "producer_authorized": False}

def mandatory_preclaim_v2(**frozen_pinned_inputs) -> dict:
    """Explicit non-executable evaluation API for a future separately pinned Broker.

    Source, queue, archive and gzip pins must be independently authenticated.
    A trusted caller must bind the PPGES engine, verifier and profile.
    """
    result = preclaim_v2_from_frozen_crosswalk(**frozen_pinned_inputs)
    return {**result, "release_authorized": False,
            "producer_authorized": False, "claim_authorized": False,
            "code_only": True}
