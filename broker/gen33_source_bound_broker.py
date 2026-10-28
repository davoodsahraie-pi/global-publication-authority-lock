#!/usr/bin/env python3
"""GEN33 source-bound Broker contract: CODE_ONLY / NOT ACTIVATED.

Pure preflight/classification functions ONLY. This module cannot write Git
refs, read secrets, import/run a Producer, or authorize an attempt. A later
protected activation must bind a separate real-Broker authorization and
trusted input-delivery chain. No caller may interpret CODE_ONLY as EXECUTE.
"""
import hashlib
import json
import re

PROFILE = "LEGACY_R25R7_FULL_BOOK"
GENERATOR_SHA = "646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c"
DRIVER_SHA = "b6ff959711cb3f3b9d103cb627bcc54e11de336b4ea2a4d862aa916ed2cb9191"
PROFILE_SCHEMA = "GEN33_SOURCE_BOUND_RUNTIME_PROFILE/1.0.0"
DESCRIPTOR_DOMAIN = b"GEN33-SOURCE-BOUND-BROKER-CODE-ONLY\0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
REAL_NAMESPACE = "refs/tags/gen33-execution-claim/"

class NotActivated(RuntimeError):
    pass


def is_sha(value):
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def canonical_bytes(obj):
    return json.dumps(obj,sort_keys=True,separators=(",", ":"),ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def descriptor_sha(payload):
    return hashlib.sha256(DESCRIPTOR_DOMAIN + canonical_bytes(payload)).hexdigest()


def expected_claim_ref(project, method, attempt):
    if not all(isinstance(x,str) and ID.fullmatch(x) for x in (project,method,attempt)):
        raise ValueError("IDENTITY_NOT_CANONICAL")
    # Hash prevents path collisions and complex Git ref escaping.
    key = canonical_bytes([project,method,attempt])
    return REAL_NAMESPACE + hashlib.sha256(key).hexdigest()


def preflight(profile, observed_bytes, expected_authority):
    """Inspect proposed bytes and metadata, never issue launch permission.

    This deliberately cannot authenticate GitHub owner actions, trusted
    filesystem provenance or Ruleset enforcement. Those require future
    separately authorized, externally trusted activation code.
    """
    errors=[]
    if not isinstance(profile,dict) or not isinstance(observed_bytes,dict):
        return {"status":"DENY","reasons":["PROFILE_OR_BYTES_INVALID"],"launch_allowed":False}
    if profile.get("schema")!=PROFILE_SCHEMA: errors.append("PROFILE_SCHEMA_INVALID")
    if profile.get("runtime_profile")!=PROFILE: errors.append("RUNTIME_PROFILE_INVALID")
    if profile.get("generator_sha256")!=GENERATOR_SHA: errors.append("ORIGINAL_GENERATOR_IDENTITY_MISMATCH")
    if profile.get("driver_sha256")!=DRIVER_SHA: errors.append("ORIGINAL_DRIVER_IDENTITY_MISMATCH")
    for key in ("canonical_source_sha256","c1_sha256","ppges_sha256","dependency_lock_sha256"):
        if not is_sha(profile.get(key)): errors.append("MISSING_OR_INVALID_"+key.upper())
    for key in ("public_sha256","private_sha256","authorization_run_id"):
        expected=expected_authority.get(key) if isinstance(expected_authority,dict) else None
        if not isinstance(expected,str) or not expected or profile.get(key)!=expected:
            errors.append("AUTHORITY_MISMATCH_"+key.upper())
    if not isinstance(profile.get("authorization_run_id"),str) or not profile["authorization_run_id"].isdigit():
        errors.append("AUTHORIZATION_RUN_INVALID")
    for name,sha_key in (("generator","generator_sha256"),("driver","driver_sha256"),
                         ("source","canonical_source_sha256"),("c1","c1_sha256"),
                         ("ppges","ppges_sha256"),("dependencies","dependency_lock_sha256")):
        data=observed_bytes.get(name)
        if not isinstance(data,bytes) or not is_sha(profile.get(sha_key)):
            errors.append("INPUT_MISSING_OR_UNBOUND_"+name.upper())
        elif hashlib.sha256(data).hexdigest()!=profile[sha_key]:
            errors.append("INPUT_BYTES_MISMATCH_"+name.upper())
    if profile.get("engineering_wheel_sha256") is not None:
        errors.append("ENGINEERING_WHEEL_PROXY_FORBIDDEN")
    # A valid code-only preflight is NOT a real Broker admission decision.
    return {"status":"DENY" if errors else "CODE_ONLY_PREFLIGHT_PASS",
            "reasons":sorted(set(errors)),"launch_allowed":False}


def classify_synthetic_claim(status, response, ref, expected_object_sha, ruleset_verified):
    """Read-only classification of a SIMULATED Git ref-create result.

    Do not use this function alone as physical redemption or launch grant.
    """
    if not ruleset_verified or not isinstance(ref,str) or not ref.startswith(REAL_NAMESPACE):
        return "DENY"
    if not is_sha(ref[len(REAL_NAMESPACE):]) or not isinstance(expected_object_sha,str) \
       or not re.fullmatch(r"[0-9a-f]{40}",expected_object_sha):
        return "DENY"
    if status==422: return "DENY"
    if status!=201: return "UNKNOWN"
    if not isinstance(response,dict): return "UNKNOWN"
    obj=response.get("object")
    if (response.get("ref")!=ref or not isinstance(obj,dict) or
        obj.get("sha")!=expected_object_sha or obj.get("type")!="commit"):
        return "UNKNOWN"
    return "SYNTHETIC_WIN_ONLY"



# GEN33 proof-only capability: maps the original attempt key to an intended
# protected ref. This never creates/claims the ref, consumes a grant, or
# communicates with GitHub. A future separately authorized Broker is required.
def protected_claim_proof_scope(project, method, attempt):
    ref=expected_claim_ref(project,method,attempt)
    return {
        "schema":"GEN33_PROTECTED_CLAIM_SCOPE/1.0.0",
        "ref":ref,
        "namespace":REAL_NAMESPACE,
        "mode":"PROOF_ONLY_NOT_ACTIVATED",
        "physical_claim_authorized":False,
        "producer_launch_authorized":False
    }


def launch_producer(*_args, **_kwargs):
    raise NotActivated("GEN33_BROKER_CODE_ONLY_NO_REAL_PRODUCER_EXECUTION")
