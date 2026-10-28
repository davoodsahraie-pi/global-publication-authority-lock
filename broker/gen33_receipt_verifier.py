#!/usr/bin/env python3
"""CODE_ONLY prototype of terminal receipt verification, not an issuer.

Real receipt keys and issuer identity are NOT provisioned. Receipt absence,
unknown signer, weak key, mismatch and replay all fail closed. A SHA string
alone is never a receipt. Verification does not authorize a Producer launch.
"""
import hashlib
import hmac
import json

RECEIPT_SCHEMA="GEN33_TERMINAL_BROKER_RECEIPT/1.0.0"
RESULTS={"NOT_LAUNCHED","STARTED_NO_OUTPUT","COMPLETED"}
REQUIRED=("schema","issuer","attempt_key_sha256","dispatch_descriptor_sha256",
          "claim_ref","claim_commit_sha","terminal_result","output_sha256",
          "authorization_run_id","nonce")


def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def verify_terminal_receipt(receipt, trusted_key, expected, seen_nonces=()):
    reasons=[]
    if not isinstance(receipt,dict) or not isinstance(expected,dict):
        return {"authenticated":False,"reasons":["RECEIPT_SCHEMA_INVALID"]}
    if receipt.get("schema")!=RECEIPT_SCHEMA or any(k not in receipt for k in REQUIRED):
        reasons.append("RECEIPT_SCHEMA_INVALID")
    if set(receipt)!=(set(REQUIRED)|{"mac_sha256"}): reasons.append("RECEIPT_EXTRA_OR_MISSING_FIELDS")
    for key in ("issuer","attempt_key_sha256","dispatch_descriptor_sha256","claim_ref",
                "claim_commit_sha","authorization_run_id"):
        if not expected.get(key) or receipt.get(key)!=expected[key]: reasons.append("RECEIPT_BINDING_MISMATCH_"+key.upper())
    if receipt.get("terminal_result") not in RESULTS: reasons.append("RECEIPT_RESULT_INVALID")
    output=receipt.get("output_sha256")
    if receipt.get("terminal_result")=="COMPLETED":
        if not isinstance(output,str) or len(output)!=64 or any(x not in "0123456789abcdef" for x in output):
            reasons.append("RECEIPT_OUTPUT_REQUIRED")
    elif output is not None: reasons.append("NONCOMPLETED_OUTPUT_FORBIDDEN")
    if not isinstance(receipt.get("nonce"),str) or len(receipt["nonce"])<16:
        reasons.append("RECEIPT_NONCE_INVALID")
    elif receipt["nonce"] in seen_nonces: reasons.append("RECEIPT_REPLAY")
    if not isinstance(trusted_key,bytes) or len(trusted_key)<32:
        reasons.append("TRUSTED_ISSUER_KEY_UNAVAILABLE")
    mac=receipt.get("mac_sha256")
    if not isinstance(mac,str) or len(mac)!=64 or any(c not in "0123456789abcdef" for c in mac):
        reasons.append("MAC_INVALID")
    elif isinstance(trusted_key,bytes) and len(trusted_key)>=32:
        message=canonical({k:v for k,v in receipt.items() if k!="mac_sha256"})
        want=hmac.new(trusted_key,message,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want,mac): reasons.append("MAC_AUTHENTICATION_FAILED")
    return {"authenticated":not reasons,"reasons":sorted(set(reasons)),
            "launch_allowed":False}
