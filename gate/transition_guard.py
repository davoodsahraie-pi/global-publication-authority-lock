#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

def sha_file(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p): return json.loads(Path(p).read_text(encoding="utf-8"))

def validate_transition(current_path, proposed_path, request):
    cur=load(current_path); prop=load(proposed_path)
    cur_sha=sha_file(current_path)
    reasons=[]
    if prop.get("generation")!=int(cur.get("generation") or 0)+1: reasons.append("GENERATION_NOT_INCREMENTED_BY_ONE")
    if prop.get("previous_public_lock_sha256")!=cur_sha: reasons.append("PREDECESSOR_PUBLIC_LOCK_SHA_MISMATCH")
    for ledger in ("immutable_pass","method_fail","frozen_project","blocked_project"):
        a=set((cur.get("ledger_hashes") or {}).get(ledger) or [])
        b=set((prop.get("ledger_hashes") or {}).get(ledger) or [])
        if not a.issubset(b): reasons.append("LEDGER_REMOVAL_FORBIDDEN:"+ledger)

    kind=request.get("action_kind","EXECUTE")
    if kind=="SET_NEXT_ACTION":
        allowed={"generation","previous_public_lock_sha256","current_action","execution_authorized_now"}
        changed=[k for k in set(cur)|set(prop) if cur.get(k)!=prop.get(k)]
        illegal=[k for k in changed if k not in allowed]
        if illegal: reasons.append("SET_NEXT_ACTION_ILLEGAL_CHANGE:"+",".join(sorted(illegal)))
    elif kind!="GOVERNANCE_UPGRADE":
        if cur.get("policy")!=prop.get("policy"): reasons.append("POLICY_CHANGE_REQUIRES_GOVERNANCE_UPGRADE")

    return {
      "schema":"GLOBAL_PUBLICATION_PUBLIC_TRANSITION_RESULT/1.0.0",
      "status":"DENY" if reasons else "PASS",
      "current_public_lock_sha256":cur_sha,
      "proposed_public_lock_sha256":sha_file(proposed_path),
      "reasons":reasons
    }
