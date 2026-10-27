#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

def sha_file(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p): return json.loads(Path(p).read_text(encoding="utf-8"))


# Motion F: public-lock append-only Attempt event ledger.
# No historical receipts are migrated or synthesized into new reservations.
EVENT_SCHEMA="GLOBAL_PUBLICATION_ATTEMPT_EVENT/1.0.0"
ATTEMPT_EVENTS=("RESERVE","START","CLOSE")
HISTORICAL_GEN29_RUN="40329927057"
# A START/CLOSE event must consume its own distinct authorization Run.
# A reserved Run must never be reused as the START or CLOSE authorization.
def run_id(value):
    return value if isinstance(value,str) and value.isdigit() and value!="" else None

def executor_id(value):
    return isinstance(value,str) and value.strip()!="" and len(value)<=256


def attempt_snapshot(events):
    """Replay immutable events; raise ValueError on any ambiguous or replayed identity."""
    attempts={}; runs={}
    if not isinstance(events,list): raise ValueError("ATTEMPT_LEDGER_NOT_LIST")
    for event in events:
        if not isinstance(event,dict) or event.get("schema")!=EVENT_SCHEMA:
            raise ValueError("ATTEMPT_EVENT_SCHEMA_INVALID")
        typ=event.get("event")
        if typ not in ATTEMPT_EVENTS: raise ValueError("ATTEMPT_EVENT_TYPE_INVALID")
        key=tuple(event.get(k) for k in ("project_id","method_id","attempt_id"))
        if not all(isinstance(x,str) and x.strip() for x in key):
            raise ValueError("ATTEMPT_KEY_INVALID")
        run=str(event.get("owner_authorization_run_id") or "")
        pin=event.get("reservation_source_public_sha256")
        if not run.isdigit() or not isinstance(pin,str) or len(pin)!=64 or any(c not in "0123456789abcdef" for c in pin):
            raise ValueError("ATTEMPT_PROVENANCE_INVALID")
        if run==HISTORICAL_GEN29_RUN or key[2]=="GEN29_ATTEMPT_01":
            raise ValueError("HISTORICAL_GEN29_ALREADY_CONSUMED")
        if typ=="RESERVE":
            if key in attempts: raise ValueError("ATTEMPT_DUPLICATE_RESERVATION")
            if run in runs: raise ValueError("AUTHORIZATION_RUN_ALREADY_RESERVED")
            if event.get("candidate_sha256") is not None:
                raise ValueError("RESERVATION_HAS_CANDIDATE")
            attempts[key]={"state":"RESERVED","run":run,"source":pin,
                           "candidate":None,"claim_run":None,"executor":None}
            runs[run]=key
        else:
            if key not in attempts: raise ValueError("UNRESERVED_ATTEMPT")
            existing=attempts[key]
            if run!=existing["run"] or pin!=existing["source"]:
                raise ValueError("ATTEMPT_PROVENANCE_CHANGED")
            if existing["state"]=="CLOSED":
                raise ValueError("CLOSED_ATTEMPT_REOPEN_OR_REPLAY")
            claim=run_id(event.get("event_authorization_run_id"))
            if claim is None: raise ValueError("ATTEMPT_EVENT_AUTH_RUN_INVALID")
            if claim in runs or claim==HISTORICAL_GEN29_RUN:
                raise ValueError("AUTHORIZATION_RUN_ALREADY_CONSUMED")
            if typ=="START":
                if existing["state"]!="RESERVED": raise ValueError("ATTEMPT_START_REPLAY")
                if event.get("candidate_sha256") is not None:
                    raise ValueError("START_HAS_CANDIDATE")
                if not executor_id(event.get("executor_id")):
                    raise ValueError("START_EXECUTOR_ID_REQUIRED")
                existing["state"]="ACTIVE"
                existing["claim_run"]=claim
                existing["executor"]=event["executor_id"]
            elif typ=="CLOSE":
                if existing["state"] not in {"RESERVED","ACTIVE"}:
                    raise ValueError("ATTEMPT_CLOSE_INVALID_STATE")
                if existing["state"]=="ACTIVE":
                    if event.get("executor_id")!=existing["executor"]:
                        raise ValueError("ATTEMPT_EXECUTOR_ID_CHANGED")
                elif event.get("executor_id") is not None:
                    raise ValueError("UNSTARTED_CLOSE_HAS_EXECUTOR")
                cand=event.get("candidate_sha256")
                if cand is not None and (not isinstance(cand,str) or len(cand)!=64 or any(c not in "0123456789abcdef" for c in cand)):
                    raise ValueError("CANDIDATE_SHA_INVALID")
                if existing["state"]=="RESERVED" and cand is not None:
                    raise ValueError("UNSTARTED_ATTEMPT_HAS_CANDIDATE")
                existing["state"]="CLOSED"
                existing["candidate"]=cand
            runs[claim]=key
    return attempts,runs

def audit_attempt_transition(cur,prop,request,cur_sha):
    reasons=[]
    before=cur.get("attempt_ledger",[])
    after=prop.get("attempt_ledger",[])
    if not isinstance(before,list) or not isinstance(after,list):
        return ["ATTEMPT_LEDGER_NOT_LIST"]
    if after[:len(before)]!=before:
        reasons.append("ATTEMPT_LEDGER_IMMUTABLE_PREFIX_CHANGED")
    for name in ("gen29_attempt01_forensic_closeout_receipt",
                 "gen29_method_bootstrap_scope",
                 "gen31_motion_d_scope_selection_receipt",
                 "gen32_motion_e_gate_implementation_scope_selection_receipt"):
        if cur.get(name)!=prop.get(name):
            reasons.append("HISTORICAL_RECEIPT_MUTATED:"+name)
    # The implementation PR never qualifies its own deployment.
    if prop.get("runtime_gate_activation_verified") is True and cur.get("runtime_gate_activation_verified") is not True:
        reasons.append("ACTIVATION_REQUIRES_INDEPENDENT_TRUSTED_BASE_PROOF")
    if prop.get("gate_hardening_implemented") is True and cur.get("gate_hardening_implemented") is not True:
        reasons.append("IMPLEMENTATION_STATUS_REQUIRES_POST_MERGE_PROOF")
    if len(after)>len(before)+1:
        reasons.append("MULTIPLE_ATTEMPT_EVENTS_IN_ONE_TRANSITION")
    try:
        before_attempts,before_runs=attempt_snapshot(before)
        attempt_snapshot(after)
    except ValueError as exc:
        reasons.append(str(exc))
        return sorted(set(reasons))
    if len(after)<=len(before):
        return sorted(set(reasons))
    event=after[-1]
    if event.get("event")=="RESERVE" and event.get("reservation_source_public_sha256")!=cur_sha:
        reasons.append("RESERVATION_SOURCE_LOCK_SHA_MISMATCH")
    if not any(k in {"GOVERNANCE_UPGRADE","EXECUTE"} for k in [request.get("action_kind")]):
        reasons.append("ATTEMPT_EVENT_ACTION_KIND_FORBIDDEN")
    ops=[v if isinstance(v,str) else v.get("type") for v in request.get("operations",[])]
    if not set(ops).intersection({"GOVERNANCE_UPGRADE","PATCH","EXECUTE","STATE_TRANSITION"}):
        reasons.append("ATTEMPT_EVENT_REQUIRES_MUTATING_OPERATION")
    if any(event.get(k)!=request.get(v) for k,v in
           (("project_id","project"),("method_id","method_id"),("attempt_id","attempt_id"))):
        reasons.append("ATTEMPT_EVENT_REQUEST_IDENTITY_MISMATCH")
    run=str(request.get("authorization_run_id") or "")
    if not run.isdigit(): reasons.append("ATTEMPT_EVENT_REQUEST_AUTH_RUN_MISSING")
    if event.get("event")=="RESERVE" and run!=str(event.get("owner_authorization_run_id")):
        reasons.append("RESERVATION_OWNER_RUN_MISMATCH")
    if event.get("event")!="RESERVE":
        if run!=event.get("event_authorization_run_id"):
            reasons.append("ATTEMPT_EVENT_AUTH_RUN_MISMATCH")
        if run in before_runs:
            reasons.append("AUTHORIZATION_RUN_ALREADY_CONSUMED")
        first=before_attempts.get(tuple(event.get(k) for k in ("project_id","method_id","attempt_id")))
        if first is None: reasons.append("ATTEMPT_EVENT_NOT_PREVIOUSLY_RESERVED")
        elif str(event.get("owner_authorization_run_id"))!=first["run"]:
            reasons.append("ATTEMPT_OWNER_RUN_CHANGED")
    if request.get("input_public_lock_sha256")!=cur_sha:
        reasons.append("ATTEMPT_EVENT_REQUEST_SOURCE_SHA_MISMATCH")
    if event.get("event")=="START":
        if event.get("executor_id")!=request.get("executor_id"):
            reasons.append("ATTEMPT_EXECUTOR_REQUEST_MISMATCH")
    if event.get("event")=="CLOSE":
        if event.get("executor_id")!=request.get("executor_id"):
            reasons.append("ATTEMPT_EXECUTOR_REQUEST_MISMATCH")
    return sorted(set(reasons))

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

    reasons += audit_attempt_transition(cur,prop,request,cur_sha)

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
