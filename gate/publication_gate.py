#!/usr/bin/env python3
import hashlib, json
from pathlib import Path
from transition_guard import attempt_snapshot

READ_ONLY_OPS={"READ","VERIFY_HASH","READ_ONLY_ANALYSIS","REPORT","GAP_MAP","VERIFY_BACKEND"}
MUTATING_OPS={"BUILD","PATCH","RENDER","EXPORT_PDF","GENERATE_DOCX","GENERATE_PDF","PROMOTE","QUALIFY","WRITE_CURRENT","UPDATE_POINTER","SOURCE_REBUILD","REQUALIFY","REIMPLEMENT","DELETE","MOVE","RENAME","UPLOAD_OFFICIAL","STATE_TRANSITION","AUTHORITY_UPDATE","ACTIVATE_BACKEND","SET_NEXT_ACTION","GOVERNANCE_UPGRADE"}
REQ_SCHEMA="GLOBAL_PUBLICATION_PUBLIC_ACTION_REQUEST/1.0.0"
AUTH_SCHEMA="GLOBAL_PUBLICATION_MANUAL_AUTHORIZATION/1.0.0"

def sha_file(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load_json(p): return json.loads(Path(p).read_text(encoding="utf-8"))
def sidecar_digest(p): return Path(p).read_text(encoding="utf-8").strip().split()[0].lower()
def digest_id(prefix,value): return hashlib.sha256((prefix+str(value).upper()).encode("utf-8")).hexdigest()

def norm_ops(ops):
    out=[]
    for op in ops or []:
        if isinstance(op,str): out.append(op)
        elif isinstance(op,dict) and op.get("type"): out.append(str(op["type"]))
    return out

def validate_authorization(auth, request, lock_sha, private_sha):
    reasons=[]
    if not auth:
        return ["MUTATING_ACTION_REQUIRES_MANUAL_WORKFLOW_AUTHORIZATION"]
    if auth.get("schema")!=AUTH_SCHEMA: reasons.append("AUTH_SCHEMA_INVALID")
    if auth.get("public_lock_sha256")!=lock_sha: reasons.append("AUTH_STALE_OR_WRONG_PUBLIC_LOCK_SHA")
    if auth.get("private_execution_state_sha256")!=private_sha: reasons.append("AUTH_STALE_OR_WRONG_PRIVATE_STATE_SHA")
    if auth.get("requested_action_id")!=request.get("requested_action_id"): reasons.append("AUTH_ACTION_MISMATCH")
    if auth.get("action_kind")!=request.get("action_kind"): reasons.append("AUTH_ACTION_KIND_MISMATCH")
    if auth.get("project")!=request.get("project"): reasons.append("AUTH_PROJECT_MISMATCH")
    if sorted(auth.get("operations") or [])!=sorted(norm_ops(request.get("operations"))): reasons.append("AUTH_OPERATIONS_MISMATCH")
    if sorted(auth.get("target_scope_ids") or [])!=sorted(request.get("target_scope_ids") or []): reasons.append("AUTH_TARGET_SCOPE_MISMATCH")
    if auth.get("manual_workflow") is not True: reasons.append("AUTH_NOT_MANUAL_WORKFLOW")
    # A manual authorization artifact belongs to exactly its submitted Run.
    if str(auth.get("github_run_id") or "")!=str(request.get("authorization_run_id") or ""):
        reasons.append("AUTHORIZATION_RUN_ID_MISMATCH")
    if str(auth.get("authorization_id") or "")!=str(request.get("authorization_run_id") or ""):
        reasons.append("AUTHORIZATION_ID_MISMATCH")
    return reasons

def validate(lock_path, sidecar_path, request_path, authorization=None):
    reasons=[]
    lock_sha=sha_file(lock_path)
    if sidecar_digest(sidecar_path)!=lock_sha: reasons.append("PUBLIC_LOCK_SIDECAR_MISMATCH")
    try: state=load_json(lock_path)
    except Exception as e: return {"status":"DENY","reasons":[f"LOCK_JSON_INVALID:{e}"]}
    try: req=load_json(request_path)
    except Exception as e: return {"status":"DENY","reasons":[f"REQUEST_JSON_INVALID:{e}"]}

    if req.get("schema")!=REQ_SCHEMA: reasons.append("REQUEST_SCHEMA_INVALID")
    if req.get("input_public_lock_sha256")!=lock_sha: reasons.append("STALE_OR_WRONG_PUBLIC_LOCK_SHA")
    private_sha=state.get("private_execution_state_sha256")
    if req.get("input_private_state_sha256")!=private_sha: reasons.append("STALE_OR_WRONG_PRIVATE_STATE_SHA")
    if req.get("user_explicit_authorization") is not True: reasons.append("USER_EXPLICIT_AUTHORIZATION_FLAG_REQUIRED")

    ops=norm_ops(req.get("operations"))
    unknown=[x for x in ops if x not in READ_ONLY_OPS and x not in MUTATING_OPS]
    if unknown: reasons.append("UNKNOWN_OPERATION_TYPE:"+",".join(sorted(set(unknown))))
    mutating=any(x in MUTATING_OPS for x in ops)
    action_kind=req.get("action_kind","EXECUTE")
    cur=state.get("current_action") or {}

    if action_kind in {"SET_NEXT_ACTION","GOVERNANCE_UPGRADE"}:
        if not mutating: reasons.append("SPECIAL_ACTION_MUST_BE_MUTATING")
        reasons += validate_authorization(authorization,req,lock_sha,private_sha)
    else:
        if req.get("requested_action_id")!=cur.get("id"): reasons.append("ACTION_NOT_EXACT_NEXT_ACTION")
        if req.get("mode")!=cur.get("mode"): reasons.append("ACTION_MODE_MISMATCH")
        if cur.get("mode")=="READ_ONLY" and mutating: reasons.append("MUTATION_FORBIDDEN_BY_READ_ONLY_NEXT_ACTION")
        if mutating:
            if state.get("execution_authorized_now") is not True: reasons.append("PUBLIC_LOCK_DOES_NOT_AUTHORIZE_MUTATING_EXECUTION_NOW")
            reasons += validate_authorization(authorization,req,lock_sha,private_sha)

    # Gate deployment does not create reservations retroactively.  All future
    # mutating EXECUTE attempts must have a protected, unspent reservation.
    try:
        attempt_state, reserved_runs=attempt_snapshot(state.get("attempt_ledger",[]))
    except ValueError as exc:
        reasons.append("ATTEMPT_LEDGER_INVALID:"+str(exc))
        attempt_state={}
    if action_kind=="EXECUTE" and mutating:
        attempt_id=req.get("attempt_id")
        method_id=req.get("method_id")
        if not attempt_id or not method_id:
            reasons.append("ATTEMPT_ID_AND_METHOD_REQUIRED")
        else:
            key=(req.get("project"),method_id,attempt_id)
            record=attempt_state.get(key)
            if not record:
                reasons.append("EXECUTE_REQUIRES_RESERVED_ATTEMPT")
            elif record["state"]!="RESERVED":
                reasons.append("EXECUTE_ATTEMPT_ALREADY_STARTED_OR_CLOSED")
            elif str(req.get("authorization_run_id"))==record["run"]:
                reasons.append("RESERVATION_AUTHORIZATION_RUN_REUSE_FOR_EXECUTE")

    project=req.get("project") or ""
    method=req.get("method_id") or ""
    targets=req.get("target_scope_ids") or []
    led=state.get("ledger_hashes") or {}
    if digest_id("FROZEN:",project) in set(led.get("frozen_project") or []) and mutating:
        reasons.append("FROZEN_PROJECT_MUTATION_FORBIDDEN")
    if digest_id("BLOCKED:",project) in set(led.get("blocked_project") or []) and mutating:
        reasons.append("BLOCKED_PROJECT_MUTATION_FORBIDDEN")
    if method and digest_id("FAIL:",method) in set(led.get("method_fail") or []) and mutating:
        reasons.append("FAILED_METHOD_RETRY_FORBIDDEN")
    imm=set(led.get("immutable_pass") or [])
    if any(digest_id("PASS:",x) in imm for x in targets) and any(x in {"BUILD","PATCH","REQUALIFY","REIMPLEMENT","SOURCE_REBUILD"} for x in ops):
        reasons.append("IMMUTABLE_PASS_REIMPLEMENTATION_FORBIDDEN")

    return {
      "schema":"GLOBAL_PUBLICATION_PUBLIC_GATE_RESULT/1.0.0",
      "status":"DENY" if reasons else "ALLOW",
      "public_lock_sha256":lock_sha,
      "private_execution_state_sha256":private_sha,
      "requested_action_id":req.get("requested_action_id"),
      "action_kind":action_kind,
      "operations":ops,
      "reasons":reasons,
      "official_effect":"NO_OFFICIAL_EXECUTION" if reasons else "AUTHORIZED_FOR_THIS_EXACT_LOCK_STATE_AND_ACTION_ONLY"
    }
