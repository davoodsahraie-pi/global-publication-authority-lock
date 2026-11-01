#!/usr/bin/env python3
import hashlib, json
from pathlib import Path
from transition_guard import attempt_snapshot, gen34_activation_errors

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


def validate_gen34_admission(lock,private_state,request,authorization,lock_sha):
    """Eligibility for a physical claim, NEVER permission to spawn.

    Caller must first authenticate the owner artifact through GitHub, hash the
    private state and all runtime/input bytes, and subsequently win/read back
    BOTH protected immutable claims. Legacy validate() continues to deny direct
    EXECUTE; no receipt or caller-supplied success flag bypasses that gate.
    """
    profile=lock.get("gen34_r25r7_bridge")
    reasons=gen34_activation_errors(profile)
    if reasons:
        return {"status":"DENY","reasons":reasons,"launch_allowed":False}
    if lock.get("execution_authorized_now") is not True or lock.get("current_action")!={"id":profile["action_id"],"mode":"MUTATING"}:
        reasons.append("GEN34_AUTHORITY_NOT_EXECUTABLE")
    contract=private_state.get("next_action_contract",{})
    if (contract.get("id")!=profile["action_id"] or contract.get("mode")!="MUTATING" or
        any(contract.get(k) is not True for k in ("build_authorized","private_payload_delivery_allowed","real_claim_authorized"))):
        reasons.append("GEN34_PRIVATE_STATE_NOT_EXECUTABLE")
    if request.get("schema")!=REQ_SCHEMA or request.get("action_kind")!="EXECUTE" or request.get("mode")!="MUTATING" or request.get("user_explicit_authorization") is not True:
        reasons.append("GEN34_REQUEST_INVALID")
    if request.get("input_public_lock_sha256")!=lock_sha or request.get("input_private_state_sha256")!=lock.get("private_execution_state_sha256"):
        reasons.append("GEN34_STALE_REQUEST")
    for field in ("project","method_id","attempt_id","executor_id","operations","target_scope_ids"):
        if request.get(field)!=profile[field]: reasons.append("GEN34_REQUEST_BINDING_"+field.upper())
    if request.get("requested_action_id")!=profile["action_id"]:
        reasons.append("GEN34_ACTION_MISMATCH")
    reasons+=validate_authorization(authorization,request,lock_sha,lock.get("private_execution_state_sha256"))
    run=str(request.get("authorization_run_id") or "")
    if run in {"40329927057","40761646972","40818118503"}:
        reasons.append("GEN34_NONEXECUTION_OR_CONSUMED_RUN")
    try:
        attempts,runs=attempt_snapshot(lock.get("attempt_ledger",[]))
        key=(profile["project"],profile["method_id"],profile["attempt_id"])
        record=attempts.get(key)
        if not record or record["state"]!="RESERVED":
            reasons.append("GEN34_UNSPENT_RESERVED_ATTEMPT_REQUIRED")
        if run in runs: reasons.append("GEN34_AUTH_RUN_ALREADY_USED")
    except ValueError:
        reasons.append("GEN34_ATTEMPT_LEDGER_INVALID")
    led=lock.get("ledger_hashes",{})
    if digest_id("FAIL:",profile["method_id"]) in led.get("method_fail",[]):
        reasons.append("FAILED_METHOD_RETRY_FORBIDDEN")
    for prefix,key in (("FROZEN:","frozen_project"),("BLOCKED:","blocked_project")):
        if digest_id(prefix,profile["project"]) in led.get(key,[]):
            reasons.append("GEN34_PROJECT_EXECUTION_FORBIDDEN")
    if any(digest_id("PASS:",x) in led.get("immutable_pass",[]) for x in profile["target_scope_ids"]):
        reasons.append("IMMUTABLE_PASS_REIMPLEMENTATION_FORBIDDEN")
    return {"status":"DENY" if reasons else "ELIGIBLE_FOR_PHYSICAL_CLAIM_ONLY",
            "reasons":sorted(set(reasons)),"launch_allowed":False}

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
        attempt_state, used_runs=attempt_snapshot(state.get("attempt_ledger",[]))
    except ValueError as exc:
        reasons.append("ATTEMPT_LEDGER_INVALID:"+str(exc))
        attempt_state={}; used_runs={}
    if action_kind=="EXECUTE" and mutating:
        # A successful preflight cannot consume a Run. Execution must be
        # delegated to a future separately authorized, one-use broker.
        reasons.append("EXECUTE_REQUIRES_DURABLE_ONE_USE_DISPATCH_RECEIPT")
        # GEN33 CODE_ONLY installs no trusted redemption agent or issuer.
        # Do not treat source-bound preflight or receipt metadata as permission.
        reasons.append("GEN33_BROKER_CODE_ONLY_NOT_ACTIVATED")
        attempt_id=req.get("attempt_id")
        method_id=req.get("method_id")
        if not attempt_id or not method_id:
            reasons.append("ATTEMPT_ID_AND_METHOD_REQUIRED")
        else:
            key=(req.get("project"),method_id,attempt_id)
            record=attempt_state.get(key)
            if not record:
                reasons.append("EXECUTE_REQUIRES_RESERVED_ATTEMPT")
            elif record["state"]=="DISPATCHED":
                # V2 records are NOT physical redemption. Keep hard broker DENY.
                reasons.append("DISPATCH_V2_CONTROL_PLANE_ONLY_NO_BROKER")
            elif record["state"]!="ACTIVE":
                reasons.append("EXECUTE_REQUIRES_COMMITTED_START_CLAIM")
            elif str(req.get("authorization_run_id"))!=record["claim_run"]:
                reasons.append("EXECUTE_AUTH_RUN_NOT_CLAIM_OWNER")
            elif req.get("executor_id")!=record["executor"]:
                reasons.append("EXECUTE_EXECUTOR_ID_MISMATCH")

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


# R17R9 11-delta code-only review. It never modifies active authorization.
def review_r17r9_11_successor_code_only(lock, candidate):
    from transition_guard import audit_r17r9_11_successor_draft, GEN34_PINS
    checked = audit_r17r9_11_successor_draft(candidate)
    reasons = list(checked["reasons"])
    if not isinstance(lock, dict):
        reasons.append("PUBLIC_LOCK_REQUIRED")
    else:
        if lock.get("execution_authorized_now") is not False:
            reasons.append("READ_ONLY_LOCK_REQUIRED")
        if (lock.get("current_action") or {}).get("mode") != "READ_ONLY":
            reasons.append("READ_ONLY_CURRENT_ACTION_REQUIRED")
        profile = lock.get("gen34_r25r7_bridge") or {}
        if profile.get("source_sha256") != GEN34_PINS["source_sha256"]:
            reasons.append("HISTORICAL_GEN34_PROFILE_CHANGED")
    return {"status": "DENY" if reasons else "DRAFT_VALID_NOT_ADMITTED",
            "reasons": sorted(set(reasons)), "source_admitted": False,
            "launch_allowed": False, "claim_allowed": False}


def validate_r17r9_11_successor_admission(lock, private_state, request, auth, public_sha):
    """Eligibility for protected physical claim ONLY; never a launch grant."""
    from transition_guard import (
        r17r9_11_successor_activation_errors, R17R9_11_OWNER_VOTE_ID,
        R17R9_11_SOURCE_SHA256, R17R9_11_MANIFEST_SHA256,
        R17R9_11_NEW_ATTEMPT,
    )
    if not isinstance(lock,dict) or not isinstance(private_state,dict):
        return {"status":"DENY","reasons":["R17R9_STATES_REQUIRED"],"launch_allowed":False}
    profile=lock.get("r17r9_11_successor")
    reasons=r17r9_11_successor_activation_errors(profile)
    if reasons: return {"status":"DENY","reasons":reasons,"launch_allowed":False}
    if lock.get("execution_authorized_now") is not True or lock.get("current_action")!={"id":profile["action_id"],"mode":"MUTATING"}:
        reasons.append("R17R9_PUBLIC_EXECUTE_NOT_SELECTED")
    contract=private_state.get("next_action_contract") or {}
    if not isinstance(contract,dict): contract={}
    required={
        "id":profile["action_id"],"mode":"MUTATING",
        "source_sha256":R17R9_11_SOURCE_SHA256,
        "attempt_id":R17R9_11_NEW_ATTEMPT,
        "method_id":profile["method_id"],
        "owner_source_adoption_comment_id":R17R9_11_OWNER_VOTE_ID,
        "source_admission_status":"FORMALLY_ADMITTED",
    }
    if any(contract.get(k)!=v for k,v in required.items()) or any(
        contract.get(k) is not True for k in (
        "build_authorized","private_payload_delivery_allowed","real_claim_authorized")):
        reasons.append("R17R9_PRIVATE_SOURCE_BINDING_OR_ADMISSION_MISSING")
    if not isinstance(request,dict) or request.get("schema")!=REQ_SCHEMA or request.get("action_kind")!="EXECUTE" or request.get("mode")!="MUTATING" or request.get("user_explicit_authorization") is not True:
        reasons.append("R17R9_EXECUTE_REQUEST_INVALID")
    else:
        for k in ("project","method_id","attempt_id","executor_id","operations","target_scope_ids"):
            if request.get(k)!=profile[k]: reasons.append("R17R9_REQUEST_BINDING:"+k)
        if request.get("requested_action_id")!=profile["action_id"]:
            reasons.append("R17R9_ACTION_BINDING_MISMATCH")
        if request.get("input_public_lock_sha256")!=public_sha or request.get("input_private_state_sha256")!=lock.get("private_execution_state_sha256"):
            reasons.append("R17R9_STALE_STATE_REQUEST")
        reasons+=validate_authorization(auth,request,public_sha,lock.get("private_execution_state_sha256"))
    try:
        attempts,runs=attempt_snapshot(lock.get("attempt_ledger",[]))
        key=(profile["project"],profile["method_id"],profile["attempt_id"])
        reserved=attempts.get(key)
        if not reserved or reserved["state"]!="RESERVED":
            reasons.append("R17R9_NEW_UNSPENT_RESERVATION_REQUIRED")
        if str(request.get("authorization_run_id") or "") in runs:
            reasons.append("R17R9_AUTHORIZATION_REPLAY_FORBIDDEN")
        if reserved and reserved["source"] not in {public_sha,lock.get("previous_public_lock_sha256")}:
            reasons.append("R17R9_ATTEMPT_SOURCE_LOCK_MISMATCH")
        if key[2]=="GEN34_R25R7_E2E_01":
            reasons.append("R17R9_HISTORICAL_ATTEMPT_REPLAY_FORBIDDEN")
    except (ValueError,TypeError,AttributeError):
        reasons.append("R17R9_ATTEMPT_LEDGER_INVALID")
    ledger=lock.get("ledger_hashes") or {}
    if digest_id("FAIL:",profile["method_id"]) in ledger.get("method_fail",[]):
        reasons.append("R17R9_FAILED_METHOD_FORBIDDEN")
    if any(digest_id(tag,profile["project"]) in ledger.get(name,[])
           for tag,name in (("FROZEN:","frozen_project"),("BLOCKED:","blocked_project"))):
        reasons.append("R17R9_PROJECT_BLOCKED")
    if any(digest_id("PASS:",s) in ledger.get("immutable_pass",[])
           for s in profile["target_scope_ids"]):
        reasons.append("R17R9_PREVIOUS_PASS_FORBIDS_REPLAY")
    return {"status":"DENY" if reasons else "ELIGIBLE_FOR_PHYSICAL_CLAIM_ONLY",
            "reasons":sorted(set(reasons)),"launch_allowed":False}
