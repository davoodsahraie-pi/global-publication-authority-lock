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

# Additive control-plane protocol. Historical v1 RESERVE/START/CLOSE is immutable.
DISPATCH_V2_SCHEMA="GLOBAL_PUBLICATION_ATTEMPT_EVENT/2.0.0"
DISPATCH_V2_SHA_FIELDS=('package_sha256','wheel_sha256','canonical_source_sha256','c1_sha256','ppges_sha256','dependency_lock_sha256','input_manifest_sha256','runtime_code_sha256','runtime_workflow_sha256',)
DISPATCH_V2_TEXT_FIELDS=("purpose","output_identity","runtime_domain")
def is_sha256(x):
    return isinstance(x,str) and len(x)==64 and all(c in "0123456789abcdef" for c in x)
def dispatch_v2_descriptor(event):
    # Descriptor is NOT a protected-main launch grant; never use it to spawn.
    canonical={k:v for k,v in event.items() if k!="descriptor_sha256"}
    encoded=json.dumps(canonical,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(b"GLOBAL-PUBLICATION-DISPATCH-V2-DESCRIPTOR\x00"+encoded).hexdigest()

# GEN33 source-bound descriptor is a DESIGN fingerprint ONLY. It is not a
# DISPATCH v2 event, a redeemed grant, a receipt, or an EXECUTE allowance.
GEN33_SOURCE_BOUND_DESCRIPTOR_DOMAIN=b"GEN33-SOURCE-BOUND-BROKER-CODE-ONLY\0"
def gen33_source_bound_fingerprint(material):
    if not isinstance(material,dict): raise ValueError("GEN33_MATERIAL_NOT_OBJECT")
    required=("generator_sha256","driver_sha256","canonical_source_sha256",
              "c1_sha256","ppges_sha256","dependency_lock_sha256")
    if any(not is_sha256(material.get(key)) for key in required):
        raise ValueError("GEN33_SOURCE_BOUND_MATERIAL_INVALID")
    raw=json.dumps({k:material[k] for k in required},sort_keys=True,
                   separators=(",",":"),ensure_ascii=True).encode("ascii")
    return hashlib.sha256(GEN33_SOURCE_BOUND_DESCRIPTOR_DOMAIN+raw).hexdigest()


# GEN34 is an opt-in source-bound runtime. The existing v1/v2 ledger protocol
# remains unchanged. Physical claims live in the already protected GEN33 tag
# namespace; no code-only PR creates reservations or activates this contract.
GEN34_SCHEMA="GEN34_R25R7_BRIDGE_ACTIVATION/1.0"
GEN34_PINS={
    "generator_sha256":"646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c",
    "driver_sha256":"b6ff959711cb3f3b9d103cb627bcc54e11de336b4ea2a4d862aa916ed2cb9191",
    "source_sha256":"360ee8a7db0cfead8576b68b768bfa9e0f4038fd9f2892102e801541abc272d5",
    "c1_sha256":"b215660f571e32c647186eba253c89b5255567c313c068c0898301ab9eb789d3",
    "ppges_sha256":"8175f477e0d45c25db894fd00fb51cd3bd0ad78ea18b61aaa034a02f725a1371",
    "grammar_sha256":"182589531ab1f2b0302fbc567f93510183af20d4682b99318bf6e4efea364213",
}
GEN34_SHA_FIELDS=("bundle_sha256","manifest_sha256","dependency_lock_sha256",
                  "runtime_code_sha256","runtime_workflow_sha256","receipt_key_sha256")
GEN34_TEXT_FIELDS=("action_id","project","method_id","attempt_id","executor_id")

def gen34_activation_errors(profile):
    import re
    required=set(GEN34_PINS)|set(GEN34_SHA_FIELDS)|set(GEN34_TEXT_FIELDS)|{
        "schema","enabled","runtime_profile","private_repository","bundle_blob_sha",
        "environment","target_scope_ids","operations","max_seconds"}
    if not isinstance(profile,dict) or set(profile)!=required:
        return ["GEN34_ACTIVATION_FIELDS_INVALID"]
    errors=[]
    if profile["schema"]!=GEN34_SCHEMA or profile["enabled"] is not True:
        errors.append("GEN34_NOT_ACTIVATED")
    if profile["runtime_profile"]!="LEGACY_R25R7_FULL_BOOK":
        errors.append("GEN34_ENGINEERING_WHEEL_OR_PROFILE_FORBIDDEN")
    if any(profile[k]!=v for k,v in GEN34_PINS.items()):
        errors.append("GEN34_IMMUTABLE_INPUT_PIN_MISMATCH")
    if any(not is_sha256(profile[k]) for k in GEN34_SHA_FIELDS):
        errors.append("GEN34_RUNTIME_PIN_INVALID")
    if not re.fullmatch(r"[0-9a-f]{40}",str(profile["bundle_blob_sha"])):
        errors.append("GEN34_PRIVATE_BLOB_INVALID")
    if any(not isinstance(profile[k],str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",profile[k]) for k in GEN34_TEXT_FIELDS):
        errors.append("GEN34_IDENTITY_INVALID")
    if profile["private_repository"]!="davoodsahraie-pi/global-publication-authority":
        errors.append("GEN34_PRIVATE_DESTINATION_INVALID")
    if profile["environment"]!="gen34-r25r7-production":
        errors.append("GEN34_ENVIRONMENT_INVALID")
    if profile["operations"]!=["BUILD","GENERATE_DOCX"] or profile["target_scope_ids"]!=["GEN34_R25R7_ORIGINAL_FULL_BOOK_ONCE"]:
        errors.append("GEN34_EXECUTION_SCOPE_INVALID")
    if type(profile["max_seconds"]) is not int or not 1<=profile["max_seconds"]<=3000:
        errors.append("GEN34_TIME_BOUND_INVALID")
    return errors

def gen34_descriptor(profile,public_sha,private_sha,authorization_run_id):
    material={"profile":profile,"public_sha256":public_sha,
              "private_sha256":private_sha,"authorization_run_id":str(authorization_run_id)}
    raw=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
    return hashlib.sha256(b"GEN34-R25R7-BOUND-DISPATCH\0"+raw).hexdigest()

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
        if not isinstance(event,dict):
            raise ValueError("ATTEMPT_EVENT_SCHEMA_INVALID")
        version=event.get("schema")
        typ=event.get("event")
        if version==EVENT_SCHEMA:
            if typ not in ATTEMPT_EVENTS: raise ValueError("ATTEMPT_EVENT_TYPE_INVALID")
        elif version==DISPATCH_V2_SCHEMA:
            if typ not in {"DISPATCH","CLOSE"}: raise ValueError("DISPATCH_V2_EVENT_TYPE_INVALID")
        else:
            raise ValueError("ATTEMPT_EVENT_SCHEMA_INVALID")
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
            elif typ=="DISPATCH":
                if existing["state"]!="ACTIVE":
                    raise ValueError("DISPATCH_REQUIRES_STARTED_ATTEMPT")
                if event.get("executor_id")!=existing["executor"]:
                    raise ValueError("DISPATCH_EXECUTOR_ID_CHANGED")
                if not is_sha256(event.get("dispatch_source_public_sha256")) or not is_sha256(event.get("dispatch_source_private_sha256")):
                    raise ValueError("DISPATCH_SOURCE_SHA_INVALID")
                if any(not is_sha256(event.get(k)) for k in DISPATCH_V2_SHA_FIELDS):
                    raise ValueError("DISPATCH_MATERIAL_SHA_INVALID")
                if any(not isinstance(event.get(k),str) or not event[k].strip() or len(event[k])>256 for k in DISPATCH_V2_TEXT_FIELDS):
                    raise ValueError("DISPATCH_PURPOSE_OR_RUNTIME_INVALID")
                if event.get("candidate_sha256") is not None:
                    raise ValueError("DISPATCH_HAS_CANDIDATE")
                if event.get("descriptor_sha256")!=dispatch_v2_descriptor(event):
                    raise ValueError("DISPATCH_DESCRIPTOR_INVALID")
                existing["state"]="DISPATCHED"
                existing["dispatch_run"]=claim
                existing["dispatch_descriptor"]=event["descriptor_sha256"]
            elif typ=="CLOSE":
                if version==DISPATCH_V2_SCHEMA:
                    if existing["state"]!="DISPATCHED":
                        raise ValueError("V2_CLOSE_REQUIRES_DISPATCH")
                    if not is_sha256(event.get("terminal_broker_receipt_sha256")):
                        raise ValueError("V2_CLOSE_TERMINAL_RECEIPT_REQUIRED")
                    if event.get("terminal_result")!="NOT_LAUNCHED":
                        raise ValueError("V2_CLOSE_REQUIRES_FUTURE_QUALIFIED_BROKER")
                    if event.get("candidate_sha256") is not None:
                        raise ValueError("V2_NEVER_LAUNCHED_HAS_CANDIDATE")
                    if event.get("dispatch_descriptor_sha256")!=existing["dispatch_descriptor"]:
                        raise ValueError("V2_CLOSE_DESCRIPTOR_MISMATCH")
                    # A SHA-looking string does not authenticate a broker receipt.
                    # This five-path control-plane patch installs no trusted Broker;
                    # therefore even NOT_LAUNCHED v2 CLOSE must fail closed.
                    raise ValueError("V2_CLOSE_REQUIRES_AUTHENTICATED_BROKER_RECEIPT")
                elif existing["state"]=="DISPATCHED":
                    raise ValueError("DISPATCHED_ATTEMPT_REQUIRES_V2_CLOSE")
                if existing["state"] not in {"RESERVED","ACTIVE","DISPATCHED"}:
                    raise ValueError("ATTEMPT_CLOSE_INVALID_STATE")
                if existing["state"] in {"ACTIVE","DISPATCHED"}:
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
    if event.get("event")=="DISPATCH":
        if event.get("dispatch_source_public_sha256")!=cur_sha:
            reasons.append("DISPATCH_PREDECESSOR_PUBLIC_SHA_MISMATCH")
        if event.get("dispatch_source_private_sha256")!=cur.get("private_execution_state_sha256"):
            reasons.append("DISPATCH_PREDECESSOR_PRIVATE_SHA_MISMATCH")
        if event.get("executor_id")!=request.get("executor_id"):
            reasons.append("DISPATCH_EXECUTOR_REQUEST_MISMATCH")
        failed=set((cur.get("ledger_hashes") or {}).get("method_fail") or [])
        fail_digest=hashlib.sha256(("FAIL:"+str(event.get("method_id")).upper()).encode("utf-8")).hexdigest()
        if fail_digest in failed: reasons.append("DISPATCH_FAILED_METHOD_FORBIDDEN")
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

    if cur.get("gen34_r25r7_bridge")!=prop.get("gen34_r25r7_bridge"):
        if request.get("action_kind")!="GOVERNANCE_UPGRADE":
            reasons.append("GEN34_ACTIVATION_CHANGE_REQUIRES_GOVERNANCE_UPGRADE")
        if prop.get("gen34_r25r7_bridge") is not None:
            reasons += gen34_activation_errors(prop["gen34_r25r7_bridge"])

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


# ENGSEQ 11-delta successor — owner Run 41270302143 CODE-ONLY.
# Audit functions are deliberately NOT an activation, reservation or Producer path.
# Never mutate GEN34_PINS or replay the completed GEN34_R25R7_E2E_01.
R17R9_11_SUCCESSOR_DRAFT = {
    "schema": "R17R9_ENGSEQ_11_SOURCE_BOUND_DRAFT/1.0",
    "source_original_sha256": "360ee8a7db0cfead8576b68b768bfa9e0f4038fd9f2892102e801541abc272d5",
    "source_successor_lab_sha256": "fbbd4d43367545d14c988d60604ed4523fbe5311fbce7f02b65f7cb742782b40",
    "generator_sha256": "646cf341c774953baa99da400ee3aa6e992fbbd8d0af95f36144f72c0fa5980c",
    "driver_sha256": "b6ff959711cb3f3b9d103cb627bcc54e11de336b4ea2a4d862aa916ed2cb9191",
    "record_count": 21529,
    "changed_publication_ids": [35, 38, 637, 647, 1558, 1596, 1638, 1783, 3067, 5583, 21473],
    "unchanged_record_count": 21518,
    "legacy_attempt_id": "GEN34_R25R7_E2E_01",
    "candidate_attempt_id": None,
    "bundle_sha256": None,
    "official_source_admitted": False,
    "reserved_attempt_confirmed": False,
    "execution_authorized": False,
    "enabled": False,
    "status": "DRAFT_SOURCE_BOUND_REVIEW_ONLY",
}

def audit_r17r9_11_successor_draft(candidate):
    """Validate one exact inactive dossier, NEVER grant source admission or EXECUTE.

    No client-provided 'approved' field can promote the frozen LAB candidate.
    An actual successor requires a separately governed protected activation,
    new private bundle, distinct attempt, and owner EXECUTE authorization.
    """
    if not isinstance(candidate, dict):
        return {"status": "DENY", "reasons": ["DRAFT_NOT_OBJECT"],
                "source_admitted": False, "launch_allowed": False}
    reasons = []
    if set(candidate) != set(R17R9_11_SUCCESSOR_DRAFT):
        reasons.append("EXACT_DRAFT_FIELD_SET_REQUIRED")
    for key, expected in R17R9_11_SUCCESSOR_DRAFT.items():
        if candidate.get(key) != expected or type(candidate.get(key)) is not type(expected):
            reasons.append("DRAFT_PIN_OR_SCOPE_MISMATCH:" + key)
    if GEN34_PINS["source_sha256"] != R17R9_11_SUCCESSOR_DRAFT["source_original_sha256"]:
        reasons.append("LEGACY_SOURCE_PIN_CHANGED")
    if GEN34_PINS["generator_sha256"] != R17R9_11_SUCCESSOR_DRAFT["generator_sha256"]:
        reasons.append("GENERATOR_PIN_CHANGED")
    if GEN34_PINS["driver_sha256"] != R17R9_11_SUCCESSOR_DRAFT["driver_sha256"]:
        reasons.append("DRIVER_PIN_CHANGED")
    return {"status": "DENY" if reasons else "DRAFT_VALID_NOT_ADMITTED",
            "reasons": sorted(set(reasons)), "source_admitted": False,
            "launch_allowed": False}


# ENGSEQ R17R9 11-delta: independent successor, never overwrite legacy GEN34_PINS.
R17R9_11_RUNTIME_SCHEMA = "R17R9_11_SOURCE_BOUND_RUNTIME/1.0"
R17R9_11_SOURCE_SHA256 = "fbbd4d43367545d14c988d60604ed4523fbe5311fbce7f02b65f7cb742782b40"
R17R9_11_MANIFEST_SHA256 = "4bf88aa6ab1632b9bde6757cdd6aac195542d33bfc1940d8ca52604d904ea980"
R17R9_11_OWNER_VOTE_ID = 6553602646
R17R9_11_LAB_INPUT_SHA256 = "9ec2a4aecb320c48adfb9e8be0fd6101ebdab4da27cc007e85655d3ea09106a6"  # old private state: NOT executable
R17R9_11_NEW_ATTEMPT = "R17R9_11_SOURCE_BOUND_E2E_01"
R17R9_11_RUNTIME_KEYS = {
    "schema","enabled","runtime_profile","action_id","project","method_id",
    "attempt_id","executor_id","operations","target_scope_ids","max_seconds",
    "private_repository","environment","source_sha256","manifest_sha256",
    "generator_sha256","driver_sha256","c1_sha256","grammar_sha256",
    "ppges_sha256","dependency_lock_sha256","bundle_sha256","bundle_blob_sha",
    "receipt_key_sha256","runtime_code_sha256","runtime_workflow_sha256",
    "source_admission_status","source_admission_receipt_sha256",
    "owner_source_adoption_comment_id",
}

def r17r9_11_successor_activation_errors(profile):
    """Validate future protected-current identity, not owner EXECUTE or a Claim."""
    import re
    if not isinstance(profile,dict) or set(profile)!=R17R9_11_RUNTIME_KEYS:
        return ["R17R9_SUCCESSOR_EXACT_PROFILE_KEYS_REQUIRED"]
    reasons=[]
    if profile["schema"]!=R17R9_11_RUNTIME_SCHEMA or profile["enabled"] is not True:
        reasons.append("R17R9_NOT_ACTIVATED")
    if profile["runtime_profile"]!="R17R9_11_UNMODIFIED_R25R7_DRIVER":
        reasons.append("R17R9_RUNTIME_PROFILE_INVALID")
    for key,value in {
        "source_sha256":R17R9_11_SOURCE_SHA256,
        "manifest_sha256":R17R9_11_MANIFEST_SHA256,
        "generator_sha256":GEN34_PINS["generator_sha256"],
        "driver_sha256":GEN34_PINS["driver_sha256"],
        "c1_sha256":GEN34_PINS["c1_sha256"],
        "grammar_sha256":GEN34_PINS["grammar_sha256"],
        "ppges_sha256":GEN34_PINS["ppges_sha256"],
        "attempt_id":R17R9_11_NEW_ATTEMPT,
        "project":"GLOBAL",
        "private_repository":"davoodsahraie-pi/global-publication-authority",
        "environment":"gen34-r25r7-production",
        "source_admission_status":"FORMALLY_ADMITTED",
        "owner_source_adoption_comment_id":R17R9_11_OWNER_VOTE_ID,
    }.items():
        if profile.get(key)!=value: reasons.append("R17R9_PIN_INVALID:"+key)
    if profile["operations"]!=["BUILD","GENERATE_DOCX"] or profile["target_scope_ids"]!=["R17R9_11_APPROVED_FULLBOOK_SUCCESSOR_ONCE"]:
        reasons.append("R17R9_PRODUCTION_SCOPE_INVALID")
    for k in ("action_id","method_id","executor_id"):
        if not isinstance(profile.get(k),str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",profile[k]):
            reasons.append("R17R9_RUNTIME_ID_INVALID:"+k)
    for k in ("bundle_sha256","dependency_lock_sha256","receipt_key_sha256",
              "runtime_code_sha256","runtime_workflow_sha256","source_admission_receipt_sha256"):
        if not is_sha256(profile.get(k)): reasons.append("R17R9_DIGEST_INVALID:"+k)
    if not isinstance(profile.get("bundle_blob_sha"),str) or not re.fullmatch(r"[0-9a-f]{40}",profile["bundle_blob_sha"]):
        reasons.append("R17R9_PRIVATE_BLOB_INVALID")
    if profile.get("bundle_sha256")==R17R9_11_LAB_INPUT_SHA256:
        reasons.append("R17R9_OLD_PRIVATE_STATE_BUNDLE_FORBIDDEN")
    if type(profile.get("max_seconds")) is not int or not 1<=profile["max_seconds"]<=3000:
        reasons.append("R17R9_BOUNDED_RUNTIME_REQUIRED")
    return sorted(set(reasons))
